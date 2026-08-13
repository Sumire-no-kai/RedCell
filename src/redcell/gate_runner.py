"""72-cell 矩阵的调度决策层 —— 只决定"下一步跑哪些",不负责执行。

## 为什么单独一层

正式矩阵是 72 个长 Run、约 21 小时、Target 并发上限 3 的连续作业。这类作业里
**真正容易出错的不是执行,是调度语义**:哪些格子还能跑、一个格子失败之后该停什么、
中断之后从哪儿续、备用 seed 什么时候才允许上场。这些规则来自 runbook,
一旦写进 shell 循环就再也没人能验证它们。

于是把决策做成纯函数、把执行留给薄脚本:**调度规则可以被测试,而外部调用不必被测试**。

## 三条来自 runbook 的硬规则

1. **失效单位是整个 seed block,不是单个 cell。** 一个 cell 无效 ⇒ 该 seed 的六个条件
   全部退出主要分析。**不得只重跑失败的那一个** —— 那会让这个 block 里各条件的
   运行时刻不再可配对,而 Gate 的统计量正是成对的。
2. **备用 seed 不得自动上场。** 它只在整块因基础设施/未知 Token/可靠性/完整性失效时
   按冻结顺序补位;而"是不是这类失效"是要人看过才能定的判断。
   ⚠️ 尤其不得因为 Finding 结果不好看就换 seed。
3. **已完成的格子永不重跑。** 重跑会产生同一 seed×condition 的第二条记录,
   而 Gate 明确拒绝重复单元格 —— 届时报错会指向数据完整性,真实原因却是调度。
"""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from enum import StrEnum

from pydantic import Field, model_validator

from redcell.budget import BudgetLimit
from redcell.gate_analysis import GateCondition
from redcell.gate_plan import GatePlan, GatePlanCell, SeedRole
from redcell.protocols.common import RedCellModel, new_id
from redcell.protocols.run import Run, RunStatus

GATE_RUNNER_STATE_VERSION = "phase-0.5-gate-runner-state-v2"
NORMAL_RUN_EXIT_CODES = frozenset({0, 1})
"""`redcell run` 正常完成的退出码：`CLEAN=0` 或 `FINDINGS=1`。

Finding 是本实验要测量的结果，不是调度失败。把 1 当失败会在第一次发现漏洞时使整个
seed block 作废，系统性删除有 Finding 的数据并偏向零结果。真正使 block 失效的是
`RUN_FAILED=3`、`BAD_CONFIG=4` 或其他未约定的退出码。
"""


class CellStatus(StrEnum):
    PENDING = "pending"
    DISPATCHED = "dispatched"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED_BLOCK_INVALID = "skipped_block_invalid"
    """同一 block 内已有格子失败,因此这一格不再派发。

    与 `FAILED` 分开记:前者是"我们主动不跑",后者是"跑了没成"。
    混成一个状态会让事后无法回答"这个 block 到底消耗了多少外部调用"。
    """


class CellRecord(RedCellModel):
    seed: int
    condition: GateCondition
    seed_role: SeedRole
    status: CellStatus = CellStatus.PENDING
    run_id: str | None = None
    exit_code: int | None = None
    detail: str | None = None

    @property
    def key(self) -> tuple[int, GateCondition]:
        return (self.seed, self.condition)


class ReserveActivation(RedCellModel):
    seed: int
    reason: str
    state_digest_before: str


class BlockView(RedCellModel):
    """一个 seed 的六条件 block 的汇总视图。"""

    seed: int
    seed_role: SeedRole
    total: int
    completed: int
    failed: int
    skipped: int

    @property
    def invalid(self) -> bool:
        return bool(self.failed or self.skipped)

    @property
    def finished(self) -> bool:
        return self.completed + self.failed + self.skipped == self.total

    @property
    def usable(self) -> bool:
        """只有六条件全部完成且无失败的 block 才进入主要分析。"""
        return self.completed == self.total


class MatrixState(RedCellModel):
    version: str = GATE_RUNNER_STATE_VERSION
    seed_plan_digest: str
    database_url: str
    cells: list[CellRecord] = Field(default_factory=list)
    enabled_reserve_seeds: list[int] = Field(default_factory=list)
    reserve_activations: list[ReserveActivation] = Field(default_factory=list)
    gate_context_fingerprint: str | None = None
    """已显式启用的备用 seed，且必须是冻结顺序的前缀。"""

    @model_validator(mode="after")
    def cells_are_unique(self) -> MatrixState:
        keys = [cell.key for cell in self.cells]
        if len(keys) != len(set(keys)):
            raise ValueError("同一 seed×condition 不得出现两条记录")
        reserve_order = list(
            dict.fromkeys(cell.seed for cell in self.cells if cell.seed_role is SeedRole.RESERVE)
        )
        if len(self.enabled_reserve_seeds) != len(set(self.enabled_reserve_seeds)):
            raise ValueError("备用 seed 不得重复启用")
        if self.enabled_reserve_seeds != reserve_order[: len(self.enabled_reserve_seeds)]:
            raise ValueError("备用 seed 必须按冻结顺序连续启用")
        return self

    def state_digest(self) -> str:
        payload = json.dumps(self.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    # ── 查询 ─────────────────────────────────────────────────────────────

    def block(self, seed: int) -> BlockView:
        members = [cell for cell in self.cells if cell.seed == seed]
        if not members:
            raise KeyError(f"state 中没有 seed {seed}")
        counts = Counter(cell.status for cell in members)
        return BlockView(
            seed=seed,
            seed_role=members[0].seed_role,
            total=len(members),
            completed=counts[CellStatus.COMPLETED],
            failed=counts[CellStatus.FAILED],
            skipped=counts[CellStatus.SKIPPED_BLOCK_INVALID],
        )

    def blocks(self) -> list[BlockView]:
        return [self.block(seed) for seed in sorted({cell.seed for cell in self.cells})]

    @property
    def usable_blocks(self) -> list[int]:
        return [view.seed for view in self.blocks() if view.usable]

    def is_active(self, seed: int, role: SeedRole) -> bool:
        """这个 seed 现在允许派发吗。

        primary 默认在场;reserve 必须被**显式**启用 —— 见模块 docstring 规则 2。
        """
        if role is SeedRole.RESERVE and seed not in self.enabled_reserve_seeds:
            return False
        return not self.block(seed).invalid


def initial_state(plan: GatePlan) -> MatrixState:
    """从 plan 建立初始 state;此时一个外部调用都还没发生。"""
    return MatrixState(
        seed_plan_digest=plan.seed_plan_digest,
        database_url=plan.database_url,
        cells=[
            CellRecord(seed=cell.seed, condition=cell.condition, seed_role=cell.seed_role)
            for cell in plan.cells
        ],
    )


def require_matching_state(plan: GatePlan, state: MatrixState) -> None:
    """state 与 plan 必须描述同一个矩阵。

    否则续跑会把上一版计划的进度当成这一版的 —— 而两者的 seed 或条件可能已经不同,
    结果是一批看起来完整、实际混了两套条件的数据。
    """
    if state.version != GATE_RUNNER_STATE_VERSION:
        raise ValueError("gate runner state 版本不受支持")
    if state.seed_plan_digest != plan.seed_plan_digest:
        raise ValueError("state 与 plan 的 seed plan digest 不一致")
    if state.database_url != plan.database_url:
        raise ValueError("state 与 plan 的数据库不一致")
    planned = {(cell.seed, cell.condition) for cell in plan.cells}
    recorded = {cell.key for cell in state.cells}
    if planned != recorded:
        raise ValueError("state 与 plan 的 seed×condition 集合不一致")


def pending_cells(plan: GatePlan, state: MatrixState, *, limit: int) -> list[GatePlanCell]:
    """按冻结顺序返回接下来可以派发的格子,最多 `limit` 个。

    刻意保持 plan 里的原始顺序:同一 block 的六个条件挨着跑,让它们的外部条件
    (时段、Provider 负载、模型版本)尽可能接近 —— 成对比较的前提就是这个。
    """
    if limit < 1:
        raise ValueError("limit 至少为 1")
    by_key = {cell.key: cell for cell in state.cells}
    ready: list[GatePlanCell] = []
    for cell in plan.cells:
        record = by_key[(cell.seed, cell.condition)]
        if record.status is not CellStatus.PENDING:
            continue
        if not state.is_active(cell.seed, cell.seed_role):
            continue
        ready.append(cell)
        if len(ready) == limit:
            break
    return ready


def record_dispatch(
    state: MatrixState, *, seed: int, condition: GateCondition, run_id: str | None = None
) -> MatrixState:
    """Durably bind a cell to its exact child Run ID before starting that child."""
    target = next((cell for cell in state.cells if cell.key == (seed, condition)), None)
    if target is None:
        raise KeyError(f"state 中没有 seed {seed} / {condition.value}")
    if target.status is not CellStatus.PENDING:
        raise ValueError(f"seed {seed} / {condition.value} 已有状态 {target.status}")
    assigned_id = run_id or new_id()
    return state.model_copy(
        update={
            "cells": [
                (
                    cell.model_copy(update={"status": CellStatus.DISPATCHED, "run_id": assigned_id})
                    if cell.key == target.key
                    else cell
                )
                for cell in state.cells
            ]
        }
    )


def invalidate_unknown_delivery(state: MatrixState) -> MatrixState:
    """Fail closed after a crash: DISPATCHED means delivery is unknowable, never reusable."""
    for cell in state.cells:
        if cell.status is CellStatus.DISPATCHED:
            return record_outcome(
                state,
                seed=cell.seed,
                condition=cell.condition,
                exit_code=91,
                run_id=cell.run_id,
                detail="进程中断后交付状态未知；整块按完整性失效，禁止猜测或复用 Run",
            )
    return state


def record_outcome(
    state: MatrixState,
    *,
    seed: int,
    condition: GateCondition,
    exit_code: int,
    run_id: str | None = None,
    detail: str | None = None,
    gate_context_fingerprint: str | None = None,
) -> MatrixState:
    """落一格结果;失败时同 block 的未跑格子一并标为不再派发。"""
    target = next((cell for cell in state.cells if cell.key == (seed, condition)), None)
    if target is None:
        raise KeyError(f"state 中没有 seed {seed} / {condition.value}")
    if target.status is not CellStatus.DISPATCHED:
        raise ValueError(f"seed {seed} / {condition.value} 已有状态 {target.status}")
    if run_id is not None and target.run_id != run_id:
        raise ValueError("cell Run ID 与派发前持久化的 Run ID 不一致")
    if gate_context_fingerprint is not None and state.gate_context_fingerprint not in (
        None,
        gate_context_fingerprint,
    ):
        raise ValueError("cell Gate context 与既有矩阵 context 不一致")
    succeeded = exit_code in NORMAL_RUN_EXIT_CODES
    updated: list[CellRecord] = []
    for cell in state.cells:
        if cell.key == (seed, condition):
            updated.append(
                cell.model_copy(
                    update={
                        "status": CellStatus.COMPLETED if succeeded else CellStatus.FAILED,
                        "run_id": run_id,
                        "exit_code": exit_code,
                        "detail": detail,
                    }
                )
            )
        elif not succeeded and cell.seed == seed and cell.status is CellStatus.PENDING:
            # 规则 1:失效单位是整个 block。这里不是"顺手放弃",而是刻意不让
            # 同一 block 的其余条件在一个已经作废的配对里继续消耗外部调用。
            updated.append(
                cell.model_copy(
                    update={
                        "status": CellStatus.SKIPPED_BLOCK_INVALID,
                        "detail": f"block 因 {condition.value} 失效",
                    }
                )
            )
        else:
            updated.append(cell)
    return state.model_copy(
        update={
            "cells": updated,
            "gate_context_fingerprint": gate_context_fingerprint or state.gate_context_fingerprint,
        }
    )


def verify_cell_run(
    run: Run | None,
    cell: GatePlanCell,
    *,
    expected_run_id: str | None = None,
    expected_gate_context_fingerprint: str | None = None,
) -> str | None:
    """逐格核验 runbook §5 的硬条件;返回失败原因,`None` 表示通过。

    **为什么退出码不够。** `redcell run` 在预算耗尽时正常退出,而"耗尽的是哪一项"
    它不体现在退出码里:一格因**墙钟**或 **attempt 上限**停下,同样是 exit 0/1。
    那样的 Run 没有跑到 320k 前缀,却会被记成 `completed`、block 显示 usable ——
    直到 21 小时之后 `gate-report` 才拒绝它,而那时补位又要再花六个 cell。
    **让坏 block 在第一时间暴露,是这个函数存在的全部理由。**
    """
    if run is None:
        return "数据库中找不到已派发 Run ID 的记录"
    if expected_run_id is not None and run.id != expected_run_id:
        return "Run ID 与派发前持久化绑定不一致"
    conditions = run.experiment_conditions
    if (
        run.seed != cell.seed
        or conditions is None
        or conditions.search is None
        or conditions.generation_memory is None
        or conditions.search.selector is not cell.search
        or conditions.generation_memory.mode is not cell.cross_attempt_memory
    ):
        return "Run 的 seed 或治疗条件与 cell 不一致"
    if (
        expected_gate_context_fingerprint is not None
        and run.gate_context_fingerprint() != expected_gate_context_fingerprint
    ):
        return "Run 的 Gate context 与矩阵状态不一致"
    if run.status is not RunStatus.COMPLETED:
        return f"Run 状态为 {run.status.value},不是 completed"
    if run.stopped_by is not BudgetLimit.TOKENS:
        stopped = run.stopped_by.value if run.stopped_by else "未记录"
        return f"停止原因为 {stopped},不是 Token —— 未跑满 Token 前缀"
    usage = run.usage
    if usage.total_tokens < cell.max_total_tokens:
        return f"累计 Token {usage.total_tokens} 未达 checkpoint {cell.max_total_tokens}"
    if usage.role_total_tokens != usage.total_tokens:
        # 总账与三角色账不守恒 ⇒ 等 Token 比较的分母本身不可信。
        return f"角色账 {usage.role_total_tokens} 与总账 {usage.total_tokens} 不一致"
    return None


def enable_reserve_block(state: MatrixState, seed: int, *, reason: str) -> MatrixState:
    """显式启用一个备用 block。

    ⚠️ 刻意要求调用方点名 seed,而不是"自动取下一个":哪一块失效、是不是属于
    允许补位的失效类型(基础设施 / 未知 Token / 可靠性 / 完整性),都要人看过才算数。
    **不得因为 Finding 结果不好看而换 seed。**
    """
    view = state.block(seed)
    if view.seed_role is not SeedRole.RESERVE:
        raise ValueError(f"seed {seed} 不是备用 seed")
    if seed in state.enabled_reserve_seeds:
        return state
    reserve_order = list(
        dict.fromkeys(cell.seed for cell in state.cells if cell.seed_role is SeedRole.RESERVE)
    )
    next_seed = reserve_order[len(state.enabled_reserve_seeds)]
    if seed != next_seed:
        raise ValueError(f"必须先按冻结顺序启用备用 seed {next_seed}")
    if not reason.strip():
        raise ValueError("启用备用 seed 必须记录人工确认的失效理由")
    return state.model_copy(
        update={
            "enabled_reserve_seeds": [*state.enabled_reserve_seeds, seed],
            "reserve_activations": [
                *state.reserve_activations,
                ReserveActivation(
                    seed=seed, reason=reason.strip(), state_digest_before=state.state_digest()
                ),
            ],
        }
    )


def progress_summary(plan: GatePlan, state: MatrixState) -> str:
    blocks = state.blocks()
    primary = [view for view in blocks if view.seed_role is SeedRole.PRIMARY]
    usable = [view for view in blocks if view.usable]
    invalid = [view for view in blocks if view.invalid]
    done = sum(view.completed for view in blocks)
    total_enabled = sum(
        1
        for cell in plan.cells
        if cell.seed_role is SeedRole.PRIMARY or cell.seed in state.enabled_reserve_seeds
    )
    lines = [
        f"cells    {done}/{total_enabled} completed",
        f"blocks   {len(usable)} usable / {len(primary)} primary / {len(invalid)} invalid",
    ]
    if invalid:
        lines.append(
            "invalid  "
            + ", ".join(f"seed {view.seed}" for view in invalid)
            + "  ← 需人工判断是否补位"
        )
    if len(usable) >= 12:
        lines.append("已有 12 个可用 block —— 可以进入 validate-paths")
    return "\n".join(lines)
