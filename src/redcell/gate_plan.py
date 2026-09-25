"""Declarative, non-executing plan for the frozen Phase 0.5 matrix."""

from __future__ import annotations

from enum import StrEnum
from typing import Literal

from pydantic import Field, SerializerFunctionWrapHandler, model_serializer, model_validator

from redcell.arena.registry import get_arena, recorded_identity
from redcell.arena.support_agent.codec import (
    NEW_EXPERIMENT_TOOL_CALL_PROTOCOL,
    ToolCallProtocol,
)
from redcell.gate_analysis import (
    FORMAL_MAX_ATTEMPTS,
    FORMAL_RUN_TOKENS,
    FROZEN_SEED_PLANS,
    GateCondition,
    SeedPlan,
    experiment_arena_id,
    require_frozen_seed_plan,
    seed_plan_digest,
)
from redcell.protocols.common import RedCellModel
from redcell.protocols.run import ExecutionHostProfile, GenerationMemoryMode, SearchSelector

GATE_PLAN_VERSION = "phase-0.5-gate-plan-v3"
HOST_BOUND_GATE_PLAN_VERSION = "phase-0.5-gate-plan-v2"
LEGACY_GATE_PLAN_VERSION = "phase-0.5-gate-plan-v1"


class SeedRole(StrEnum):
    PRIMARY = "primary"
    RESERVE = "reserve"


_TREATMENTS: tuple[tuple[GateCondition, SearchSelector, GenerationMemoryMode], ...] = (
    (GateCondition.STATIC_OFF, SearchSelector.STATIC, GenerationMemoryMode.OFF),
    (
        GateCondition.STATIC_MEMORY,
        SearchSelector.STATIC,
        GenerationMemoryMode.BOUNDED_RELEVANT_V1,
    ),
    (
        GateCondition.LLM_MEMORY,
        SearchSelector.LLM,
        GenerationMemoryMode.BOUNDED_RELEVANT_V1,
    ),
    (GateCondition.LLM_OFF, SearchSelector.LLM, GenerationMemoryMode.OFF),
    (GateCondition.RANDOM_OFF, SearchSelector.RANDOM, GenerationMemoryMode.OFF),
    (GateCondition.THOMPSON_OFF, SearchSelector.THOMPSON, GenerationMemoryMode.OFF),
)


class GatePlanCell(RedCellModel):
    seed: int
    seed_role: SeedRole
    enabled_initially: bool
    condition: GateCondition
    search: SearchSelector
    cross_attempt_memory: GenerationMemoryMode
    max_attempts: int = Field(ge=1)
    max_total_tokens: int = FORMAL_RUN_TOKENS
    argv: list[str]


class GatePlan(RedCellModel):
    plan_version: Literal[
        "phase-0.5-gate-plan-v1",
        "phase-0.5-gate-plan-v2",
        "phase-0.5-gate-plan-v3",
    ] = GATE_PLAN_VERSION
    seed_plan_digest: str
    database_url: str
    report_directory: str
    execution_host_profile: ExecutionHostProfile | None = None
    tool_call_protocol_version: str | None = None
    env_file: str | None = None
    """每个正式 Run 叠在 `.env` 之上的配置文件(`run --env-file`);`None` 表示只用 `.env`。

    冻结的是路径,不是内容:内容会作为模型配置写进每个 Run 的实验条件与指纹,
    矩阵分析与 preflight 按那里核对。未设置时不进入序列化结果,旧计划的 JSON 与
    校验逐字节不变(2026-09-24)。
    """
    arena_id: str | None = None
    """每个正式 Run 的 `--arena`;由 seed plan 登记的实验推出,不单独传参。

    与 `recorded_identity` 同一约定:默认(客服)靶场为 `None`、不进入序列化,所以已有
    计划的 JSON 与校验逐字节不变;其他靶场写入并追加到每格 argv(2026-09-25)。
    """
    max_attempts: int = Field(ge=1)
    primary_cells: int
    reserve_cells: int
    cells: list[GatePlanCell]

    @model_serializer(mode="wrap")
    def _serialize(self, handler: SerializerFunctionWrapHandler) -> dict:
        data = handler(self)
        if self.env_file is None:
            data.pop("env_file", None)
        if self.arena_id is None:
            data.pop("arena_id", None)
        return data

    @model_validator(mode="after")
    def matches_registered_matrix(self) -> GatePlan:
        """Reject a drifted/tampered execution plan before any paid child can start."""
        if self.max_attempts != FORMAL_MAX_ATTEMPTS:
            raise ValueError(f"Phase 0.5 Gate max_attempts must be {FORMAL_MAX_ATTEMPTS}")
        if not self.database_url.startswith("sqlite:///"):
            raise ValueError("Phase 0.5 Gate plan requires an explicit SQLite database URL")
        if not self.report_directory.strip():
            raise ValueError("report_directory must not be empty")
        frozen = next(
            (item for item in FROZEN_SEED_PLANS.values() if item.digest == self.seed_plan_digest),
            None,
        )
        if frozen is None:
            raise ValueError("Gate plan seed digest is not registered")
        primary = list(
            dict.fromkeys(cell.seed for cell in self.cells if cell.seed_role is SeedRole.PRIMARY)
        )
        reserve = list(
            dict.fromkeys(cell.seed for cell in self.cells if cell.seed_role is SeedRole.RESERVE)
        )
        seed_plan = SeedPlan(experiment=frozen.experiment, primary=primary, reserve=reserve)
        require_frozen_seed_plan(seed_plan)
        if self.arena_id != _plan_arena_id(seed_plan):
            raise ValueError("Gate plan 的 arena_id 与该实验预注册的靶场不一致")
        if (
            frozen.tool_call_protocol is not None
            and self.tool_call_protocol_version != frozen.tool_call_protocol
        ):
            raise ValueError("Gate plan 的工具协议与该实验预注册的协议不一致")
        if (
            self.plan_version in {HOST_BOUND_GATE_PLAN_VERSION, GATE_PLAN_VERSION}
            and self.execution_host_profile is None
        ):
            raise ValueError("v2/v3 Gate plan 必须冻结 execution_host_profile")
        if (
            self.plan_version == LEGACY_GATE_PLAN_VERSION
            and self.execution_host_profile is not None
        ):
            raise ValueError("v1 Gate plan 不得携带 execution_host_profile")
        if self.plan_version == GATE_PLAN_VERSION:
            if self.tool_call_protocol_version is None:
                raise ValueError("v3 Gate plan 必须冻结 tool_call_protocol_version")
            ToolCallProtocol(self.tool_call_protocol_version)
        elif self.tool_call_protocol_version is not None:
            raise ValueError("v1/v2 Gate plan 不得携带 tool_call_protocol_version")
        expected = _build_cells(
            seed_plan,
            max_attempts=self.max_attempts,
            database_url=self.database_url,
            report_directory=self.report_directory,
            execution_host_profile=self.execution_host_profile,
            tool_call_protocol_version=self.tool_call_protocol_version,
            env_file=self.env_file,
            arena_id=self.arena_id,
        )
        if self.primary_cells != len(primary) * len(_TREATMENTS):
            raise ValueError("Gate plan primary_cells does not match its frozen allocation")
        if self.reserve_cells != len(reserve) * len(_TREATMENTS):
            raise ValueError("Gate plan reserve_cells does not match its frozen allocation")
        if self.cells != expected:
            raise ValueError("Gate plan cells/argv do not match the canonical frozen matrix")
        return self


def _plan_arena_id(seed_plan: SeedPlan) -> str | None:
    return recorded_identity(get_arena(experiment_arena_id(seed_plan.experiment)))[0]


def _build_cells(
    seed_plan: SeedPlan,
    *,
    max_attempts: int,
    database_url: str,
    report_directory: str,
    execution_host_profile: ExecutionHostProfile | None,
    tool_call_protocol_version: str | None,
    env_file: str | None = None,
    arena_id: str | None = None,
) -> list[GatePlanCell]:
    cells: list[GatePlanCell] = []
    for role, seeds in (
        (SeedRole.PRIMARY, seed_plan.primary),
        (SeedRole.RESERVE, seed_plan.reserve),
    ):
        for seed in seeds:
            for condition, search, memory in _TREATMENTS:
                argv = [
                    "redcell",
                    "run",
                    "--online",
                    "--search",
                    search.value,
                    "--cross-attempt-memory",
                    memory.value,
                    "--budget",
                    str(max_attempts),
                    "--max-tokens",
                    str(FORMAL_RUN_TOKENS),
                    "--seed",
                    str(seed),
                    "--db",
                    database_url,
                    "--out",
                    report_directory,
                ]
                if execution_host_profile is not None:
                    argv.extend(["--execution-host-profile", execution_host_profile.value])
                if tool_call_protocol_version is not None:
                    argv.extend(["--tool-call-protocol", tool_call_protocol_version])
                if env_file is not None:
                    argv.extend(["--env-file", env_file])
                if arena_id is not None:
                    argv.extend(["--arena", arena_id])
                cells.append(
                    GatePlanCell(
                        seed=seed,
                        seed_role=role,
                        enabled_initially=role is SeedRole.PRIMARY,
                        condition=condition,
                        search=search,
                        cross_attempt_memory=memory,
                        max_attempts=max_attempts,
                        argv=argv,
                    )
                )
    return cells


def build_gate_plan(
    seed_plan: SeedPlan,
    *,
    max_attempts: int,
    database_url: str,
    report_directory: str,
    execution_host_profile: ExecutionHostProfile = ExecutionHostProfile.WINDOWS_WAKELOCK_V1,
    tool_call_protocol: ToolCallProtocol | None = None,
    env_file: str | None = None,
) -> GatePlan:
    """Build commands without executing a Provider or touching the run database.

    `tool_call_protocol=None` 取实验登记的协议;登记没有冻结协议的实验(0.5 到 0.5d)
    取新实验默认。显式传入与登记不符的协议直接拒绝。
    """
    if max_attempts != FORMAL_MAX_ATTEMPTS:
        raise ValueError(f"Phase 0.5 Gate max_attempts must be {FORMAL_MAX_ATTEMPTS}")
    require_frozen_seed_plan(seed_plan)
    if not database_url.startswith("sqlite:///"):
        raise ValueError("Phase 0.5 Gate plan requires an explicit SQLite database URL")
    if not report_directory.strip():
        raise ValueError("report_directory must not be empty")
    registered = FROZEN_SEED_PLANS[seed_plan.experiment].tool_call_protocol
    if tool_call_protocol is None:
        tool_call_protocol = (
            ToolCallProtocol(registered) if registered else NEW_EXPERIMENT_TOOL_CALL_PROTOCOL
        )
    elif registered is not None and tool_call_protocol.value != registered:
        raise ValueError(
            f"{seed_plan.experiment} 预注册的工具协议是 {registered},"
            f"不能用 {tool_call_protocol.value}"
        )
    arena_id = _plan_arena_id(seed_plan)
    cells = _build_cells(
        seed_plan,
        max_attempts=max_attempts,
        database_url=database_url,
        report_directory=report_directory,
        execution_host_profile=execution_host_profile,
        tool_call_protocol_version=tool_call_protocol.value,
        env_file=env_file,
        arena_id=arena_id,
    )
    return GatePlan(
        seed_plan_digest=seed_plan_digest(seed_plan),
        database_url=database_url,
        report_directory=report_directory,
        execution_host_profile=execution_host_profile,
        tool_call_protocol_version=tool_call_protocol.value,
        env_file=env_file,
        arena_id=arena_id,
        max_attempts=max_attempts,
        primary_cells=len(seed_plan.primary) * len(_TREATMENTS),
        reserve_cells=len(seed_plan.reserve) * len(_TREATMENTS),
        cells=cells,
    )
