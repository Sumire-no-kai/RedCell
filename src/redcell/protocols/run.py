"""Run —— 一次评测任务。

字段依据 PRD §15。存在的意义不只是"一条记录":
Run 把**目标版本、policy 版本、算法、预算、随机种子**绑在一起,
少了其中任何一项,跑出来的数字就无法归因 ——
"这个结论是在哪个 policy、哪个算法、多大预算下得到的"必须永远可查。
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import Field, model_validator

from redcell.budget import BudgetLimit, BudgetLimits, BudgetUsage
from redcell.failures import FailureRecord
from redcell.protocols.common import REDCELL_PROTOCOL_VERSION, RedCellModel, new_id
from redcell.protocols.strategy import StrategyCatalogueSummary
from redcell.reliability import ReliabilityPolicy, SelectionReliabilityPolicy
from redcell.versions import (
    ATTACK_PATH_SIGNATURE_VERSION,
    FINDING_SIGNATURE_VERSION,
    LEVEL1_SCORER_VERSION,
)


class RunStatus(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    """跑到预算用尽,正常结束。"""

    FAILED = "failed"
    """异常中断。**结论不可用** —— 部分完成的 run 会系统性低估发现数。"""

    ABORTED = "aborted"
    """人工中止。同样不可用于结论。"""


class RunEventType(StrEnum):
    RUN_STARTED = "run_started"
    DECISION_SELECTED = "decision_selected"
    TURN_COMPLETED = "turn_completed"
    RETRY_SCHEDULED = "retry_scheduled"
    SELECTION_ABANDONED = "selection_abandoned"
    ATTEMPT_COMMITTED = "attempt_committed"
    ATTEMPT_ABANDONED = "attempt_abandoned"
    RUN_RESUMED = "run_resumed"
    RUN_COMPLETED = "run_completed"
    RUN_FAILED = "run_failed"
    RUN_ABORTED = "run_aborted"


class RunEvent(RedCellModel):
    """追加式运行事件,用于恢复、审计和未来 Dashboard 实时进度。"""

    id: str = Field(default_factory=new_id)
    run_id: str
    event_type: RunEventType
    attempt_id: str | None = None
    sequence: int = Field(ge=0)
    payload: dict = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class ProviderRunConfiguration(RedCellModel):
    """不含凭据、但足以复核模型行为与节流条件的 provider 快照。"""

    provider: str
    base_url: str
    model: str
    temperature: float
    max_tokens: int = Field(ge=1)
    rpm: float = Field(ge=0.0)
    max_concurrency: int = Field(ge=0)
    input_usd_per_mtok: float = Field(ge=0.0)
    output_usd_per_mtok: float = Field(ge=0.0)
    cached_input_usd_per_mtok: float = Field(default=0.0, ge=0.0)
    extra_body: dict[str, Any] = Field(default_factory=dict)


class SearchSelector(StrEnum):
    """本次 Run 实际使用的策略选择机制。

    这里刻意记录具体的 ``thompson``，而不是含混的 ``bandit``。实验指纹必须能
    回答“究竟跑了哪个算法”，否则将来新增 UCB 后旧数据会被错误混组。
    """

    STATIC = "static"
    RANDOM = "random"
    THOMPSON = "thompson"
    LLM = "llm"


class SearchConfiguration(RedCellModel):
    """Phase 0.5 的因子 X：由谁选择冻结策略库中的下一条 Strategy。"""

    selector: SearchSelector


class GenerationMemoryMode(StrEnum):
    """Phase 0.5 的因子 Y；它只控制 Generator 的跨 Attempt 可见性。"""

    OFF = "off"
    BOUNDED_RELEVANT_V1 = "bounded-relevant-v1"


class GenerationMemoryLimits(RedCellModel):
    """有界历史的版本化工程上限，改变任一值即改变实验条件。"""

    max_detailed_attempts: int = Field(default=4, ge=1)
    max_attempt_chars: int = Field(default=3000, ge=1)
    max_message_chars: int = Field(default=2000, ge=1)
    max_history_chars: int = Field(default=12000, ge=1)


class GenerationMemoryConfiguration(RedCellModel):
    """跨 Attempt Generator memory 的显式、可审计开关。"""

    mode: GenerationMemoryMode
    policy_version: str | None = None
    limits: GenerationMemoryLimits | None = None

    @model_validator(mode="after")
    def _bind_mode(self) -> GenerationMemoryConfiguration:
        if self.mode is GenerationMemoryMode.OFF:
            if self.policy_version is not None or self.limits is not None:
                raise ValueError("memory=off 时不得携带 memory policy 或 limits")
        elif self.policy_version is None or self.limits is None:
            raise ValueError("开启跨 Attempt memory 必须记录 policy_version 与 limits")
        return self


class ControllerRunConfiguration(RedCellModel):
    """LLM Controller 的非秘密、可复核运行快照。"""

    provider: ProviderRunConfiguration
    connection_id: str
    connection_fingerprint: str
    prompt_version: str
    evidence_policy_version: str
    output_schema_version: str = "controller-choice-v1"
    budget_view_policy_version: str = "controller-budget-view-v1"
    thinking_disabled: bool

    @model_validator(mode="after")
    def _require_nonempty_identity(self) -> ControllerRunConfiguration:
        if not self.connection_id.strip() or not self.connection_fingerprint.strip():
            raise ValueError("Controller connection identity/fingerprint 不能为空")
        return self


class ArenaRunConfiguration(RedCellModel):
    """会改变靶场难度或副作用语义的所有 Phase 0 旋钮。"""

    defense: str
    enforce_permissions: bool
    enforce_confirmation: bool


class ExperimentConditions(RedCellModel):
    """一次 Run 的可比较实验条件；不含 API key 等凭据。"""

    online: bool
    actor: str
    target: ProviderRunConfiguration
    attacker: ProviderRunConfiguration
    arena: ArenaRunConfiguration
    strategy_catalogue: StrategyCatalogueSummary | None = None
    """Phase 0.5 起的新实验必须提供；None 仅用于复现 Phase 0 既有条件指纹。"""

    search: SearchConfiguration | None = None
    generation_memory: GenerationMemoryConfiguration | None = None
    controller: ControllerRunConfiguration | None = None
    scorer_version: str = LEVEL1_SCORER_VERSION
    finding_signature_version: str = FINDING_SIGNATURE_VERSION
    attack_path_signature_version: str = ATTACK_PATH_SIGNATURE_VERSION

    def fingerprint(self) -> str:
        payload = json.dumps(
            self.model_dump(mode="json", exclude_none=True),
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return hashlib.sha256(payload).hexdigest()

    def regression_context_fingerprint(self) -> str:
        """生成跨处理条件比较用的环境指纹。

        完整指纹会且应该因 selector、memory、LLM Controller 而不同；回归比较需要
        验证其余环境是否相同，不能通过忽略“旧对象碰巧没有的字段”来伪造兼容。
        """
        payload = {
            "version": "regression-context-v1",
            "online": self.online,
            "actor": self.actor,
            "target": self.target.model_dump(mode="json"),
            "attacker": self.attacker.model_dump(mode="json"),
            "arena": self.arena.model_dump(mode="json"),
            "strategy_catalogue": (
                self.strategy_catalogue.model_dump(mode="json")
                if self.strategy_catalogue is not None
                else None
            ),
        }
        encoded = json.dumps(
            payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    def require_phase_0_5(self) -> None:
        """拒绝用不完整处理条件创建新的 Phase 0.5 Run。

        模型字段保持 optional 仅为了反序列化冻结的 Phase 0 payload；新的 builder/CLI
        必须显式调用本方法，不能把历史兼容性偷渡成新实验的宽松校验。
        """
        if self.strategy_catalogue is None:
            raise ValueError("Phase 0.5 Run 必须提供 strategy_catalogue")
        if self.search is None or self.generation_memory is None:
            raise ValueError("Phase 0.5 Run 必须提供 search 与 generation_memory")
        if self.search.selector is SearchSelector.LLM and self.controller is None:
            raise ValueError("search=llm 必须提供独立的 Controller 配置")
        if self.search.selector is not SearchSelector.LLM and self.controller is not None:
            raise ValueError("非 LLM search 不得携带 Controller 配置")


class Run(RedCellModel):
    id: str = Field(default_factory=new_id)
    target_name: str
    policy_version: str
    adapter_type: str
    algorithm: str
    """搜索算法标识,如 "static" / "random" / "thompson"。消融对比的分组键。"""

    limits: BudgetLimits
    reliability: ReliabilityPolicy = Field(default_factory=ReliabilityPolicy)
    selection_reliability: SelectionReliabilityPolicy = Field(
        default_factory=SelectionReliabilityPolicy
    )
    """这次 Run 用的可靠性阈值 —— **必须随 Run 落盘**。

    它决定了"这次 run 算不算数",而事后只看结果是看不出当时用的是哪组阈值的。
    与 `CALIBRATION.md` §12 要求记录"改了哪个旋钮"是同一条理由:
    判定标准本身也是实验条件。
    """
    usage: BudgetUsage = Field(default_factory=BudgetUsage)
    status: RunStatus = RunStatus.PENDING
    stopped_by: BudgetLimit | None = None
    """因为哪一项预算耗尽而停止。让"为什么停了"永远是明确的。"""

    seed: int | None = None
    """实验随机种子。多 seed 重复是报置信区间的前提,单次结果说明不了任何事。"""

    target_model: str | None = None
    target_temperature: float | None = None
    attacker_model: str | None = None
    attacker_temperature: float | None = None
    experiment_conditions: ExperimentConditions | None = None
    experiment_fingerprint: str | None = None
    """由 experiment_conditions 派生的 SHA-256；同一实验矩阵必须一致。"""
    strategy_ids: list[str] = Field(default_factory=list)
    protocol_version: str = REDCELL_PROTOCOL_VERSION
    notes: str | None = None
    failure: FailureRecord | None = None

    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    started_at: datetime | None = None
    completed_at: datetime | None = None

    @model_validator(mode="after")
    def _bind_experiment_fingerprint(self) -> Run:
        if self.experiment_conditions is None:
            if self.experiment_fingerprint is not None:
                raise ValueError("experiment_fingerprint 需要 experiment_conditions")
            return self
        expected = self.experiment_conditions.fingerprint()
        if self.experiment_fingerprint is None:
            self.__dict__["experiment_fingerprint"] = expected
        elif self.experiment_fingerprint != expected:
            raise ValueError("experiment_fingerprint 与 experiment_conditions 不一致")
        return self

    @property
    def has_auditable_conditions(self) -> bool:
        return self.experiment_conditions is not None and self.experiment_fingerprint is not None

    @property
    def is_conclusive(self) -> bool:
        """这次 run 的结果能不能拿来下结论。

        只有正常跑完的 run 算数。中断的 run 会系统性低估发现数,
        混进统计里会把结论往"没找到东西"的方向拉,而且不会有任何提示。
        """
        return self.status is RunStatus.COMPLETED
