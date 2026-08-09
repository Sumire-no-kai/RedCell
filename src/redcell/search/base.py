"""SearchController 的窄接口与统一决策审计。"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from pydantic import Field, model_validator

from redcell.protocols.common import RedCellModel


class ControllerProtocolError(RuntimeError):
    """select/update 调用顺序或结果违反 Controller interface。"""


class NoAvailableStrategiesError(RuntimeError):
    """Budget Manager 过滤后没有可选 Strategy。"""


class ControllerDecisionOutcome(StrEnum):
    PENDING = "pending"
    COMPLETED = "completed"
    ABANDONED = "abandoned"


class ControllerDecision(RedCellModel):
    attempt_index: int = Field(ge=0)
    controller: str
    available_strategy_ids: list[str] = Field(min_length=1)
    selected_strategy_id: str
    invocation_id: str | None = None
    """产生该选择的外部 Controller 调用；本地同步 Controller 为 None。"""
    decision_state: dict[str, Any] = Field(default_factory=dict)
    observed_score: float | None = Field(default=None, ge=0.0, le=1.0)
    outcome: ControllerDecisionOutcome = ControllerDecisionOutcome.PENDING
    failure_reason: str | None = None

    @model_validator(mode="after")
    def _validate_outcome(self) -> ControllerDecision:
        if self.outcome is ControllerDecisionOutcome.PENDING:
            if self.observed_score is not None or self.failure_reason is not None:
                raise ValueError("pending decision 不能已有结果")
        elif self.outcome is ControllerDecisionOutcome.COMPLETED:
            if self.observed_score is None or self.failure_reason is not None:
                raise ValueError("completed decision 必须且只能带 observed_score")
        elif self.observed_score is not None or not self.failure_reason:
            raise ValueError("abandoned decision 必须且只能带 failure_reason")
        return self


@dataclass(frozen=True)
class Selection:
    """`_choose` 的返回值:选中的 Strategy,以及写进决策审计的状态快照。"""

    strategy_id: str
    state: dict[str, Any]


class SearchController(ABC):
    """调用方只需学会 seed/select/update/abandon;决策审计由基类统一保证。"""

    def __init__(self) -> None:
        self._decisions: list[ControllerDecision] = []
        self._pending_index: int | None = None
        self._controller_seed: int | None = None

    @property
    @abstractmethod
    def name(self) -> str: ...

    @property
    def requires_seed(self) -> bool:
        """本 Controller 的选择是否依赖随机性。

        Orchestrator 据此强制播种:非学习的 Static 不需要,
        Random 与后续的 Thompson/UCB 需要。默认 False,子类显式声明。
        """
        return False

    @property
    def controller_seed(self) -> int | None:
        """实际生效的种子。写进 ReproductionContext,必须与真实使用的一致。"""
        return self._controller_seed

    def seed(self, controller_seed: int) -> None:
        """由 Orchestrator 从 Run 主种子派生后注入。

        **不能让调用方自己播种。** Run 主种子可能是 Orchestrator 在
        `_prepare_run` 里现生成的,调用方在构造 Controller 时根本还不知道它;
        那样 ReproductionContext 里记的 controller_seed 会和真正驱动选择的
        RNG 毫无关系,而这条不一致不会有任何报错 —— 只会在某天重放失败时才发现。
        """
        if controller_seed < 0:
            raise ValueError("controller_seed 必须 >= 0")
        if self._decisions:
            raise ControllerProtocolError("已经开始决策的 Controller 不能重新播种")
        self._controller_seed = controller_seed
        self._on_seeded(controller_seed)

    def _on_seeded(self, controller_seed: int) -> None:
        """子类在此建立自己的私有 RNG。不需要随机性的实现无需覆写。"""
        return None

    def select(self, available_strategy_ids: Sequence[str]) -> str:
        """从 Budget Manager 给出的可选列表中选一个。

        一次 select 必须由有效 update 或显式 abandon 收尾,不能悄悄再 select
        并丢掉未完成决策。
        """
        if self._pending_index is not None:
            raise ControllerProtocolError("上一次 select 尚未收到有效 Attempt 的 update")

        available = tuple(available_strategy_ids)
        if not available:
            raise NoAvailableStrategiesError("没有可选 Strategy")
        if len(set(available)) != len(available):
            raise ValueError("available_strategy_ids 不能包含重复项")

        selection = self._choose(available)
        if selection.strategy_id not in available:
            raise ControllerProtocolError(
                f"Controller '{self.name}' 选择了不可用 Strategy '{selection.strategy_id}'"
            )

        decision = ControllerDecision(
            attempt_index=len(self._decisions),
            controller=self.name,
            available_strategy_ids=list(available),
            selected_strategy_id=selection.strategy_id,
            decision_state=selection.state,
        )
        self._decisions.append(decision)
        self._pending_index = decision.attempt_index
        return selection.strategy_id

    def update(self, strategy_id: str, score: float) -> None:
        if self._pending_index is None:
            raise ControllerProtocolError("update 前必须先 select")
        if not 0.0 <= score <= 1.0:
            raise ValueError("score 必须在 [0, 1] 内")

        decision = self._decisions[self._pending_index]
        if decision.selected_strategy_id != strategy_id:
            raise ControllerProtocolError(
                f"update 的 Strategy '{strategy_id}' 与最近选择 "
                f"'{decision.selected_strategy_id}' 不一致"
            )

        learning_state = self._learn(strategy_id, score)
        decision_state = decision.decision_state
        if learning_state:
            # Selection 时记录的是「为什么选」;学习完成后补上「这次如何更新」。
            # 对非学习基线它保持原样,因此不让 Thompson 的审计需求污染调用方接口。
            decision_state = {**decision_state, **learning_state}
        self._decisions[self._pending_index] = _resolved_decision(
            decision,
            observed_score=score,
            outcome=ControllerDecisionOutcome.COMPLETED,
            decision_state=decision_state,
        )
        self._pending_index = None

    def abandon(self, strategy_id: str, reason: str) -> None:
        """记录未产出有效 Attempt 的选择并释放 pending,不向学习器回传零分。"""
        if self._pending_index is None:
            raise ControllerProtocolError("abandon 前必须先 select")
        if not reason.strip():
            raise ValueError("abandon reason 不能为空")

        decision = self._decisions[self._pending_index]
        if decision.selected_strategy_id != strategy_id:
            raise ControllerProtocolError(
                f"abandon 的 Strategy '{strategy_id}' 与最近选择 "
                f"'{decision.selected_strategy_id}' 不一致"
            )

        self._decisions[self._pending_index] = _resolved_decision(
            decision,
            outcome=ControllerDecisionOutcome.ABANDONED,
            failure_reason=reason.strip(),
        )
        self._pending_index = None

    @property
    def decisions(self) -> tuple[ControllerDecision, ...]:
        """完整决策审计。深拷贝,调用方拿到的快照改不动内部状态。"""
        return tuple(decision.model_copy(deep=True) for decision in self._decisions)

    @property
    def latest_decision(self) -> ControllerDecision | None:
        """最近一次决策。

        Orchestrator 每轮要读好几次最近决策,走 `decisions[-1]` 会把整段历史
        深拷贝一遍,开销随 Attempt 数增长。这里只拷一条。
        """
        if not self._decisions:
            return None
        return self._decisions[-1].model_copy(deep=True)

    @property
    def has_pending_decision(self) -> bool:
        """是否有一次 select 尚未由 update / abandon 收尾。"""
        return self._pending_index is not None

    def restore(
        self,
        *,
        controller_seed: int,
        decisions: Sequence[ControllerDecision],
    ) -> None:
        """从已完成/已放弃的审计轨迹重建内部 RNG 与学习状态。

        恢复只接受已经收尾的 decision；崩溃留下的 pending decision 必须先由
        Orchestrator 标为 abandoned，避免重放一场可能已碰过外部副作用的 Attempt。
        """
        if any(decision.outcome is ControllerDecisionOutcome.PENDING for decision in decisions):
            raise ControllerProtocolError("恢复前必须先处理 pending ControllerDecision")
        self.seed(controller_seed)
        for expected in decisions:
            selected = self.select(expected.available_strategy_ids)
            if selected != expected.selected_strategy_id:
                raise ControllerProtocolError(
                    "恢复时 Controller 选择了 "
                    f"'{selected}',审计记录为 '{expected.selected_strategy_id}'"
                )
            if expected.outcome is ControllerDecisionOutcome.COMPLETED:
                assert expected.observed_score is not None
                self.update(selected, expected.observed_score)
            else:
                assert expected.failure_reason is not None
                self.abandon(selected, expected.failure_reason)

    @abstractmethod
    def _choose(self, available_strategy_ids: tuple[str, ...]) -> Selection: ...

    def _learn(self, strategy_id: str, score: float) -> dict[str, Any] | None:
        """更新内部学习状态,可返回要追加到决策审计的快照。"""
        return None


def _resolved_decision(
    decision: ControllerDecision,
    **updates: object,
) -> ControllerDecision:
    payload = decision.model_dump(mode="python")
    payload.update(updates)
    return ControllerDecision.model_validate(payload)
