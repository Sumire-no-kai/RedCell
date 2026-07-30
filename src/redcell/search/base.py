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
class _Selection:
    strategy_id: str
    state: dict[str, Any]


class SearchController(ABC):
    """调用方只需学会 select/update/abandon;决策审计由基类统一保证。"""

    def __init__(self) -> None:
        self._decisions: list[ControllerDecision] = []
        self._pending_index: int | None = None

    @property
    @abstractmethod
    def name(self) -> str: ...

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

        self._learn(strategy_id, score)
        self._decisions[self._pending_index] = _resolved_decision(
            decision,
            observed_score=score,
            outcome=ControllerDecisionOutcome.COMPLETED,
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
        return tuple(decision.model_copy(deep=True) for decision in self._decisions)

    @abstractmethod
    def _choose(self, available_strategy_ids: tuple[str, ...]) -> _Selection: ...

    def _learn(self, strategy_id: str, score: float) -> None:
        """非学习基线为空实现;Bandit 将在子类中覆盖。"""
        return None


def _resolved_decision(
    decision: ControllerDecision,
    **updates: object,
) -> ControllerDecision:
    payload = decision.model_dump(mode="python")
    payload.update(updates)
    return ControllerDecision.model_validate(payload)
