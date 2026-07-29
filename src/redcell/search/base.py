"""SearchController 的窄接口与统一决策审计。"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from pydantic import Field

from redcell.protocols.common import RedCellModel


class ControllerProtocolError(RuntimeError):
    """select/update 调用顺序或结果违反 Controller interface。"""


class NoAvailableStrategiesError(RuntimeError):
    """Budget Manager 过滤后没有可选 Strategy。"""


class ControllerDecision(RedCellModel):
    attempt_index: int = Field(ge=0)
    controller: str
    available_strategy_ids: list[str] = Field(min_length=1)
    selected_strategy_id: str
    decision_state: dict[str, Any] = Field(default_factory=dict)
    observed_score: float | None = Field(default=None, ge=0.0, le=1.0)


@dataclass(frozen=True)
class _Selection:
    strategy_id: str
    state: dict[str, Any]


class SearchController(ABC):
    """调用方只需学会 select/update;决策记录由基类统一保证。"""

    def __init__(self) -> None:
        self._decisions: list[ControllerDecision] = []
        self._pending_index: int | None = None

    @property
    @abstractmethod
    def name(self) -> str: ...

    def select(self, available_strategy_ids: Sequence[str]) -> str:
        """从 Budget Manager 给出的可选列表中选一个。

        一次 select 必须对应一次有效 update。基础设施错误时由上层停止或采用
        未来明确的错误策略,不能悄悄再 select 并丢掉未完成决策。
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
        self._decisions[self._pending_index] = decision.model_copy(update={"observed_score": score})
        self._pending_index = None

    @property
    def decisions(self) -> tuple[ControllerDecision, ...]:
        return tuple(decision.model_copy(deep=True) for decision in self._decisions)

    @abstractmethod
    def _choose(self, available_strategy_ids: tuple[str, ...]) -> _Selection: ...

    def _learn(self, strategy_id: str, score: float) -> None:
        """非学习基线为空实现;Bandit 将在子类中覆盖。"""
        return None
