"""Static baseline:按冻结顺序循环。"""

from __future__ import annotations

from redcell.search.base import NoAvailableStrategiesError, SearchController, Selection


class StaticController(SearchController):
    def __init__(self, strategy_order: list[str]) -> None:
        if not strategy_order:
            raise ValueError("strategy_order 不能为空")
        if len(set(strategy_order)) != len(strategy_order):
            raise ValueError("strategy_order 不能包含重复项")
        super().__init__()
        self._order = tuple(strategy_order)
        self._cursor = 0

    @property
    def name(self) -> str:
        return "static"

    def _choose(self, available_strategy_ids: tuple[str, ...]) -> Selection:
        available = set(available_strategy_ids)
        cursor_before = self._cursor

        for offset in range(len(self._order)):
            order_index = (self._cursor + offset) % len(self._order)
            candidate = self._order[order_index]
            if candidate not in available:
                continue

            self._cursor = (order_index + 1) % len(self._order)
            return Selection(
                strategy_id=candidate,
                state={
                    "cursor_before": cursor_before,
                    "selected_order_index": order_index,
                },
            )

        raise NoAvailableStrategiesError("可选 Strategy 均不在 StaticController 的冻结顺序中")
