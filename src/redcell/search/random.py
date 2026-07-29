"""Random baseline:在可用 Strategy 中均匀随机。"""

from __future__ import annotations

import random

from redcell.search.base import SearchController, _Selection


class RandomController(SearchController):
    def __init__(self, rng: random.Random) -> None:
        super().__init__()
        self._rng = rng

    @property
    def name(self) -> str:
        return "random"

    def _choose(self, available_strategy_ids: tuple[str, ...]) -> _Selection:
        selected_index = self._rng.randrange(len(available_strategy_ids))
        return _Selection(
            strategy_id=available_strategy_ids[selected_index],
            state={
                "selected_index": selected_index,
                "candidate_count": len(available_strategy_ids),
            },
        )
