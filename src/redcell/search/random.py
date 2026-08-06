"""Random baseline:在可用 Strategy 中均匀随机。"""

from __future__ import annotations

import random

from redcell.search.base import ControllerProtocolError, SearchController, Selection


class RandomController(SearchController):
    """在可用 Strategy 中均匀随机。

    RNG 由 Orchestrator 通过 `seed()` 从 Run 主种子派生后注入 ——
    构造时也可以直接传一个 RNG,仅供不经 Orchestrator 的单元测试使用。
    """

    def __init__(self, rng: random.Random | None = None) -> None:
        super().__init__()
        self._rng = rng

    @property
    def name(self) -> str:
        return "random"

    @property
    def requires_seed(self) -> bool:
        return True

    def _on_seeded(self, controller_seed: int) -> None:
        self._rng = random.Random(controller_seed)

    def _choose(self, available_strategy_ids: tuple[str, ...]) -> Selection:
        if self._rng is None:
            raise ControllerProtocolError(
                "RandomController 尚未播种;必须先调用 seed(),或在构造时注入 RNG"
            )
        selected_index = self._rng.randrange(len(available_strategy_ids))
        return Selection(
            strategy_id=available_strategy_ids[selected_index],
            state={
                "selected_index": selected_index,
                "candidate_count": len(available_strategy_ids),
            },
        )
