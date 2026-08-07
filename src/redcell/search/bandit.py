"""Thompson Sampling —— Beta-Bernoulli，通过概率取整消化 [0,1] reward。

选型理由、冷启动处理和 decision_state 的字段设计见 DEVLOG 2026-08-06。
"""

from __future__ import annotations

import random
from typing import Any

from redcell.search.base import SearchController, Selection


class ThompsonSamplingController(SearchController):
    """每个臂维护 Beta(alpha, beta) 后验；每轮各抽一个样本，选最高的。

    reward 是 [0,1] 的分档值，而 Beta-Bernoulli 只接受二元反馈。这里将 reward
    视为本次记为成功的概率，再用私有、可复现的 RNG 抽取 0/1 结果。该近似满足
    ``E[outcome] = reward``，且不需要冷启动时不可靠的方差估计。
    """

    def __init__(self, rng: random.Random | None = None) -> None:
        super().__init__()
        self._rng = rng
        self._posteriors: dict[str, tuple[float, float]] = {}

    @property
    def name(self) -> str:
        return "thompson"

    @property
    def requires_seed(self) -> bool:
        return True

    def _on_seeded(self, controller_seed: int) -> None:
        if self._rng is None:
            self._rng = random.Random(controller_seed)

    def _choose(self, available_strategy_ids: tuple[str, ...]) -> Selection:
        if self._rng is None:
            raise ValueError("ThompsonSamplingController 尚未播种;调用 seed() 或在构造时注入 rng")

        posteriors_before: dict[str, dict[str, float]] = {}
        samples: dict[str, float] = {}
        for strategy_id in available_strategy_ids:
            alpha, beta = self._posteriors.setdefault(strategy_id, (1.0, 1.0))
            posteriors_before[strategy_id] = {"alpha": alpha, "beta": beta}
            samples[strategy_id] = self._rng.betavariate(alpha, beta)

        selected = max(available_strategy_ids, key=lambda strategy_id: samples[strategy_id])
        return Selection(
            strategy_id=selected,
            state={
                "posteriors_before": posteriors_before,
                "samples": samples,
                "selected_sample": samples[selected],
            },
        )

    def _learn(self, strategy_id: str, score: float) -> dict[str, Any]:
        if self._rng is None:
            raise RuntimeError("ThompsonSamplingController 的 RNG 在学习前未初始化")

        alpha, beta = self._posteriors[strategy_id]
        outcome = 1 if self._rng.random() < score else 0
        updated = (alpha + outcome, beta + (1 - outcome))
        self._posteriors[strategy_id] = updated
        return {
            "posterior_update": {
                "outcome": outcome,
                "before": {"alpha": alpha, "beta": beta},
                "after": {"alpha": updated[0], "beta": updated[1]},
            }
        }
