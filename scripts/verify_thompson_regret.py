"""零成本验证 Thompson Sampling 是否会偏向已知较优的合成臂。

这不是对真实靶场的结论，也不进入 pytest。它只验证搜索器本身：两个固定 reward
臂在 1,000 次选择后，累计 regret 应远低于线性探索的量级。
"""

from __future__ import annotations

import random

from redcell.search import ThompsonSamplingController

REWARDS = {"strong": 0.9, "weak": 0.1}
ROUNDS = 1_000
SEED = 20_260_806


def main() -> None:
    controller = ThompsonSamplingController(random.Random(SEED))
    best_reward = max(REWARDS.values())
    cumulative_reward = 0.0
    selections = {strategy_id: 0 for strategy_id in REWARDS}

    for round_index in range(1, ROUNDS + 1):
        selected = controller.select(list(REWARDS))
        score = REWARDS[selected]
        controller.update(selected, score)
        selections[selected] += 1
        cumulative_reward += score

        if round_index in (10, 100, 500, ROUNDS):
            regret = best_reward * round_index - cumulative_reward
            print(
                f"round={round_index:4d} cumulative_reward={cumulative_reward:7.1f} "
                f"regret={regret:6.2f} regret/round={regret / round_index:.4f}"
            )

    final_regret = best_reward * ROUNDS - cumulative_reward
    print(f"selections={selections}")
    print(f"final_regret={final_regret:.2f}; compare regret/round rather than claiming a proof.")


if __name__ == "__main__":
    main()
