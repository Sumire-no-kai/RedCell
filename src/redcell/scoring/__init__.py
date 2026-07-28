"""判定层。

Phase 0 只有 Level-1(确定性规则)。Level-2(结构化规则)与 Level-3(LLM judge)
留到 Phase 1 —— 核心实验刻意不引入 judge 噪声,见 docs/CONCEPTS.md。
"""

from redcell.scoring.level1 import Level1Scorer, ScoringResult
from redcell.scoring.tiers import TIER_REWARDS, CanaryTier, ToolTier, reward_for

__all__ = [
    "TIER_REWARDS",
    "CanaryTier",
    "Level1Scorer",
    "ScoringResult",
    "ToolTier",
    "reward_for",
]
