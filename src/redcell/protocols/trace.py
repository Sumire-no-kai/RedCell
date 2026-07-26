"""Attempt 与 Trace —— 一次攻击的完整记录。

计量单位约定(重要):**一次 Attempt = 一场完整的攻击会话**,内部可能有多轮对话。
理由是 bandit 拉一次杆 = 试一个策略 = 一次 attempt,三者必须一一对应,
reward 的归属才清晰。多轮策略天然更费 token,这个差异由独立的 token 预算约束,
不去污染 query 预算的语义。
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from pydantic import Field, model_validator

from redcell.protocols.adapter import AdapterOutput
from redcell.protocols.common import (
    REDCELL_PROTOCOL_VERSION,
    RedCellModel,
    SignalChannel,
    new_id,
)

REWARD_TOLERANCE = 1e-9


class Turn(RedCellModel):
    """会话中的一轮:攻击方说一句,目标回一次(可能带工具调用)。"""

    index: int
    attacker_message: str
    output: AdapterOutput


class SignalScore(RedCellModel):
    """单条信号线的确定性得分。

    这些分数**全量保留**,不因为 reward 取 max 而丢失——
    reward 是给 bandit 的控制信号(可以有损压缩成一个数),
    signals 是证据链(绝不能有损)。两条线同时非零意味着两类风险同时存在,
    应当各自生成一条 Finding。
    """

    channel: SignalChannel
    score: float = Field(ge=0.0, le=1.0)
    tier: str
    """命中的档位名,如 "canary_full" / "tool_constraint_violation"。"""
    evidence: str
    """具体匹配到了什么,供人工复核。"""


class CostRecord(RedCellModel):
    prompt_tokens: int = 0
    completion_tokens: int = 0
    usd: float = 0.0
    wall_ms: float = 0.0

    @property
    def total_tokens(self) -> int:
        return self.prompt_tokens + self.completion_tokens


class ReproductionContext(RedCellModel):
    """复现这次 attempt 所需的**全部**上下文。

    PRD §5.5 要求每个漏洞必须可复现。缺字段这件事的残酷之处在于:
    只有等到复现失败那天才会发现,而那时实验数据已经跑完了。
    所以宁可现在多记。
    """

    policy_version: str
    target_name: str
    adapter_type: str
    strategy_id: str
    mutation_operators: list[str] = Field(default_factory=list)
    parent_attempt_id: str | None = None
    seed: int | None = None
    target_model: str | None = None
    target_temperature: float | None = None
    attacker_model: str | None = None
    attacker_temperature: float | None = None
    protocol_version: str = REDCELL_PROTOCOL_VERSION
    recorded_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    extra: dict[str, Any] = Field(default_factory=dict)


def compute_reward(signals: list[SignalScore]) -> float:
    """把多条信号线压成给 bandit 的单个标量。

    取 max 而不是求和/加权:一次 attempt 的目标是"找到任何一个漏洞",
    不是"同时找到两个"。求和会让通用策略仅因为触发面广就获得虚高评价。

    代价:两类漏洞同时命中时,reward 无法体现"这次收获更大"。
    我们接受这个代价——覆盖度由 signals 全量记录和 Finding 数量体现,
    不需要 reward 兼职表达。
    """
    return max((s.score for s in signals), default=0.0)


class Attempt(RedCellModel):
    """一场完整攻击会话的记录。也是 bandit 的一次"拉杆"。"""

    id: str = Field(default_factory=new_id)
    run_id: str
    strategy_id: str
    actor: str
    attack_prompt: str
    """本场使用的攻击话术(变异后的最终版本)。"""

    turns: list[Turn] = Field(default_factory=list)
    signals: list[SignalScore] = Field(default_factory=list)
    reward: float = Field(default=0.0, ge=0.0, le=1.0)
    cost: CostRecord = Field(default_factory=CostRecord)
    reproduction: ReproductionContext
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @model_validator(mode="after")
    def _reward_matches_signals(self) -> Attempt:
        expected = compute_reward(self.signals)
        if abs(self.reward - expected) > REWARD_TOLERANCE:
            raise ValueError(
                f"reward({self.reward}) 与 signals 的 max({expected}) 不一致。"
                "reward 必须由 compute_reward(signals) 得出,不可手工赋值。"
            )
        return self

    # ── 查询辅助 ──────────────────────────────────────────────────────────

    @property
    def turn_count(self) -> int:
        return len(self.turns)

    def signal(self, channel: SignalChannel) -> SignalScore | None:
        return next((s for s in self.signals if s.channel is channel), None)

    def triggered_channels(self) -> list[SignalChannel]:
        """所有非零信号线。两条都在 = 两类风险同时存在。"""
        return [s.channel for s in self.signals if s.score > 0.0]

    def all_tool_calls(self) -> list[Any]:
        return [tc for turn in self.turns for tc in turn.output.tool_calls]

    def all_side_effects(self) -> list[Any]:
        return [se for turn in self.turns for se in turn.output.side_effects]


def build_attempt(
    *,
    run_id: str,
    strategy_id: str,
    actor: str,
    attack_prompt: str,
    reproduction: ReproductionContext,
    turns: list[Turn] | None = None,
    signals: list[SignalScore] | None = None,
    cost: CostRecord | None = None,
) -> Attempt:
    """构造 Attempt 的推荐入口:reward 由 signals 自动推导,杜绝手工赋值。"""
    signals = signals or []
    return Attempt(
        run_id=run_id,
        strategy_id=strategy_id,
        actor=actor,
        attack_prompt=attack_prompt,
        turns=turns or [],
        signals=signals,
        reward=compute_reward(signals),
        cost=cost or CostRecord(),
        reproduction=reproduction,
    )
