"""Attempt 与 Trace —— 一次攻击的完整记录。

计量单位约定(重要):**一次 Attempt = 一场完整的攻击会话**,内部可能有多轮对话。
理由是 bandit 拉一次杆 = 试一个策略 = 一次 attempt,三者必须一一对应,
reward 的归属才清晰。多轮策略天然更费 token,这个差异由独立的 token 预算约束,
不去污染 query 预算的语义。
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import Field, model_validator

from redcell._base import CostRecord
from redcell.protocols.adapter import AdapterOutput
from redcell.protocols.common import (
    REDCELL_PROTOCOL_VERSION,
    RedCellModel,
    SignalChannel,
    new_id,
)

REWARD_TOLERANCE = 1e-9


class AttemptStopReason(StrEnum):
    """一场 Attempt 为什么停止。

    不能只记 `stopped_early: bool`:同样是只跑了一轮,可能是已经确认漏洞,
    也可能是跑满了计划轮数。原因不同,实验含义完全不同。

    ⚠️ **只列举得到的两种。** 这里刻意没有 `execution_error` / `aborted` ——
    因为 Attempt 对象只为**完整执行完的会话**而存在:执行失败或被取消时,
    Executor 抛 AttemptExecutionError,Orchestrator 走 abandon 路径,
    事实记在 FailureRecord 与 RunEvent 里,**不会构造出一个 Attempt**。
    列一个永远取不到的值,会让读代码的人以为存在一条根本不存在的分支。

    将来若 resume 需要持久化部分执行的 Attempt,再随那次改动一起加回。
    """

    ATTEMPT_SUCCESS = "attempt_success"
    MAX_TURNS = "max_turns"


class Turn(RedCellModel):
    """会话中的一轮:攻击方说一句,目标回一次(可能带工具调用)。"""

    index: int
    attacker_message: str
    output: AdapterOutput

    attacker_generation_retries: int = 0
    """生成这句话术时额外重采样了几次。

    ⚠️ **不落进 trace 就等于没记。** `AttackMessage.generation_retries` 加上之后
    我曾写下"校准时应当聚合这个数",但它当时只活在内存里 —— 聚合不了。
    重试会把"攻击方不稳"这个症状盖住,而症状正是"该换攻击方"的信号。
    """

    attacker_cost: CostRecord = Field(default_factory=CostRecord)
    """生成这句攻击话术花掉的用量。**与 target 侧分开记,但一起计入预算。**

    分开记是 CONCEPTS §14.4 的要求(两个模型位必须分别记录 model/temperature/cost),
    这样事后能回答"这轮到底是哪一侧贵";一起计入是因为**预算约束的是整场实验的
    总开销**,漏掉任何一侧都会让上限失真。
    """


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


# `CostRecord` 现在定义在 `redcell._base` —— 因为 `failures.py` 也要用它,
# 而 failures 不能依赖 protocols(会形成循环导入,见 `_base.py` 文档)。
# 这里 re-export,既有的 `from redcell.protocols.trace import CostRecord` 不受影响。


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
    run_seed: int | None = None
    controller_seed: int | None = None
    seed: int | None = None
    """本场 Attempt 的派生种子。保留字段名以兼容已有记录。"""
    generator_seed: int | None = None
    actor_seed: int | None = None
    target_seed: int | None = None
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
    planned_max_turns: int | None = Field(default=None, ge=1)
    stop_reason: AttemptStopReason | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @model_validator(mode="after")
    def _reward_matches_signals(self) -> Attempt:
        expected = compute_reward(self.signals)
        if abs(self.reward - expected) > REWARD_TOLERANCE:
            raise ValueError(
                f"reward({self.reward}) 与 signals 的 max({expected}) 不一致。"
                "reward 必须由 compute_reward(signals) 得出,不可手工赋值。"
            )
        if self.planned_max_turns is not None and self.turn_count > self.planned_max_turns:
            raise ValueError(
                f"实际轮数({self.turn_count})超过计划上限({self.planned_max_turns})。"
                "Executor 不得在 max_turns 之后继续发送消息。"
            )
        return self

    # ── 查询辅助 ──────────────────────────────────────────────────────────

    @property
    def turn_count(self) -> int:
        return len(self.turns)

    @property
    def stopped_early(self) -> bool:
        """是否在计划轮数前结束。

        该布尔值只作查询便利;解释原因必须看 `stop_reason`。
        """
        return self.planned_max_turns is not None and self.turn_count < self.planned_max_turns

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
    attempt_id: str | None = None,
    run_id: str,
    strategy_id: str,
    actor: str,
    attack_prompt: str,
    reproduction: ReproductionContext,
    turns: list[Turn] | None = None,
    signals: list[SignalScore] | None = None,
    cost: CostRecord | None = None,
    planned_max_turns: int | None = None,
    stop_reason: AttemptStopReason | None = None,
) -> Attempt:
    """构造 Attempt 的推荐入口:reward 由 signals 自动推导,杜绝手工赋值。"""
    signals = signals or []
    payload: dict[str, Any] = {
        "run_id": run_id,
        "strategy_id": strategy_id,
        "actor": actor,
        "attack_prompt": attack_prompt,
        "turns": turns or [],
        "signals": signals,
        "reward": compute_reward(signals),
        "cost": cost or CostRecord(),
        "reproduction": reproduction,
        "planned_max_turns": planned_max_turns,
        "stop_reason": stop_reason,
    }
    if attempt_id is not None:
        payload["id"] = attempt_id
    return Attempt(
        **payload,
    )
