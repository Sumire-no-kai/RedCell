"""预算管理 —— 把成本从"目标"变成"约束"。

这是一个刻意的建模选择。另一种写法是把成本折进 reward:
`reward = 命中 − λ × 成本`。但 λ 该取多少?一次 API 调用值多少个漏洞?
这个权重永远是拍脑袋的,而且换一个 λ 结论就变。

改成"在预算 ≤ N 的前提下最大化发现"就不需要任何权重
(文献里叫 **budgeted bandit / bandit with knapsack**),
而且和产品语义天然吻合:"我给你 100 次机会,尽量找"。

⚠️ 预算之所以必须存在,不只是省钱:**整个研究问题的立足点就是"预算有限"**。
预算无限时 bandit 毫无价值——全都试一万次自然知道谁最好。
"""

from __future__ import annotations

import time
from collections import Counter
from enum import StrEnum

from pydantic import Field, model_validator

from redcell.protocols.common import RedCellModel


class BudgetLimit(StrEnum):
    """触发停止的具体原因。写进报告,让"为什么停了"永远是明确的。"""

    ATTEMPTS = "attempts"
    TOKENS = "tokens"
    COST = "cost"
    WALL_CLOCK = "wall_clock"
    STRATEGY_SHARE = "strategy_share"
    """单个策略占用的预算比例超限 —— 见 BudgetLimits.max_share_per_strategy。"""


class BudgetLimits(RedCellModel):
    """一次 Run 的预算上限。至少要设一项,否则可能永不停止。"""

    max_attempts: int | None = Field(default=None, ge=1)
    max_total_tokens: int | None = Field(default=None, ge=1)
    max_cost_usd: float | None = Field(default=None, gt=0)
    max_wall_seconds: float | None = Field(default=None, gt=0)

    max_share_per_strategy: float | None = Field(default=None, gt=0, le=1.0)
    """单个策略最多能占走多少比例的 attempt 预算。

    存在的意义是给 bandit 的"利用"设一道上限:一个早期运气好的臂
    可能把几乎全部预算吸走,于是这次 run 实质上退化成了单策略测试,
    coverage 归零而我们还以为在做自适应搜索。

    需要 max_attempts 才能计算,否则没有分母。
    """

    @model_validator(mode="after")
    def _require_at_least_one_limit(self) -> BudgetLimits:
        if not any(
            [self.max_attempts, self.max_total_tokens, self.max_cost_usd, self.max_wall_seconds]
        ):
            raise ValueError("至少要设一项预算上限,否则 Run 可能永不停止")
        if self.max_share_per_strategy is not None and self.max_attempts is None:
            raise ValueError("max_share_per_strategy 需要 max_attempts 作为分母")
        return self


class BudgetUsage(RedCellModel):
    """逻辑机会、有效样本与运行故障分开计数。"""

    attempts: int = 0
    completed_attempts: int = 0
    abandoned_attempts: int = 0
    retries: int = 0
    prompt_tokens: int = 0
    completion_tokens: int = 0
    cost_usd: float = 0.0
    wall_seconds: float = 0.0
    per_strategy_attempts: dict[str, int] = Field(default_factory=dict)

    @property
    def total_tokens(self) -> int:
        return self.prompt_tokens + self.completion_tokens


class BudgetManager:
    """预算账本。

    **计量单位是 attempt,而且 attempt 是原子的。** 预算只在一场 attempt
    *开始之前*检查,不在中途打断 —— 打断会留下一条残缺的 trace,
    既无法判定也无法复现,那比稍微超支糟糕得多。

    因此实际消耗可能略微越过 token / 成本上限,幅度不超过一场 attempt。
    这是有意的取舍,不是 bug。
    """

    def __init__(self, limits: BudgetLimits, *, clock=time.monotonic) -> None:
        self._limits = limits
        self._clock = clock
        self._started = clock()
        self._usage = BudgetUsage()
        self._per_strategy: Counter[str] = Counter()

    @property
    def limits(self) -> BudgetLimits:
        return self._limits

    def usage(self) -> BudgetUsage:
        return self._usage.model_copy(
            update={
                "wall_seconds": self._elapsed(),
                "per_strategy_attempts": dict(self._per_strategy),
            }
        )

    def _elapsed(self) -> float:
        return self._clock() - self._started

    # ── 准入 ─────────────────────────────────────────────────────────────

    def exhausted(self) -> BudgetLimit | None:
        """整体预算是否已经用尽(与具体策略无关)。"""
        limits = self._limits
        if limits.max_attempts is not None and self._usage.attempts >= limits.max_attempts:
            return BudgetLimit.ATTEMPTS
        if (
            limits.max_total_tokens is not None
            and self._usage.total_tokens >= limits.max_total_tokens
        ):
            return BudgetLimit.TOKENS
        if limits.max_cost_usd is not None and self._usage.cost_usd >= limits.max_cost_usd:
            return BudgetLimit.COST
        if limits.max_wall_seconds is not None and self._elapsed() >= limits.max_wall_seconds:
            return BudgetLimit.WALL_CLOCK
        return None

    def blocked_reason(self, strategy_id: str) -> BudgetLimit | None:
        """这个策略现在能不能再跑一场。None 表示可以。"""
        overall = self.exhausted()
        if overall is not None:
            return overall
        if self._strategy_share_exceeded(strategy_id):
            return BudgetLimit.STRATEGY_SHARE
        return None

    def allows(self, strategy_id: str) -> bool:
        return self.blocked_reason(strategy_id) is None

    def available_strategies(self, strategy_ids: list[str]) -> list[str]:
        """筛掉已经打满配额的策略,供 controller 选择。

        整体预算耗尽时返回空列表 —— 此时应结束 Run,而不是换一个策略。
        """
        if self.exhausted() is not None:
            return []
        return [sid for sid in strategy_ids if not self._strategy_share_exceeded(sid)]

    def _strategy_share_exceeded(self, strategy_id: str) -> bool:
        share = self._limits.max_share_per_strategy
        if share is None or self._limits.max_attempts is None:
            return False
        cap = max(1, int(self._limits.max_attempts * share))
        return self._per_strategy[strategy_id] >= cap

    # ── 记账 ─────────────────────────────────────────────────────────────

    def record(
        self,
        *,
        strategy_id: str,
        prompt_tokens: int = 0,
        completion_tokens: int = 0,
        cost_usd: float = 0.0,
    ) -> None:
        """兼容入口:预留、记资源并完成一场有效 Attempt。"""
        self.reserve_attempt(strategy_id)
        self.record_usage(
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            cost_usd=cost_usd,
        )
        self.complete_attempt()

    def reserve_attempt(self, strategy_id: str) -> None:
        """Controller 选中 Strategy 后立即占用一个逻辑 Attempt 位置。"""
        self._usage = self._usage.model_copy(
            update={
                "attempts": self._usage.attempts + 1,
            }
        )
        self._per_strategy[strategy_id] += 1

    def record_usage(
        self,
        *,
        prompt_tokens: int = 0,
        completion_tokens: int = 0,
        cost_usd: float = 0.0,
    ) -> None:
        """追加真实资源消耗;失败请求也必须调用。"""
        self._usage = self._usage.model_copy(
            update={
                "prompt_tokens": self._usage.prompt_tokens + prompt_tokens,
                "completion_tokens": self._usage.completion_tokens + completion_tokens,
                "cost_usd": self._usage.cost_usd + cost_usd,
            }
        )

    def complete_attempt(self) -> None:
        self._usage = self._usage.model_copy(
            update={"completed_attempts": self._usage.completed_attempts + 1}
        )

    def abandon_attempt(self) -> None:
        self._usage = self._usage.model_copy(
            update={"abandoned_attempts": self._usage.abandoned_attempts + 1}
        )

    def record_retry(self) -> None:
        self._usage = self._usage.model_copy(update={"retries": self._usage.retries + 1})

    # ── 观测 ─────────────────────────────────────────────────────────────

    def remaining_attempts(self) -> int | None:
        if self._limits.max_attempts is None:
            return None
        return max(0, self._limits.max_attempts - self._usage.attempts)

    def progress(self) -> float:
        """已消耗比例,取各项里最紧的一项。用于进度显示。"""
        ratios = []
        limits, usage = self._limits, self._usage
        if limits.max_attempts:
            ratios.append(usage.attempts / limits.max_attempts)
        if limits.max_total_tokens:
            ratios.append(usage.total_tokens / limits.max_total_tokens)
        if limits.max_cost_usd:
            ratios.append(usage.cost_usd / limits.max_cost_usd)
        if limits.max_wall_seconds:
            ratios.append(self._elapsed() / limits.max_wall_seconds)
        return min(1.0, max(ratios, default=0.0))
