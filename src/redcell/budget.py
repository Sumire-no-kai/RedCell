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

# ⚠️ 从 `_base` 而非 `protocols.common` 取:`protocols/run.py` 反过来依赖本模块
# (`Run.limits`),走 protocols 会形成循环导入。见 `_base.py` 的模块文档。
from redcell._base import RedCellModel


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

    count_abandoned_against_attempts: bool = True
    """放弃的 attempt 算不算进 `max_attempts`。⭐

    **默认 True(普通扫描):** `max_attempts` 是"最多给目标发多少场",
    放弃的也算 —— 它是**成本闸门**,故障也消耗了配额和时间。

    **校准必须设 False。** 否则会出现一件很难察觉的坏事:
    `max_attempts=1200` 配上 10% 的放弃容忍,一轮可以"正常完成"于约 1080 条
    有效样本 —— 某个策略手里只有 180 条,而 `CALIBRATION.md` §7 冻结的是 **200**。
    更糟的是缺口**不均匀**:限流窗口里正在跑哪个臂,缺的就是哪个臂,
    而 §4.1 检验的正是**成对比较** —— 一边 200 一边 180,两条臂不再等权。

    设为 False 后,放弃的场次会被自动补跑(预算按**完成数**结算),
    N=200 这个冻结标准就不会被运行故障悄悄改小。
    其余上限(token / 墙钟 / 连续放弃 / 放弃比例)仍然照常兜底,不会无限跑下去。
    """

    max_completed_per_strategy: int | None = Field(default=None, ge=1)
    """每个策略要跑满多少条**完成**的 attempt。⭐ 校准专用。

    ## 为什么单靠 `count_abandoned_against_attempts` 不够

    那一项补的是**总样本量**,不是**每臂的**。实测(2026-08-03)一轮 N=10 的彩排:

    ```
    逻辑 76 / 完成 70 / 放弃 6
    每臂完成: [9, 9, 10, 10, 10, 11, 11]   ← 总数对了,每臂没对
    ```

    round-robin 控制器在某臂被放弃后只是继续轮转,**不会专门把那一臂补回来**。
    而校准冻结的是**每臂 N=200**:190 与 210 并存会让成对比较不等权 ——
    那恰好是 `STRATEGIES.md` §4.1 要测的量。

    设了本项之后,跑满额度的臂会退出候选池,其余继续跑,直到**每一臂都满**。
    """

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
        if self.max_completed_per_strategy is not None and self.count_abandoned_against_attempts:
            # 不静默降级:两者同时生效时,坏运气会在每臂跑满之前先耗光总预算,
            # 于是又回到"每臂不等长"那个 bug —— 而且**看起来是正常完成的**。
            raise ValueError(
                "max_completed_per_strategy 需要配合 count_abandoned_against_attempts=False,"
                "否则放弃的 attempt 会先耗光总预算,每臂仍然跑不满"
            )
        return self


class BudgetUsage(RedCellModel):
    """逻辑机会、有效样本与运行故障分开计数。"""

    attempts: int = 0
    completed_attempts: int = 0
    abandoned_attempts: int = 0
    successful_selections: int = 0
    abandoned_selections: int = 0
    retries: int = 0
    prompt_tokens: int = 0
    completion_tokens: int = 0
    cost_usd: float = 0.0
    wall_seconds: float = 0.0
    per_strategy_attempts: dict[str, int] = Field(default_factory=dict)
    per_strategy_completed: dict[str, int] = Field(default_factory=dict)
    """每个策略**跑完**了多少场。

    与 `per_strategy_attempts`(逻辑机会)分开记,因为校准要的是有效样本量:
    看这两个数对不对得上,就知道 N 有没有被运行故障吃掉,以及吃在了哪个臂上。
    """

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
        self._per_strategy_completed: Counter[str] = Counter()
        self._wall_seconds_before_start = 0.0

    @classmethod
    def from_usage(
        cls,
        limits: BudgetLimits,
        usage: BudgetUsage,
        *,
        clock=time.monotonic,
    ) -> BudgetManager:
        """从一次原子提交后的账本恢复；离线停机时间不计入 wall-clock 预算。"""
        manager = cls(limits, clock=clock)
        manager._usage = usage.model_copy(deep=True)
        manager._per_strategy = Counter(usage.per_strategy_attempts)
        manager._per_strategy_completed = Counter(usage.per_strategy_completed)
        manager._wall_seconds_before_start = usage.wall_seconds
        return manager

    @property
    def limits(self) -> BudgetLimits:
        return self._limits

    def usage(self) -> BudgetUsage:
        return self._usage.model_copy(
            update={
                "wall_seconds": self._elapsed(),
                "per_strategy_attempts": dict(self._per_strategy),
                "per_strategy_completed": dict(self._per_strategy_completed),
            }
        )

    def _elapsed(self) -> float:
        return self._wall_seconds_before_start + self._clock() - self._started

    def _attempts_spent(self) -> int:
        """按当前计数口径,已经花掉多少 attempt 预算。

        口径由 `count_abandoned_against_attempts` 决定 —— 见该字段的说明。
        计成本时数逻辑机会,计样本时数完成数,两者不能混用同一个变量。
        """
        if self._limits.count_abandoned_against_attempts:
            return self._usage.attempts
        return self._usage.completed_attempts

    # ── 准入 ─────────────────────────────────────────────────────────────

    def exhausted(self) -> BudgetLimit | None:
        """整体预算是否已经用尽(与具体策略无关)。"""
        limits = self._limits
        if limits.max_attempts is not None and self._attempts_spent() >= limits.max_attempts:
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
        per_strategy = self._limits.max_completed_per_strategy
        if per_strategy is not None and self._per_strategy_completed[strategy_id] >= per_strategy:
            # 这一臂已经跑满 —— 退出候选池,让别的臂补上。
            # 全部退出时 available_strategies() 返回空,orchestrator 据此正常结束。
            return True

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
        self.complete_attempt(strategy_id)

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

    def complete_attempt(self, strategy_id: str) -> None:
        """记一场**有效样本**。

        刻意要求传 strategy_id 而不是做成可选:每臂的有效样本量是校准的核心量,
        让调用方无法"忘了传"比事后发现某个臂的计数一直是 0 要好。
        """
        self._usage = self._usage.model_copy(
            update={"completed_attempts": self._usage.completed_attempts + 1}
        )
        self._per_strategy_completed[strategy_id] += 1

    def abandon_attempt(self) -> None:
        self._usage = self._usage.model_copy(
            update={"abandoned_attempts": self._usage.abandoned_attempts + 1}
        )

    def complete_selection(self) -> None:
        self._usage = self._usage.model_copy(
            update={"successful_selections": self._usage.successful_selections + 1}
        )

    def abandon_selection(self) -> None:
        self._usage = self._usage.model_copy(
            update={"abandoned_selections": self._usage.abandoned_selections + 1}
        )

    def record_retry(self) -> None:
        self._usage = self._usage.model_copy(update={"retries": self._usage.retries + 1})

    # ── 观测 ─────────────────────────────────────────────────────────────

    def remaining_attempts(self) -> int | None:
        if self._limits.max_attempts is None:
            return None
        return max(0, self._limits.max_attempts - self._attempts_spent())

    def progress(self) -> float:
        """已消耗比例,取各项里最紧的一项。用于进度显示。"""
        ratios = []
        limits, usage = self._limits, self._usage
        if limits.max_attempts:
            ratios.append(self._attempts_spent() / limits.max_attempts)
        if limits.max_total_tokens:
            ratios.append(usage.total_tokens / limits.max_total_tokens)
        if limits.max_cost_usd:
            ratios.append(usage.cost_usd / limits.max_cost_usd)
        if limits.max_wall_seconds:
            ratios.append(self._elapsed() / limits.max_wall_seconds)
        return min(1.0, max(ratios, default=0.0))
