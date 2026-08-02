"""按故障类型配置的有界重试与 Run 可靠性阈值。"""

from __future__ import annotations

import asyncio
import random
from collections.abc import Awaitable, Callable
from typing import TypeVar

from pydantic import Field

from redcell.failures import (
    DeliveryStatus,
    FailureKind,
    FailureRecord,
    FailureStage,
    RetrySafety,
    SideEffectStatus,
)

# 只依赖 provider 的异常类型。openai_compatible 只向下依赖 llm.base 与 protocols.common,
# 不会与本模块形成环 —— 有 test_module_imports 的逐模块子进程导入兜底。
from redcell.llm.openai_compatible import ProviderRateLimitedError, ProviderTransientError
from redcell.protocols.common import RedCellModel
from redcell.reliability import ReliabilityPolicy

T = TypeVar("T")

RETRY_AFTER_KEY = "retry_after_seconds"
"""`FailureRecord.details` 里存放服务端 `Retry-After` 的键。

放在 `details` 而不是给 `FailureRecord` 加字段:它只对限流这一类有意义,
为一种故障给所有故障加一个大多数时候为空的字段,不划算。
"""


class RetryPolicy(RedCellModel):
    """工程默认值集中在一个配置对象中,不散落在 catch 分支。

    ⚠️ **限流(429)有独立的一套参数。** 原先它与网络故障共用
    `base=0.5s / cap=8s`,那组值是按"付费 API 的瞬时抖动"调的:
    4 次重试累计只等约 3.75 秒。而 2026-08-01 实测免费层限流恢复
    **需要累计等 116 秒** —— 用原参数会在正常的免费层抖动下直接判死一次 attempt。
    """

    max_agent_retries: int = Field(default=2, ge=0, le=10)
    max_network_retries: int = Field(default=4, ge=0, le=20)
    max_rate_limit_retries: int = Field(default=5, ge=0, le=20)
    max_persistence_retries: int = Field(default=4, ge=0, le=20)

    base_delay_seconds: float = Field(default=0.5, ge=0)
    max_delay_seconds: float = Field(default=8.0, ge=0)

    rate_limit_base_delay_seconds: float = Field(default=5.0, ge=0)
    rate_limit_max_delay_seconds: float = Field(default=60.0, ge=0)

    retry_after_jitter_seconds: float = Field(default=2.0, ge=0)
    """采纳服务端 `Retry-After` 时额外叠加的抖动上限。

    服务端给的是同一个时刻,所有被限流的调用方会**同时**醒来再撞一次
    (惊群)。加一点随机抖动把它们错开。
    """

    full_jitter: bool = True

    def max_retries_for(self, failure: FailureRecord) -> int:
        if not failure.retryable:
            return 0
        if failure.kind is FailureKind.AGENT_TRANSIENT:
            return self.max_agent_retries
        if failure.kind is FailureKind.NETWORK_TRANSIENT:
            return self.max_network_retries
        if failure.kind is FailureKind.RATE_LIMITED:
            return self.max_rate_limit_retries
        if failure.kind is FailureKind.PERSISTENCE_TRANSIENT:
            return self.max_persistence_retries
        return 0

    def delay_seconds(
        self,
        failure: FailureRecord,
        retry_number: int,
        *,
        rng: random.Random,
    ) -> float:
        """Full-jitter 指数退避;服务端给了 `Retry-After` 就优先采纳。

        retry_number 从 1 开始。抖动避免多个 Run 在 Provider 恢复瞬间同时重试。

        **为什么优先用服务端的值:** 对方明确知道还要等多久,
        我们自己算的曲线只是猜测。猜短了白撞一次,猜长了白等。

        **但仍然夹到上限。** 服务端可能回一个 3600 秒 ——
        照单全收会让整个 Run 挂在那里。夹住之后若仍不够,
        那本就该走"放弃这次 attempt"而不是"继续等"。
        """
        if retry_number < 1:
            raise ValueError("retry_number 必须从 1 开始")
        if not failure.retryable:
            return 0.0

        cap = self._cap_for(failure)
        hinted = failure.details.get(RETRY_AFTER_KEY)
        if isinstance(hinted, (int, float)) and not isinstance(hinted, bool) and hinted >= 0:
            return min(float(hinted), cap) + rng.uniform(0.0, self.retry_after_jitter_seconds)

        backoff = min(cap, self._base_for(failure) * (2 ** (retry_number - 1)))
        return rng.uniform(0.0, backoff) if self.full_jitter else backoff

    def _base_for(self, failure: FailureRecord) -> float:
        if failure.kind is FailureKind.RATE_LIMITED:
            return self.rate_limit_base_delay_seconds
        return self.base_delay_seconds

    def _cap_for(self, failure: FailureRecord) -> float:
        if failure.kind is FailureKind.RATE_LIMITED:
            return self.rate_limit_max_delay_seconds
        return self.max_delay_seconds


async def retry_provider_call(
    operation: Callable[[], Awaitable[T]],
    *,
    policy: RetryPolicy,
    sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    rng: random.Random | None = None,
    on_retry: Callable[[FailureRecord, int, float], None] | None = None,
) -> T:
    """给**直接调用 provider** 的路径做有界重试。⭐

    ## 为什么需要它

    正式 run 的重试在 orchestrator 里(按 attempt 重试)。但开跑前的两道对照
    (`controls` / `attacker-control`)**不走 orchestrator**,于是它们此前
    **一次重试都没有** —— 而它们恰恰是最容易撞 429 的地方:
    连续几十次串行调用、跑在免费层上。实测就是这样被一个 429 整个打断的。

    后果比"跑失败了"更糟:命令带着 traceback 崩掉,而操作者很容易把
    **"对照崩了"读成"对照没过"** —— 前者要重跑,后者要停下来查链路,处置完全相反。

    ## 只重试两类,其余立刻抛

    * `RATE_LIMITED` —— 服务端在处理**之前**就拒绝,送达状态确定为 NOT_SENT;
    * `NETWORK_TRANSIENT` —— 超时 / 5xx。

    配置错误(401/404)与协议错误(200 但结构不对)**不重试**:
    退避循环只会把"端点写错了"磨成一条超时,让人查错方向。

    ⚠️ 这里对副作用的判断比 executor 宽松,原因是**场景不同**:对照跑的是
    只读探测,且每条 case 之前都会 `reset()` 靶场 —— 靶场是模拟器,重放安全。
    正式 run 里的攻击可能触发退款一类不可重放的动作,所以那条路径**必须**
    保留 executor 那套更严的"可能已产生副作用"判定,不要拿本函数去替换它。
    """
    rng = rng or random.Random(0)
    retry_number = 0
    while True:
        try:
            return await operation()
        except ProviderRateLimitedError as exc:
            # 当日配额耗尽:等到明天之前重试多少次都没用,而服务端给的
            # Retry-After 还会误导人(实测 Gemini 此时仍回 2s)。
            # 白烧完整套重试预算之后抛出的还是"限流",真正的原因一个字没提。
            if exc.daily_quota_exhausted:
                raise
            details: dict[str, str | int | float | bool | None] = {}
            if exc.retry_after_seconds is not None:
                details[RETRY_AFTER_KEY] = exc.retry_after_seconds
            failure = _preflight_failure(exc, FailureKind.RATE_LIMITED, details)
            pending = exc
        except (ProviderTransientError, TimeoutError, ConnectionError) as exc:
            failure = _preflight_failure(exc, FailureKind.NETWORK_TRANSIENT, {})
            pending = exc

        if retry_number >= policy.max_retries_for(failure):
            # ⚠️ 必须显式 re-raise 这个对象:裸 `raise` 在 except 块**之外**没有
            # 活跃异常,会变成 "No active exception to reraise",把真正的限流原因
            # 换成一条毫无信息量的 RuntimeError。抛同一个对象可保留原始 traceback。
            raise pending
        retry_number += 1
        delay = policy.delay_seconds(failure, retry_number, rng=rng)
        if on_retry is not None:
            on_retry(failure, retry_number, delay)
        await sleep(delay)


def _preflight_failure(
    exc: Exception,
    kind: FailureKind,
    details: dict[str, str | int | float | bool | None],
) -> FailureRecord:
    return FailureRecord(
        kind=kind,
        stage=FailureStage.PREFLIGHT,
        code=kind.value,
        message=str(exc),
        cause_type=type(exc).__name__,
        retry_safety=RetrySafety.SAFE,
        delivery_status=DeliveryStatus.NOT_SENT,
        side_effect_status=SideEffectStatus.NONE,
        details=details,
    )


# `ReliabilityPolicy` 已下沉到 redcell.reliability —— 见该模块开头的说明。
# 这里保留 re-export,既有的 `from redcell.retry import ReliabilityPolicy` 无需改动。
# ⚠️ 不要改回在本文件里定义:`protocols/run.py` 需要它,而 retry 依赖 protocols,
# 定义在这里会制造循环导入。
__all__ = [
    "RETRY_AFTER_KEY",
    "ReliabilityPolicy",
    "RetryPolicy",
    "retry_provider_call",
]
