"""按故障类型配置的有界重试与 Run 可靠性阈值。"""

from __future__ import annotations

import random

from pydantic import Field

from redcell.failures import FailureKind, FailureRecord
from redcell.protocols.common import RedCellModel
from redcell.reliability import ReliabilityPolicy

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


# `ReliabilityPolicy` 已下沉到 redcell.reliability —— 见该模块开头的说明。
# 这里保留 re-export,既有的 `from redcell.retry import ReliabilityPolicy` 无需改动。
# ⚠️ 不要改回在本文件里定义:`protocols/run.py` 需要它,而 retry 依赖 protocols,
# 定义在这里会制造循环导入。
__all__ = ["RETRY_AFTER_KEY", "ReliabilityPolicy", "RetryPolicy"]
