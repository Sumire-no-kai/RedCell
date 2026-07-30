"""按故障类型配置的有界重试与 Run 可靠性阈值。"""

from __future__ import annotations

import random

from pydantic import Field

from redcell.failures import FailureKind, FailureRecord
from redcell.protocols.common import RedCellModel


class RetryPolicy(RedCellModel):
    """工程默认值集中在一个配置对象中,不散落在 catch 分支。"""

    max_agent_retries: int = Field(default=2, ge=0, le=10)
    max_network_retries: int = Field(default=4, ge=0, le=20)
    max_persistence_retries: int = Field(default=4, ge=0, le=20)
    base_delay_seconds: float = Field(default=0.5, ge=0)
    max_delay_seconds: float = Field(default=8.0, ge=0)
    full_jitter: bool = True

    def max_retries_for(self, failure: FailureRecord) -> int:
        if not failure.retryable:
            return 0
        if failure.kind is FailureKind.AGENT_TRANSIENT:
            return self.max_agent_retries
        if failure.kind is FailureKind.NETWORK_TRANSIENT:
            return self.max_network_retries
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
        """Full-jitter exponential backoff。

        retry_number 从 1 开始。抖动避免多个 Run 在 Provider 恢复瞬间同时重试。
        """
        if retry_number < 1:
            raise ValueError("retry_number 必须从 1 开始")
        if not failure.retryable:
            return 0.0
        cap = min(
            self.max_delay_seconds,
            self.base_delay_seconds * (2 ** (retry_number - 1)),
        )
        return rng.uniform(0.0, cap) if self.full_jitter else cap


class ReliabilityPolicy(RedCellModel):
    """少量偶发故障可继续;超过阈值则 Run 不再具有实验可信度。"""

    max_consecutive_abandoned: int = Field(default=3, ge=1)
    max_abandoned_fraction: float = Field(default=0.10, ge=0.0, le=1.0)
    fraction_min_attempts: int = Field(default=10, ge=1)

    def invalidates_run(
        self,
        *,
        logical_attempts: int,
        abandoned_attempts: int,
        consecutive_abandoned: int,
    ) -> bool:
        if consecutive_abandoned >= self.max_consecutive_abandoned:
            return True
        if logical_attempts < self.fraction_min_attempts:
            return False
        return abandoned_attempts / logical_attempts > self.max_abandoned_fraction

    def invalidates_completed_run(
        self,
        *,
        logical_attempts: int,
        completed_attempts: int,
        abandoned_attempts: int,
    ) -> bool:
        """预算结束时没有“再观察几次”的机会,直接按最终有效比例判定。"""
        if logical_attempts == 0 or completed_attempts == 0:
            return True
        return abandoned_attempts / logical_attempts > self.max_abandoned_fraction
