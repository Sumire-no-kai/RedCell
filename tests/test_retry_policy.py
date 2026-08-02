"""重试策略的测试 —— 重点是限流(429)与网络故障必须**分开对待**。

这不只是参数调优:429 与超时的**送达状态**根本不同,
把它们混成一类会让本可安全重试的限流被当成"可能已产生副作用"而放弃。
"""

from __future__ import annotations

import random

import pytest

from redcell.failures import (
    DeliveryStatus,
    FailureKind,
    FailureRecord,
    FailureStage,
    RetrySafety,
    SideEffectStatus,
)
from redcell.retry import RETRY_AFTER_KEY, ReliabilityPolicy, RetryPolicy


def _failure(
    kind: FailureKind,
    *,
    retry_after: float | None = None,
    safety: RetrySafety = RetrySafety.SAFE,
) -> FailureRecord:
    details: dict[str, str | int | float | bool | None] = {}
    if retry_after is not None:
        details[RETRY_AFTER_KEY] = retry_after
    return FailureRecord(
        kind=kind,
        stage=FailureStage.TARGET_SEND,
        code="X",
        message="m",
        cause_type="t",
        retry_safety=safety,
        delivery_status=DeliveryStatus.NOT_SENT,
        side_effect_status=SideEffectStatus.NONE,
        details=details,
    )


def _rng() -> random.Random:
    return random.Random(0)


# ── 次数 ────────────────────────────────────────────────────


def test_rate_limited_gets_its_own_retry_budget() -> None:
    """作者定的上限:限流最多重试 5 次。"""
    policy = RetryPolicy()

    assert policy.max_retries_for(_failure(FailureKind.RATE_LIMITED)) == 5
    assert policy.max_retries_for(_failure(FailureKind.NETWORK_TRANSIENT)) == 4
    assert policy.max_retries_for(_failure(FailureKind.AGENT_TRANSIENT)) == 2


def test_rate_limited_is_transient_and_therefore_retryable() -> None:
    assert FailureKind.RATE_LIMITED.transient is True
    assert _failure(FailureKind.RATE_LIMITED).retryable is True


def test_non_retryable_gets_no_budget() -> None:
    unsafe = _failure(FailureKind.RATE_LIMITED, safety=RetrySafety.UNSAFE)

    assert unsafe.retryable is False
    assert RetryPolicy().max_retries_for(unsafe) == 0


# ── 退避曲线 ────────────────────────────────────────────────


def test_rate_limit_backoff_is_far_longer_than_network_backoff() -> None:
    """默认网络参数(base 0.5 / cap 8)是按付费 API 的瞬时抖动调的。

    2026-08-01 实测免费层限流需累计等约 116 秒才恢复 ——
    用网络那套参数,4 次重试累计只等约 3.75 秒,会直接判死一次 attempt。
    """
    policy = RetryPolicy(full_jitter=False)
    rng = _rng()

    rate = policy.delay_seconds(_failure(FailureKind.RATE_LIMITED), 3, rng=rng)
    net = policy.delay_seconds(_failure(FailureKind.NETWORK_TRANSIENT), 3, rng=rng)

    assert rate == pytest.approx(20.0)  # 5 × 2²
    assert net == pytest.approx(2.0)  # 0.5 × 2²
    assert rate > net * 5


def test_rate_limit_backoff_is_capped() -> None:
    policy = RetryPolicy(full_jitter=False)

    delay = policy.delay_seconds(_failure(FailureKind.RATE_LIMITED), 10, rng=_rng())

    assert delay == pytest.approx(policy.rate_limit_max_delay_seconds)


def test_retry_number_must_start_at_one() -> None:
    with pytest.raises(ValueError):
        RetryPolicy().delay_seconds(_failure(FailureKind.RATE_LIMITED), 0, rng=_rng())


# ── Retry-After ─────────────────────────────────────────────


def test_server_retry_after_wins_over_our_own_curve() -> None:
    """对方明确知道还要等多久,我们自己算的曲线只是猜测。"""
    policy = RetryPolicy(retry_after_jitter_seconds=0)

    delay = policy.delay_seconds(
        _failure(FailureKind.RATE_LIMITED, retry_after=30.0), 1, rng=_rng()
    )

    # 第 1 次的自算退避只有 5 秒,服务端说 30 就等 30。
    assert delay == pytest.approx(30.0)


def test_retry_after_is_still_capped() -> None:
    """服务端可能回一个 3600 —— 照单全收会让整个 Run 挂在那里。

    夹住之后若仍不够,那本就该走"放弃这次 attempt",而不是"继续等"。
    """
    policy = RetryPolicy(retry_after_jitter_seconds=0)

    delay = policy.delay_seconds(
        _failure(FailureKind.RATE_LIMITED, retry_after=3600.0), 1, rng=_rng()
    )

    assert delay == pytest.approx(policy.rate_limit_max_delay_seconds)


def test_retry_after_carries_jitter_to_avoid_a_thundering_herd() -> None:
    """服务端给的是同一个时刻,所有被限流的调用方会同时醒来再撞一次。"""
    policy = RetryPolicy(retry_after_jitter_seconds=2.0)
    failure = _failure(FailureKind.RATE_LIMITED, retry_after=10.0)

    delays = {policy.delay_seconds(failure, 1, rng=random.Random(s)) for s in range(20)}

    assert len(delays) > 1  # 不是所有人都等同一个时长
    assert all(10.0 <= d <= 12.0 for d in delays)


def test_a_zero_retry_after_is_honoured_not_ignored() -> None:
    """`Retry-After: 0` 是"立刻可以再试",不能被当成"没给值"而回退到自算曲线。"""
    policy = RetryPolicy(retry_after_jitter_seconds=0)

    delay = policy.delay_seconds(_failure(FailureKind.RATE_LIMITED, retry_after=0.0), 4, rng=_rng())

    assert delay == pytest.approx(0.0)


def test_bool_is_not_mistaken_for_a_retry_after_value() -> None:
    """Python 里 `True == 1`,若不排除 bool,一个误写的 True 会变成"等 1 秒"。"""
    failure = _failure(FailureKind.RATE_LIMITED)
    failure.details[RETRY_AFTER_KEY] = True
    policy = RetryPolicy(full_jitter=False, retry_after_jitter_seconds=0)

    delay = policy.delay_seconds(failure, 2, rng=_rng())

    assert delay == pytest.approx(10.0)  # 走自算曲线 5 × 2¹,不是 1 秒


def test_network_failures_also_honour_retry_after() -> None:
    """5xx 也可能带 Retry-After,没理由只对 429 生效。"""
    policy = RetryPolicy(retry_after_jitter_seconds=0)

    delay = policy.delay_seconds(
        _failure(FailureKind.NETWORK_TRANSIENT, retry_after=3.0), 1, rng=_rng()
    )

    assert delay == pytest.approx(3.0)


# ── Run 失效阈值(2026-08-01 复核) ──────────────────────────────────────


def test_consecutive_threshold_tolerates_a_free_tier_rate_limit_window() -> None:
    """3 → 5 的理由是代价不对称。

    重试已经在一场 attempt 内部吸收了约 116 秒的退避,所以连续 3 次放弃
    意味着已持续失败 6 分钟以上 —— 而免费层的配额窗口经常就是这个量级。
    为一次可恢复的抖动作废整轮 2.3 小时的校准,比多等几场糟糕得多。
    """
    policy = ReliabilityPolicy()
    assert policy.max_consecutive_abandoned == 5

    assert not policy.invalidates_run(
        logical_attempts=100, abandoned_attempts=4, consecutive_abandoned=4
    )
    # 真正的宕机不会在第 5 场自己好转,仍然抓得住。
    assert policy.invalidates_run(
        logical_attempts=100, abandoned_attempts=5, consecutive_abandoned=5
    )


def test_reliability_policy_is_importable_from_both_places() -> None:
    """它已下沉到 redcell.reliability,retry 保留 re-export。

    ⚠️ 搬回 retry.py 会重新制造 protocols ↔ retry 的循环导入
    (2026-08-01 Step 11 修过一次同形状的 bug)。
    """
    from redcell.reliability import ReliabilityPolicy as Sunk
    from redcell.retry import ReliabilityPolicy as ReExported

    assert Sunk is ReExported
