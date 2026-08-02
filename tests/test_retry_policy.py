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
    """限流单独一档,且比其它两类都宽。

    2026-08-03 由 5 提到 8:实测 target 的过载是**突发窗口**式的,
    而等待免费、判废一轮校准很贵 —— 代价极不对称。
    """
    policy = RetryPolicy()

    assert policy.max_retries_for(_failure(FailureKind.RATE_LIMITED)) == 8
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


# ── 当日配额耗尽 ≠ 瞬时节流(2026-08-02 实测) ───────────────────────────


def test_daily_quota_exhaustion_is_detected_from_the_body() -> None:
    """Gemini 免费层在 quotaId 里明写 PerDay —— 那是按天计的,重试无用。"""
    import httpx

    from redcell.llm.openai_compatible import _is_daily_quota_exhausted

    daily = httpx.Response(
        429,
        json=[
            {
                "error": {
                    "code": 429,
                    "details": [
                        {
                            "violations": [
                                {"quotaId": "GenerateRequestsPerDayPerProjectPerModel-FreeTier"}
                            ]
                        }
                    ],
                }
            }
        ],
    )
    throttle = httpx.Response(429, json={"error": {"message": "too many requests per minute"}})

    assert _is_daily_quota_exhausted(daily)
    # 认不出来就按可重试处理 —— 把普通节流误判成"今天没了"会让跑批白白停掉。
    assert not _is_daily_quota_exhausted(throttle)


async def test_exhausted_daily_quota_is_not_retried() -> None:
    """重试到明天之前都不会好,烧光重试预算只会掩盖真实原因。"""
    from redcell.llm.openai_compatible import ProviderRateLimitedError
    from redcell.retry import retry_provider_call

    calls = {"n": 0}

    async def _op():
        calls["n"] += 1
        # ⚠️ 服务端此时仍会给一个很短的 Retry-After —— 照它退避正是那个坑。
        raise ProviderRateLimitedError("quota", retry_after_seconds=2, daily_quota_exhausted=True)

    with pytest.raises(ProviderRateLimitedError):
        await retry_provider_call(_op, policy=RetryPolicy(retry_after_jitter_seconds=0))

    assert calls["n"] == 1


def test_rate_limit_retry_budget_is_stated_in_full_jitter_terms() -> None:
    """能扛多久要按 full jitter 算 —— 每次等待是 uniform(0, backoff),不是 backoff。

    按 cap 直觉估会高估一倍以上,而这个数决定了一个过载窗口会不会判废整轮校准。
    """
    policy = RetryPolicy()
    assert policy.max_rate_limit_retries == 8

    failure = _failure(FailureKind.RATE_LIMITED)
    worst = sum(
        min(
            policy.rate_limit_max_delay_seconds,
            policy.rate_limit_base_delay_seconds * (2 ** (n - 1)),
        )
        for n in range(1, policy.max_rate_limit_retries + 1)
    )
    assert worst == pytest.approx(315.0)  # 5.25 分钟

    # 实际抽样必须落在 [0, backoff] 内 —— 这正是"最坏"与"期望"差一倍的原因。
    rng = random.Random(0)
    for n in range(1, policy.max_rate_limit_retries + 1):
        delay = policy.delay_seconds(failure, n, rng=rng)
        cap = min(
            policy.rate_limit_max_delay_seconds,
            policy.rate_limit_base_delay_seconds * (2 ** (n - 1)),
        )
        assert 0.0 <= delay <= cap
