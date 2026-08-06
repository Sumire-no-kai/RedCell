from redcell.executor import _classify_failure
from redcell.failures import (
    DeliveryStatus,
    FailureKind,
    FailureStage,
    RetrySafety,
    SideEffectStatus,
    safe_error_message,
)
from redcell.llm import (
    ProviderConfigurationError,
    ProviderProtocolError,
    ProviderRateLimitedError,
    ProviderTransientError,
)
from redcell.protocols.adapter import AdapterCapabilities, IdempotencySupport, ResetScope
from redcell.protocols.trace import CostRecord

# 既不支持幂等键、也不能整状态复位的目标 ——
# 网络超时在这种目标上会升级为"副作用不明",禁止重试。
_NO_IDEMPOTENCY = AdapterCapabilities(
    idempotency=IdempotencySupport.NONE,
    reset_scope=ResetScope.NONE,
)


def _classify(exc: Exception):
    return _classify_failure(
        exc,
        stage=FailureStage.TARGET_SEND,
        capabilities=_NO_IDEMPOTENCY,
        partial_cost=CostRecord(),
    )


# ── provider 异常 → FailureRecord ───────────────────────────


def test_rate_limit_is_classified_as_safely_retryable() -> None:
    """429 与超时的**送达状态不同**,这是分开两类的核心理由。

    服务端在处理之前就拒绝了 → 请求确定没生效 → 重试无条件安全。
    """
    failure = _classify(ProviderRateLimitedError("429", retry_after_seconds=30.0))

    assert failure.kind is FailureKind.RATE_LIMITED
    assert failure.delivery_status is DeliveryStatus.NOT_SENT
    assert failure.side_effect_status is SideEffectStatus.NONE
    assert failure.retry_safety is RetrySafety.SAFE
    assert failure.retryable is True
    assert failure.details["retry_after_seconds"] == 30.0


def test_a_timeout_on_the_same_target_is_not_safely_retryable() -> None:
    """同一个目标、同一个阶段,超时却必须走"副作用不明"。

    对照上一个测试:这正是把 429 混进 NETWORK_TRANSIENT 会造成的误伤 ——
    一个本可安全重试的限流会被当成"可能已经改了对方的状态"而放弃。
    """
    failure = _classify(TimeoutError("timed out"))

    assert failure.kind is FailureKind.AMBIGUOUS_SIDE_EFFECT
    assert failure.retryable is False


def test_rate_limit_without_a_header_carries_no_hint() -> None:
    """没有 Retry-After 时不能编一个,上层会退回自己的退避曲线。"""
    failure = _classify(ProviderRateLimitedError("429"))

    assert "retry_after_seconds" not in failure.details


def test_provider_config_error_is_not_retryable() -> None:
    """key 错、模型名错 —— 退避多少次都是同样结果。"""
    failure = _classify(ProviderConfigurationError("bad key"))

    assert failure.kind is FailureKind.CONFIGURATION
    assert failure.retryable is False
    assert failure.delivery_status is DeliveryStatus.NOT_SENT


def test_provider_protocol_error_records_the_request_as_sent() -> None:
    """HTTP 200 但结构不对:请求确实送达并被处理了,只是我们读不懂回复。"""
    failure = _classify(ProviderProtocolError("weird body"))

    assert failure.kind is FailureKind.PROTOCOL
    assert failure.delivery_status is DeliveryStatus.SENT
    assert failure.retryable is False


def test_generic_provider_transient_falls_back_to_network_semantics() -> None:
    failure = _classify(ProviderTransientError("503"))

    assert failure.kind in {FailureKind.NETWORK_TRANSIENT, FailureKind.AMBIGUOUS_SIDE_EFFECT}


def test_persisted_error_message_redacts_common_credentials() -> None:
    error = RuntimeError(
        "Authorization: Bearer secret-token api_key=super-secret "
        "provider=sk-proj-abcdefghijklmnopqrstuvwxyz"
    )

    message = safe_error_message(error)

    assert "secret-token" not in message
    assert "super-secret" not in message
    assert "sk-proj-" not in message
    assert message.count("[REDACTED]") == 3
