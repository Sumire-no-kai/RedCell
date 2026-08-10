"""OpenAICompatibleProvider 的测试 —— 全程走 MockTransport,不联网、不花钱、不要 key。

这正是 `LLMProvider` 这层抽象存在的理由之一:真实 provider 的分支逻辑
(限流、认证失败、协议漂移)必须能在 CI 里确定性地测到,
否则只有等到跑校准时才发现,而那时已经在花钱了。
"""

from __future__ import annotations

import httpx
import pytest

from redcell.llm import (
    LLMMessage,
    OpenAICompatibleProvider,
    ProviderConfigurationError,
    ProviderProtocolError,
    ProviderRateLimitedError,
    ProviderTransientError,
    TokenPricing,
)
from redcell.protocols import Role

_OK_BODY = {
    "model": "glm-4.7-flash",
    "choices": [
        {"message": {"role": "assistant", "content": "你好,需要查订单吗?"}, "finish_reason": "stop"}
    ],
    "usage": {"prompt_tokens": 1200, "completion_tokens": 300},
}


def _provider(
    handler: httpx.MockTransport | None = None,
    *,
    pricing: TokenPricing | None = None,
    **kwargs: object,
) -> OpenAICompatibleProvider:
    transport = handler or httpx.MockTransport(lambda _: httpx.Response(200, json=_OK_BODY))
    return OpenAICompatibleProvider(
        base_url="https://example.invalid/v4",
        model="glm-4.7-flash",
        api_key="test-key",
        name="glm",
        pricing=pricing,
        client=httpx.AsyncClient(transport=transport),
        **kwargs,  # type: ignore[arg-type]
    )


def _user(text: str) -> list[LLMMessage]:
    return [LLMMessage(role=Role.USER, content=text)]


# ── 正常路径 ────────────────────────────────────────────────


async def test_parses_content_tokens_and_latency() -> None:
    response = await _provider().complete(_user("你好"))

    assert response.content == "你好,需要查订单吗?"
    assert response.prompt_tokens == 1200
    assert response.completion_tokens == 300
    assert response.total_tokens == 1500
    assert response.latency_ms > 0


async def test_request_body_carries_model_messages_and_temperature() -> None:
    seen: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        import json

        seen.update(json.loads(request.content))
        seen["url"] = str(request.url)
        seen["auth"] = request.headers.get("authorization")
        return httpx.Response(200, json=_OK_BODY)

    await _provider(httpx.MockTransport(handler)).complete(
        _user("查一下订单"), temperature=0.7, max_tokens=512
    )

    assert seen["url"] == "https://example.invalid/v4/chat/completions"
    assert seen["auth"] == "Bearer test-key"
    assert seen["model"] == "glm-4.7-flash"
    assert seen["temperature"] == 0.7
    assert seen["max_tokens"] == 512
    assert seen["messages"] == [{"role": "user", "content": "查一下订单"}]


async def test_max_tokens_is_omitted_when_not_set() -> None:
    """不设上限时不该发一个 max_tokens 字段过去——

    有的兼容端点会把显式的 null 当成 0 处理,那会得到空回复而不报错。
    """
    seen: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        import json

        seen.update(json.loads(request.content))
        return httpx.Response(200, json=_OK_BODY)

    await _provider(httpx.MockTransport(handler)).complete(_user("你好"))

    assert "max_tokens" not in seen


async def test_extra_body_is_merged_into_every_request() -> None:
    """2026-08-06 加入:厂商专属字段(如 GLM 的 `thinking: disabled`)原样透传。

    这是让"关闭 thinking"这个隐藏旋钮能被显式配置、写进 .env 的机制——
    不是 GLM 专属代码,provider 层不理解也不校验字段含义,只负责原样带过去。
    """
    seen: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        import json

        seen.update(json.loads(request.content))
        return httpx.Response(200, json=_OK_BODY)

    await _provider(
        httpx.MockTransport(handler), extra_body={"thinking": {"type": "disabled"}}
    ).complete(_user("你好"))

    assert seen["thinking"] == {"type": "disabled"}
    assert seen["model"] == "glm-4.7-flash"  # 标准字段不受影响


async def test_extra_body_defaults_to_empty_and_stays_out_of_the_payload() -> None:
    seen: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        import json

        seen.update(json.loads(request.content))
        return httpx.Response(200, json=_OK_BODY)

    await _provider(httpx.MockTransport(handler)).complete(_user("你好"))

    assert "thinking" not in seen


async def test_uses_server_reported_model_as_drift_evidence() -> None:
    """服务端回传的 model 串与请求串不一致时,必须留下前者——那是模型漂移的唯一证据。"""
    body = {**_OK_BODY, "model": "glm-4.7-flash-0301"}
    provider = _provider(httpx.MockTransport(lambda _: httpx.Response(200, json=body)))

    assert (await provider.complete(_user("你好"))).model == "glm-4.7-flash-0301"


# ── 成本可观测性(约定 #4)────────────────────────────────────


async def test_without_pricing_cost_is_not_reported() -> None:
    """没配单价 = 成本不可观测。绝不能假装知道。"""
    provider = _provider(pricing=None)

    assert provider.reports_cost is False
    assert (await provider.complete(_user("你好"))).cost_usd == 0.0


async def test_with_pricing_cost_is_computed_from_tokens() -> None:
    provider = _provider(
        pricing=TokenPricing(
            input_usd_per_mtok=0.14,
            output_usd_per_mtok=0.28,
            cached_input_usd_per_mtok=0.0,
        )
    )
    response = await provider.complete(_user("你好"))

    assert provider.reports_cost is True
    # 1200 × 0.14/1M + 300 × 0.28/1M
    assert response.cost_usd == pytest.approx(0.000168 + 0.000084)


async def test_free_model_declares_zero_price_explicitly() -> None:
    """免费模型的 0 和"忘了填"的 0 必须能分开。

    前者 reports_cost=True(我确认它免费,预算上限因此是可信的),
    后者 reports_cost=False(我不知道,别拿这个数当安全网)。
    """
    provider = _provider(
        pricing=TokenPricing(
            input_usd_per_mtok=0,
            output_usd_per_mtok=0,
            cached_input_usd_per_mtok=0,
        )
    )
    response = await provider.complete(_user("你好"))

    assert provider.reports_cost is True
    assert response.cost_usd == 0.0


async def test_pricing_is_recorded_for_audit() -> None:
    """厂商调价后,只有这条留档能说明当时算的是哪一档价。"""
    provider = _provider(
        pricing=TokenPricing(
            input_usd_per_mtok=0.14,
            output_usd_per_mtok=0.28,
            cached_input_usd_per_mtok=0.0,
        )
    )
    raw = (await provider.complete(_user("你好"))).raw

    assert raw["pricing"] == {
        "input_usd_per_mtok": 0.14,
        "output_usd_per_mtok": 0.28,
        "cached_input_usd_per_mtok": 0.0,
    }


# ── 失败分类 ────────────────────────────────────────────────


@pytest.mark.parametrize("status", [401, 403])
async def test_auth_failures_are_configuration_errors(status: int) -> None:
    provider = _provider(httpx.MockTransport(lambda _: httpx.Response(status, text="bad key")))

    with pytest.raises(ProviderConfigurationError):
        await provider.complete(_user("你好"))


async def test_unknown_model_is_a_configuration_error() -> None:
    """404 大概率是 base_url 或 model 串写错了,退避重试只会浪费时间。"""
    provider = _provider(httpx.MockTransport(lambda _: httpx.Response(404, text="no such model")))

    with pytest.raises(ProviderConfigurationError):
        await provider.complete(_user("你好"))


async def test_rate_limit_raises_the_dedicated_subclass() -> None:
    """429 必须能和 5xx 区分开。

    不是为了参数好看:429 是服务端**在处理之前**就拒绝了,送达状态确定为未送达,
    重试无条件安全;而 5xx / 超时无法确定请求是否已被处理。
    混成一类会让本可安全重试的限流被当作"可能已产生副作用"而放弃。
    """
    provider = _provider(
        httpx.MockTransport(
            lambda _: httpx.Response(429, text="rate limited", headers={"retry-after": "30"})
        )
    )

    with pytest.raises(ProviderRateLimitedError) as exc:
        await provider.complete(_user("你好"))
    assert exc.value.retry_after_seconds == 30.0


async def test_server_error_is_not_a_rate_limit() -> None:
    """5xx 走父类,不能被误判成限流——否则会用上分钟级的退避去等一个几秒的抖动。"""
    provider = _provider(httpx.MockTransport(lambda _: httpx.Response(503, text="overloaded")))

    with pytest.raises(ProviderTransientError) as exc:
        await provider.complete(_user("你好"))
    assert not isinstance(exc.value, ProviderRateLimitedError)


async def test_failures_are_logged_without_leaking_the_key() -> None:
    """失败要进运行时日志,但日志里绝不能出现凭据。

    有的 provider 会在错误信息里回显请求头 —— 所以只记结构化字段,
    不记请求体或响应全文。
    """
    import structlog

    cap = structlog.testing.LogCapture()
    structlog.configure(processors=[cap])
    try:
        provider = _provider(httpx.MockTransport(lambda _: httpx.Response(429, text="slow down")))
        with pytest.raises(ProviderRateLimitedError):
            await provider.complete(_user("你好"))
    finally:
        structlog.reset_defaults()

    assert len(cap.entries) == 1
    entry = cap.entries[0]
    assert entry["event"] == "provider_request_failed"
    assert entry["provider"] == "glm"
    assert entry["status"] == 429
    assert entry["kind"] == "rate_limited"
    assert "test-key" not in repr(entry)


async def test_server_error_is_transient() -> None:
    provider = _provider(httpx.MockTransport(lambda _: httpx.Response(503, text="overloaded")))

    with pytest.raises(ProviderTransientError):
        await provider.complete(_user("你好"))


async def test_timeout_is_transient() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("timed out", request=request)

    with pytest.raises(ProviderTransientError):
        await _provider(httpx.MockTransport(handler)).complete(_user("你好"))


async def test_malformed_json_is_a_protocol_error() -> None:
    """HTTP 200 但不是 JSON —— 通常意味着端点变了,重试无济于事,需要人看一眼。"""
    provider = _provider(
        httpx.MockTransport(lambda _: httpx.Response(200, text="<html>502</html>"))
    )

    with pytest.raises(ProviderProtocolError):
        await provider.complete(_user("你好"))


async def test_missing_choices_is_a_protocol_error() -> None:
    provider = _provider(httpx.MockTransport(lambda _: httpx.Response(200, json={"usage": {}})))

    with pytest.raises(ProviderProtocolError):
        await provider.complete(_user("你好"))


async def test_null_content_becomes_empty_string_not_an_error() -> None:
    """空回复是合法结果(例如被对方安全策略拦下),不是协议错误。

    但也不能让 None 往下传——那会在解析工具调用时炸在离现场很远的地方。
    """
    body = {
        "model": "glm-4.7-flash",
        "choices": [{"message": {"role": "assistant", "content": None}, "finish_reason": "stop"}],
        "usage": {"prompt_tokens": 10, "completion_tokens": 0},
    }
    provider = _provider(httpx.MockTransport(lambda _: httpx.Response(200, json=body)))

    assert (await provider.complete(_user("你好"))).content == ""


async def test_missing_usage_does_not_crash() -> None:
    """有的兼容端点在流式或异常情况下不回 usage。token 数记 0,但不能让整次调用失败。"""
    body = {"model": "m", "choices": [{"message": {"content": "ok"}}]}
    provider = _provider(httpx.MockTransport(lambda _: httpx.Response(200, json=body)))
    response = await provider.complete(_user("你好"))

    assert response.content == "ok"
    assert response.total_tokens == 0
    assert not response.usage_known


# ── 不自己重试(避免与 retry.py 叠加)──────────────────────────


async def test_provider_does_not_retry_internally() -> None:
    """provider 内部重试会和 retry.py 的退避叠加成两层,而日志里只看得见一层。

    重试次数上限本身还是未定项(A3),更不该在这里偷偷定一个。
    """
    attempts = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal attempts
        attempts += 1
        return httpx.Response(500, text="boom")

    with pytest.raises(ProviderTransientError):
        await _provider(httpx.MockTransport(handler)).complete(_user("你好"))

    assert attempts == 1


# ── 免费层限速 ──────────────────────────────────────────────


async def test_throttle_spaces_out_requests() -> None:
    """Gemini 免费层是 10 RPM,不自律就会被 429 打穿。

    断言留了容差:Windows 计时器精度约 15ms,`asyncio.sleep` 可能早醒一点点。
    卡在间隔值本身上会做出一个偶发失败的测试——而偶发失败的测试最终会被无视,
    那时它就再也保护不了任何东西。这里只要证明"确实等了"即可。
    """
    import time

    interval = 0.2
    provider = _provider(min_interval_seconds=interval)
    started = time.monotonic()
    await provider.complete(_user("一"))
    await provider.complete(_user("二"))
    elapsed = time.monotonic() - started

    assert elapsed >= interval * 0.75


async def test_no_throttle_by_default() -> None:
    """不设间隔时不该有任何等待——默认值不能偷偷替使用者做限流决定。"""
    import time

    provider = _provider()
    started = time.monotonic()
    await provider.complete(_user("一"))
    await provider.complete(_user("二"))

    assert time.monotonic() - started < 0.05


# ── 并发上限 ────────────────────────────────────────────────
# GLM-4.7-Flash 的官方并发上限是 1 —— 按 RPM 节流挡不住并发超限,
# 这是两个不同的限流维度,必须分别处理。


async def test_max_concurrency_serialises_in_flight_requests() -> None:
    import asyncio

    in_flight = 0
    peak = 0

    async def handler(request: httpx.Request) -> httpx.Response:
        nonlocal in_flight, peak
        in_flight += 1
        peak = max(peak, in_flight)
        await asyncio.sleep(0.02)
        in_flight -= 1
        return httpx.Response(200, json=_OK_BODY)

    provider = _provider(httpx.MockTransport(handler), max_concurrency=1)
    await asyncio.gather(*(provider.complete(_user(str(i))) for i in range(5)))

    assert peak == 1


async def test_concurrency_above_one_allows_overlap() -> None:
    """上限不是"永远串行"——设成 3 就该真的能同时跑 3 个,否则跑批会白白慢下来。"""
    import asyncio

    in_flight = 0
    peak = 0

    async def handler(request: httpx.Request) -> httpx.Response:
        nonlocal in_flight, peak
        in_flight += 1
        peak = max(peak, in_flight)
        await asyncio.sleep(0.02)
        in_flight -= 1
        return httpx.Response(200, json=_OK_BODY)

    provider = _provider(httpx.MockTransport(handler), max_concurrency=3)
    await asyncio.gather(*(provider.complete(_user(str(i))) for i in range(6)))

    assert peak == 3


async def test_unlimited_concurrency_by_default() -> None:
    import asyncio

    in_flight = 0
    peak = 0

    async def handler(request: httpx.Request) -> httpx.Response:
        nonlocal in_flight, peak
        in_flight += 1
        peak = max(peak, in_flight)
        await asyncio.sleep(0.02)
        in_flight -= 1
        return httpx.Response(200, json=_OK_BODY)

    provider = _provider(httpx.MockTransport(handler))
    await asyncio.gather(*(provider.complete(_user(str(i))) for i in range(4)))

    assert peak == 4
