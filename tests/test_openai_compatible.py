"""OpenAICompatibleProvider 的测试 —— 全程走 MockTransport,不联网、不花钱、不要 key。

这正是 `LLMProvider` 这层抽象存在的理由之一:真实 provider 的分支逻辑
(限流、认证失败、协议漂移)必须能在 CI 里确定性地测到,
否则只有等到跑校准时才发现,而那时已经在花钱了。
"""

from __future__ import annotations

import sqlite3
import time

import httpx
import pytest

from redcell.llm import (
    LLMMessage,
    LLMToolCall,
    LLMToolDefinition,
    OpenAICompatibleProvider,
    ProviderConfigurationError,
    ProviderProtocolError,
    ProviderRateLimitedError,
    ProviderTransientError,
    TokenPricing,
)
from redcell.protocols import Role
from redcell.protocols.run import UsageAccountingMode
from redcell.shared_rate_limit import SQLiteRateLimiter

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


async def test_total_minus_prompt_accounts_hidden_thinking_tokens() -> None:
    body = {
        **_OK_BODY,
        "usage": {"prompt_tokens": 15, "completion_tokens": 18, "total_tokens": 175},
    }
    provider = _provider(
        httpx.MockTransport(lambda _: httpx.Response(200, json=body)),
        pricing=TokenPricing(
            input_usd_per_mtok=0.25,
            output_usd_per_mtok=1.5,
            cached_input_usd_per_mtok=0.025,
        ),
        usage_accounting_mode=UsageAccountingMode.TOTAL_MINUS_PROMPT_V1,
    )

    response = await provider.complete(_user("你好"))

    assert response.prompt_tokens == 15
    assert response.completion_tokens == 160
    assert response.total_tokens == 175
    assert response.cost_usd == pytest.approx((15 * 0.25 + 160 * 1.5) / 1_000_000)
    assert response.raw["usage_accounting"] == {
        "mode": "total-minus-prompt-v1",
        "provider_prompt_tokens": 15,
        "provider_completion_tokens": 18,
        "provider_total_tokens": 175,
        "hidden_output_tokens": 142,
        "accounted_output_tokens": 160,
    }


async def test_prompt_completion_mode_preserves_legacy_semantics_when_total_is_larger() -> None:
    body = {
        **_OK_BODY,
        "usage": {"prompt_tokens": 15, "completion_tokens": 18, "total_tokens": 175},
    }
    provider = _provider(httpx.MockTransport(lambda _: httpx.Response(200, json=body)))

    response = await provider.complete(_user("你好"))

    assert response.total_tokens == 33
    assert response.raw["usage_accounting"]["hidden_output_tokens"] == 0


@pytest.mark.parametrize(
    "usage",
    [
        {"prompt_tokens": 15, "completion_tokens": 18},
        {"prompt_tokens": 15, "completion_tokens": 18, "total_tokens": 32},
    ],
)
async def test_total_minus_prompt_rejects_missing_or_inconsistent_total(usage: dict) -> None:
    body = {**_OK_BODY, "usage": usage}
    provider = _provider(
        httpx.MockTransport(lambda _: httpx.Response(200, json=body)),
        usage_accounting_mode=UsageAccountingMode.TOTAL_MINUS_PROMPT_V1,
    )

    with pytest.raises(ProviderProtocolError):
        await provider.complete(_user("你好"))


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


async def test_native_tools_are_sent_and_structured_calls_are_parsed() -> None:
    import json

    seen: dict[str, object] = {}
    body = {
        "model": "glm-4.7",
        "choices": [
            {
                "message": {
                    "role": "assistant",
                    "content": None,
                    "tool_calls": [
                        {
                            "id": "call-1",
                            "type": "function",
                            "function": {
                                "name": "search_faq",
                                "arguments": '{"topic":"refund"}',
                            },
                        }
                    ],
                },
                "finish_reason": "tool_calls",
            }
        ],
        "usage": {"prompt_tokens": 10, "completion_tokens": 5},
    }

    def handler(request: httpx.Request) -> httpx.Response:
        seen.update(json.loads(request.content))
        return httpx.Response(200, json=body)

    response = await _provider(httpx.MockTransport(handler)).complete(
        _user("refund"),
        tools=[
            LLMToolDefinition(
                name="search_faq",
                description="Search FAQ",
                parameters={"type": "object", "properties": {}},
            )
        ],
        tool_choice="auto",
    )

    tools = seen["tools"]
    assert isinstance(tools, list)
    assert seen["tool_choice"] == "auto"
    assert tools[0]["function"]["name"] == "search_faq"
    assert response.tool_calls[0].id == "call-1"
    assert response.tool_calls[0].arguments_json == '{"topic":"refund"}'


def _gemini_tool_call_body(extra_content: object) -> dict[str, object]:
    call: dict[str, object] = {
        "id": "call-1",
        "type": "function",
        "function": {"name": "get_customer_profile", "arguments": '{"customer_id":"customer_b"}'},
    }
    if extra_content is not None:
        call["extra_content"] = extra_content
    return {
        "model": "gemini-3.1-flash-lite",
        "choices": [
            {
                "message": {"role": "assistant", "content": None, "tool_calls": [call]},
                "finish_reason": "tool_calls",
            }
        ],
        "usage": {"prompt_tokens": 10, "completion_tokens": 5},
    }


async def test_tool_call_extra_content_is_echoed_back_unchanged() -> None:
    """2026-09-23: Gemini 3 returns a thought signature on each function call and rejects
    the follow-up turn with HTTP 400 ("missing a thought_signature") unless it comes back
    verbatim at `tool_calls[].extra_content`.
    """
    import json

    signature = {"google": {"thought_signature": "opaque-signature=="}}
    requests: list[dict[str, object]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(json.loads(request.content))
        return httpx.Response(200, json=_gemini_tool_call_body(signature))

    provider = _provider(httpx.MockTransport(handler))
    first = await provider.complete(_user("look up customer_b"))
    assert first.tool_calls[0].extra_content == signature

    await provider.complete(
        [
            *_user("look up customer_b"),
            LLMMessage(role=Role.ASSISTANT, content="", tool_calls=first.tool_calls),
            LLMMessage(role=Role.TOOL, content="{}", tool_call_id="call-1"),
        ]
    )

    echoed = requests[1]["messages"][1]["tool_calls"][0]
    assert echoed["extra_content"] == signature
    assert echoed["id"] == "call-1"


async def test_tool_call_without_extra_content_is_echoed_without_the_key() -> None:
    """Providers that never send it (GLM, OpenAI) must see an unchanged payload."""
    import json

    requests: list[dict[str, object]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(json.loads(request.content))
        return httpx.Response(200, json=_gemini_tool_call_body(None))

    provider = _provider(httpx.MockTransport(handler))
    first = await provider.complete(_user("look up customer_b"))
    assert first.tool_calls[0].extra_content is None

    await provider.complete(
        [
            *_user("look up customer_b"),
            LLMMessage(role=Role.ASSISTANT, content="", tool_calls=first.tool_calls),
        ]
    )

    assert "extra_content" not in requests[1]["messages"][1]["tool_calls"][0]


async def test_tool_call_extra_content_must_be_an_object() -> None:
    provider = _provider(
        httpx.MockTransport(
            lambda _: httpx.Response(200, json=_gemini_tool_call_body("not-an-object"))
        )
    )

    with pytest.raises(ProviderProtocolError, match="extra_content"):
        await provider.complete(_user("look up customer_b"))


def test_tool_call_extra_content_defaults_to_none() -> None:
    call = LLMToolCall(id="call-1", name="search_faq", arguments_json="{}")

    assert call.extra_content is None


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


def test_extra_body_rejects_unknown_or_secret_fields() -> None:
    with pytest.raises(ValueError, match="Extra inputs are not permitted"):
        _provider(extra_body={"api_key": "do-not-store"})


async def test_usage_coverage_is_an_explicit_capability() -> None:
    assert not _provider().usage_covers_billed_tokens
    assert _provider(usage_covers_billed_tokens=True).usage_covers_billed_tokens


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


async def test_rate_limit_is_published_to_the_shared_limiter_before_the_lease_releases(
    tmp_path,
) -> None:
    limiter = SQLiteRateLimiter(
        f"sqlite:///{tmp_path / 'rate-limit.db'}",
        provider_key="example|model",
        min_interval_seconds=0,
        max_concurrency=1,
    )
    provider = _provider(
        httpx.MockTransport(lambda _: httpx.Response(429, headers={"retry-after": "30"})),
        shared_limiter=limiter,
    )

    with pytest.raises(ProviderRateLimitedError):
        await provider.complete(_user("你好"))

    with sqlite3.connect(tmp_path / "rate-limit.db") as connection:
        blocked_until, streak = connection.execute(
            "SELECT blocked_until, consecutive_rate_limits "
            "FROM shared_provider_rate_limit WHERE provider_key = ?",
            ("example|model",),
        ).fetchone()

    assert blocked_until > time.time()
    assert streak == 1


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


# ── 畸形用量(2026-08-11 安全审查)───────────────────────────────────────


def test_boolean_token_counts_are_not_accepted_as_known_usage() -> None:
    """⭐ Python 里 `isinstance(True, int)` 为真。

    于是 `{"prompt_tokens": true}` 会被当成"已知用量、值为 1" —— 一次完全没有
    记账的调用就此冒充成记账正确的调用。而 `usage_known` 正是 Token 预算与
    Phase 0.5 Gate 证据赖以成立的那个标志位;Provider 在信任边界之外,
    畸形回包必须当作未知,不能当作 1。
    """
    from redcell.llm.openai_compatible import _as_int, _is_token_count

    assert _is_token_count(5)
    assert _is_token_count(0)
    assert not _is_token_count(True)
    assert not _is_token_count(False)
    assert not _is_token_count(-1)
    assert not _is_token_count("7")
    assert not _is_token_count(1.5)
    assert _as_int(True) == 0
    assert _as_int(7) == 7


async def test_max_tokens_parameter_renames_the_output_cap_field() -> None:
    """2026-09-23:gpt-6-luna 对 `max_tokens` 返回 HTTP 400,只认 `max_completion_tokens`。"""
    seen: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        import json

        seen.update(json.loads(request.content))
        return httpx.Response(200, json=_OK_BODY)

    await _provider(
        httpx.MockTransport(handler),
        max_tokens_parameter="max_completion_tokens",
        extra_body={"reasoning_effort": "none"},
    ).complete(_user("你好"), temperature=1.0, max_tokens=512)

    assert seen["max_completion_tokens"] == 512
    assert "max_tokens" not in seen
    assert seen["reasoning_effort"] == "none"
    assert seen["temperature"] == 1.0


def test_reasoning_effort_rejects_undocumented_values() -> None:
    with pytest.raises(ValueError, match="reasoning_effort"):
        _provider(extra_body={"reasoning_effort": "turbo"})
