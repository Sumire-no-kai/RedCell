"""OpenAICompatibleProvider —— 一份实现覆盖大部分低成本 provider。

选这条路的理由(见 DEVLOG 2026-07-27 的 D2 调研):国产 DeepSeek / Qwen / GLM /
Kimi / 硅基流动,以及 Gemini 的兼容端点,全都接受同一套 `chat/completions` 协议。
换 provider 因此是**改配置**,不是改代码 —— 而 `CALIBRATION.md` §10 把"更换靶场
模型"列为核弹级操作,能少一个改代码的理由就少一分改错的机会。

⚠️ **本类刻意不做重试。** `retry.py` 已经有 `RetryPolicy`(指数退避 + 抖动),
重试次数上限本身还是未定项。provider 内部再退避一次会得到两层叠加的等待,
而日志里只看得见一层 —— 排查时对不上号。这里只负责**把失败分类清楚**,
让上层照既定策略决定重试几次。
"""

from __future__ import annotations

import asyncio
import time
from typing import Any

import httpx
import structlog
from pydantic import Field

from redcell.llm.base import LLMMessage, LLMProvider, LLMResponse
from redcell.protocols.common import RedCellModel

_log = structlog.get_logger(__name__)


class TokenPricing(RedCellModel):
    """每百万 token 的美元单价。

    **必须显式给出,没有默认值。** OpenAI 兼容协议的 `usage` 只回 token 数,
    从不回金额 —— 所以"知道花了多少钱"完全依赖这张表是不是填对了。
    给一个默认值就等于替使用者猜价格,而猜错不会报错,只会让预算上限失真。

    免费模型请显式写 `TokenPricing(input_usd_per_mtok=0, output_usd_per_mtok=0)`:
    那是一句"我确认它免费"的声明,和"忘了填"在语义上必须分得开。
    """

    input_usd_per_mtok: float = Field(ge=0.0)
    output_usd_per_mtok: float = Field(ge=0.0)

    def cost_for(self, prompt_tokens: int, completion_tokens: int) -> float:
        return (
            prompt_tokens * self.input_usd_per_mtok + completion_tokens * self.output_usd_per_mtok
        ) / 1_000_000


class ProviderConfigurationError(RuntimeError):
    """key 无效、模型名不存在、权限不足 —— 重试多少次都是同样结果。

    对应 `FailureKind.CONFIGURATION`:必须让 Run 立刻失败,而不是退避后再撞一次。
    """


class ProviderTransientError(RuntimeError):
    """5xx / 超时 / 连接中断 —— 稍后重试有意义。

    对应 `FailureKind.NETWORK_TRANSIENT`。**送达状态未知** ——
    请求可能已被处理,所以在不支持幂等键的目标上重试并不安全。
    """

    def __init__(self, message: str, *, retry_after_seconds: float | None = None) -> None:
        super().__init__(message)
        self.retry_after_seconds = retry_after_seconds


class ProviderRateLimitedError(ProviderTransientError):
    """429 —— 超出速率或配额上限。

    对应 `FailureKind.RATE_LIMITED`,单独一类的理由见 `failures.py` 模块文档。
    要点是**送达状态确定**:服务端在处理之前就拒绝了,请求确定没有生效,
    因此重试是无条件安全的 —— 这一点和超时截然不同。

    免费层会大量走这条路径,所以 `retry_after_seconds` 尽量取响应头的真实值,
    而不是让上层瞎猜。
    """


class ProviderProtocolError(RuntimeError):
    """HTTP 200,但响应结构不是预期的样子。

    单独分一类,是因为它和"网络抖动"的处置完全不同:重试通常无济于事,
    而它往往意味着换了端点或对方改了协议 —— 那是需要人看一眼的信号,
    不该被退避循环磨平成一条超时。
    """


class OpenAICompatibleProvider(LLMProvider):
    """通过 `POST {base_url}/chat/completions` 调用任意 OpenAI 兼容端点。

    已知可用的 base_url:

    * 智谱 GLM        `https://open.bigmodel.cn/api/paas/v4`
    * Gemini 兼容端点 `https://generativelanguage.googleapis.com/v1beta/openai`
    * DeepSeek        `https://api.deepseek.com/v1`

    ⚠️ **`model` 必须传具体版本串,不要传滚动别名。** 厂商中途更新模型不会报错,
    只会让此前的实验结论静默作废 —— 届时只看得到"数字对不上",查不出原因。
    真实回传的模型串会原样写进 `LLMResponse.model`,便于事后核对是否发生漂移。
    """

    def __init__(
        self,
        *,
        base_url: str,
        model: str,
        api_key: str,
        name: str,
        pricing: TokenPricing | None = None,
        timeout_seconds: float = 60.0,
        min_interval_seconds: float = 0.0,
        max_concurrency: int = 0,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        """
        Args:
            name: 写进 trace 的 provider 标识(如 `"glm"` / `"gemini"`)。
                target 与 attacker 即使复用同一个类,也必须各自可辨认。
            pricing: 不给就等于声明"本 provider 的成本不可观测",
                `reports_cost` 随之为 False,`cost_usd` 恒为 0。
            min_interval_seconds: 两次请求之间的最小间隔,给按 **RPM** 限速的
                provider 用(例如 10 RPM 对应 6.0)。0 表示不节流。
            max_concurrency: 同时在途的请求数上限,给按**并发数**限速的 provider 用。
                0 表示不限制。

                两个参数管的是不同的东西,不能互相替代:GLM 按并发数限流
                (GLM-4.7-Flash 上限为 1),Gemini 免费层按 RPM 限流。
                只做间隔节流挡不住并发超限,只做并发限制挡不住 RPM 超限。

                ⚠️ 两者都是**本地自律**,不是配额保证 —— 真限流仍会以 429 出现,
                所以 `ProviderTransientError` 那条路径必须一直有效。
            client: 供测试注入 `httpx.MockTransport`,从而全程不联网、不花钱。
        """
        self._base_url = base_url.rstrip("/")
        self._model = model
        self._api_key = api_key
        self._name = name
        self._pricing = pricing
        self._timeout = timeout_seconds
        self._min_interval = min_interval_seconds
        self._client = client
        self._owns_client = client is None
        self._throttle = asyncio.Lock()
        self._last_request_at: float | None = None
        self._slots = asyncio.Semaphore(max_concurrency) if max_concurrency > 0 else None

    @property
    def name(self) -> str:
        return self._name

    @property
    def model(self) -> str:
        """本 provider 配置的默认模型串(请求串,非服务端回传)。"""
        return self._model

    @property
    def reports_cost(self) -> bool:
        """仅当显式配置了 `pricing` 才为 True。

        注意这里的语义是"**我拿到了单价,能算出金额**",不是"API 告诉了我金额" ——
        OpenAI 兼容协议从不返回金额。所以厂商调价后这个数会**静默偏移**,
        本类因此把用到的单价一并写进 `LLMResponse.raw`,让事后能复核算的是哪一档价。
        """
        return self._pricing is not None

    async def complete(
        self,
        messages: list[LLMMessage],
        *,
        model: str | None = None,
        temperature: float = 0.0,
        max_tokens: int | None = None,
    ) -> LLMResponse:
        payload: dict[str, Any] = {
            "model": model or self._model,
            "messages": [{"role": m.role.value, "content": m.content} for m in messages],
            "temperature": temperature,
        }
        if max_tokens is not None:
            payload["max_tokens"] = max_tokens

        if self._slots is None:
            return await self._timed_post(payload)
        # 并发闸在节流之前:先占到位子再算间隔,否则一批协程会同时通过间隔检查,
        # 然后一起冲进去把并发上限撞穿。
        async with self._slots:
            return await self._timed_post(payload)

    async def _timed_post(self, payload: dict[str, Any]) -> LLMResponse:
        await self._await_throttle()
        started = time.perf_counter()
        data = await self._post(payload)
        latency_ms = (time.perf_counter() - started) * 1000
        return self._to_response(data, latency_ms)

    async def aclose(self) -> None:
        """关闭自建的 HTTP 客户端。注入进来的客户端由调用方负责。"""
        if self._owns_client and self._client is not None:
            await self._client.aclose()
            self._client = None

    # ── 内部 ────────────────────────────────────────────────────

    async def _await_throttle(self) -> None:
        if self._min_interval <= 0:
            return
        async with self._throttle:
            if self._last_request_at is not None:
                elapsed = time.monotonic() - self._last_request_at
                if elapsed < self._min_interval:
                    await asyncio.sleep(self._min_interval - elapsed)
            self._last_request_at = time.monotonic()

    def _ensure_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=self._timeout)
        return self._client

    async def _post(self, payload: dict[str, Any]) -> dict[str, Any]:
        client = self._ensure_client()
        try:
            response = await client.post(
                f"{self._base_url}/chat/completions",
                json=payload,
                headers={
                    "Authorization": f"Bearer {self._api_key}",
                    "Content-Type": "application/json",
                },
                timeout=self._timeout,
            )
        except httpx.TimeoutException as exc:
            raise ProviderTransientError(f"{self._name} 请求超时:{exc}") from exc
        except httpx.HTTPError as exc:
            raise ProviderTransientError(f"{self._name} 连接失败:{exc}") from exc

        self._raise_for_status(response)

        try:
            data = response.json()
        except ValueError as exc:
            raise ProviderProtocolError(
                f"{self._name} 返回了 200 但不是合法 JSON(前 200 字符:{response.text[:200]!r})"
            ) from exc
        if not isinstance(data, dict):
            raise ProviderProtocolError(
                f"{self._name} 返回的顶层结构不是对象:{type(data).__name__}"
            )
        return data

    def _raise_for_status(self, response: httpx.Response) -> None:
        status = response.status_code
        if status < 400:
            return

        detail = response.text[:300]
        if status in (401, 403):
            self._log_failure(status, "configuration", "认证失败")
            raise ProviderConfigurationError(
                f"{self._name} 认证失败(HTTP {status})——"
                f"检查 API key 是否有效、是否已开通该模型。{detail}"
            )
        if status == 404:
            self._log_failure(status, "configuration", "端点或模型不存在")
            raise ProviderConfigurationError(
                f"{self._name} 端点或模型不存在(HTTP 404)——检查 base_url 与 model 串。{detail}"
            )
        if status == 429:
            retry_after = _retry_after(response)
            self._log_failure(status, "rate_limited", "触发限流", retry_after=retry_after)
            raise ProviderRateLimitedError(
                f"{self._name} 触发限流(HTTP 429)。{detail}",
                retry_after_seconds=retry_after,
            )
        if status >= 500:
            retry_after = _retry_after(response)
            self._log_failure(status, "network_transient", "服务端错误", retry_after=retry_after)
            raise ProviderTransientError(
                f"{self._name} 服务端错误(HTTP {status})。{detail}",
                retry_after_seconds=retry_after,
            )
        # 其余 4xx:请求本身有问题,重试不会变好。
        self._log_failure(status, "configuration", "请求被拒绝")
        raise ProviderConfigurationError(f"{self._name} 拒绝了请求(HTTP {status})。{detail}")

    def _log_failure(
        self,
        status: int,
        kind: str,
        reason: str,
        *,
        retry_after: float | None = None,
    ) -> None:
        """写进**运行时日志**(与 DEVLOG 无关)。

        只记结构化字段,**绝不记请求体或响应全文** —— 那里可能带着攻击话术、
        靶场数据,以及最要命的:某些 provider 会在错误信息里回显请求头。
        """
        _log.warning(
            "provider_request_failed",
            provider=self._name,
            model=self._model,
            status=status,
            kind=kind,
            reason=reason,
            retry_after_seconds=retry_after,
        )

    def _to_response(self, data: dict[str, Any], latency_ms: float) -> LLMResponse:
        choices = data.get("choices")
        if not isinstance(choices, list) or not choices:
            raise ProviderProtocolError(f"{self._name} 的响应里没有 choices:{_preview(data)}")
        message = choices[0].get("message") if isinstance(choices[0], dict) else None
        if not isinstance(message, dict):
            raise ProviderProtocolError(
                f"{self._name} 的 choices[0] 里没有 message:{_preview(data)}"
            )

        content = message.get("content")
        if content is None:
            # 空回复本身是合法结果(例如被安全策略拦下),不该当协议错误处理——
            # 但也不能悄悄变成 None 往下传,那会在解析工具调用时炸在很远的地方。
            content = ""
        if not isinstance(content, str):
            raise ProviderProtocolError(
                f"{self._name} 的 message.content 不是字符串:{type(content).__name__}"
            )

        usage = data.get("usage") if isinstance(data.get("usage"), dict) else {}
        prompt_tokens = _as_int(usage.get("prompt_tokens"))
        completion_tokens = _as_int(usage.get("completion_tokens"))

        raw: dict[str, Any] = {
            "provider": self._name,
            "finish_reason": choices[0].get("finish_reason"),
            "usage": usage,
        }
        cost = 0.0
        if self._pricing is not None:
            cost = self._pricing.cost_for(prompt_tokens, completion_tokens)
            # 把单价一起留档:厂商调价后,只有这条记录能说明当时算的是哪一档。
            raw["pricing"] = self._pricing.model_dump()

        return LLMResponse(
            content=content,
            # 用**服务端回传的** model 串;它与请求串不一致就是模型漂移的证据。
            model=str(data.get("model") or self._model),
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            latency_ms=latency_ms,
            cost_usd=cost,
            raw=raw,
        )


def _retry_after(response: httpx.Response) -> float | None:
    """优先用服务端给的 Retry-After,拿不到才让上层用自己的退避曲线。"""
    value = response.headers.get("retry-after")
    if value is None:
        return None
    try:
        seconds = float(value)
    except ValueError:
        return None
    return seconds if seconds >= 0 else None


def _as_int(value: Any) -> int:
    return value if isinstance(value, int) and value >= 0 else 0


def _preview(data: dict[str, Any]) -> str:
    return repr(data)[:200]
