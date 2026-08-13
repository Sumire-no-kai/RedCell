"""从环境 / `.env` 读取 provider 配置,并组装成 Provider 实例。

## 为什么是这一层

CLI 是 composition root,但"从 env 读哪些键、怎么拼成 Provider"本身有取舍
(免费档限流、成本可观测性、target 与 attacker 分开),不该散在 CLI 的命令函数里。
这一层把它收拢,CLI 只调 `load_providers()`。

## 两个模型位为什么分开配置

见 CONCEPTS §14.4:target(被测)与 attacker(出题)必须分别记录 model /
temperature / cost。它们可以复用同一个实现类、甚至同一个模型,但**配置分开**——
否则换 target 时可能顺带换掉 attacker,成功率一变就无法归因。
"""

from __future__ import annotations

import os

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

from redcell.llm import OpenAICompatibleProvider, TokenPricing
from redcell.protocols.run import ProviderExtraBody, ProviderRunConfiguration
from redcell.shared_rate_limit import SQLiteRateLimiter

# `.env` 里把一个键留空(`REDCELL_ATTACKER_TEMPERATURE=`)是很自然的写法,意思是"用默认值"。
# 但 pydantic 默认会把空串喂给字段,数值字段随即报错。`env_ignore_empty=True` 让空值
# 被当作"未设置",默认值因此生效 —— 留空是配置常态,不该是崩溃点。
_ENV = SettingsConfigDict(
    env_file=".env",
    env_file_encoding="utf-8",
    env_ignore_empty=True,
    extra="ignore",
)


class ProviderSettings(BaseSettings):
    """一个模型位(target 或 attacker)的配置。

    用前缀区分两位:`REDCELL_TARGET_*` 与 `REDCELL_ATTACKER_*`。
    """

    model_config = _ENV

    provider: str = ""
    base_url: str = ""
    api_key: str = ""
    model: str = ""
    temperature: float = 0.7
    rpm: float = Field(default=0.0, ge=0.0)
    """每分钟请求上限,0 表示不节流。给按 RPM 限流的 provider(如 Gemini 免费层)用。"""

    max_concurrency: int = Field(default=0, ge=0)
    """并发上限,0 表示不限。给按并发数限流的 provider(如 GLM 免费层上限 1)用。"""

    max_tokens: int = Field(default=512, gt=0)
    """单次回复的 token 上限。⭐

    ⚠️ **开了 thinking 的模型必须调大。** 2026-08-03 实测:
    `gemini-3.6-flash` / `3.5-flash` 的思考 token **占用这个预算却不计进
    `completion_tokens`** —— 512 时可见正文被截在句子中间(3.5-flash 七条全断),
    调到 2048 后截断归零。

    截断的攻击话术是**残缺的仪器**:它系统性地弱化每一条攻击,
    而截断率还可能因策略而异 —— 那就成了偏差,不是噪声。

    ⚠️ **同时意味着成本会被低估:** `--max-cost` 是按 `usage` 报的 token 算的,
    而思考 token 不在里面。对 thinking 模型,那道闸门只管住了一部分开销 ——
    首次跑完必须拿控制台用量对一次账。不想操心这件事就选非 thinking 的模型
    (`*-flash-lite` 实测无此问题:512 下 0/7 截断,报的 token 与正文长度相符)。
    """

    # 未填价格 = 不知道，不能伪装成免费。免费档也要把三项都显式填 0。
    input_usd_per_mtok: float | None = Field(default=None, ge=0.0)
    output_usd_per_mtok: float | None = Field(default=None, ge=0.0)
    cached_input_usd_per_mtok: float | None = Field(default=None, ge=0.0)

    extra_body: ProviderExtraBody = Field(default_factory=ProviderExtraBody)
    """受类型约束并入请求的厂商字段；当前只允许 `thinking.type`。

    ⚠️ **这是一个隐藏旋钮,不是普通配置。** 2026-08-06 实测:GLM 的
    `{"thinking": {"type": "disabled"}}` 能把延迟压到约 1/12,但同时改变了
    工具调用的格式遵循率——它有能力同时改变延迟、成本和 ASR,
    和 `CALIBRATION.md` §10 的四个已知旋钮是同一类东西。启用它必须像那四个
    旋钮一样显式声明、重跑阳性对照、写进 DEVLOG,不能当默认性能优化用。
    """

    usage_covers_billed_tokens: bool = False
    """只有能证明 usage 覆盖全部计费 Token 的角色才可进入正式 Gate。"""

    def is_configured(self) -> bool:
        """必要字段是否齐全,可以真正建 provider。"""
        return bool(self.provider and self.base_url and self.api_key and self.model)

    def run_configuration(self) -> ProviderRunConfiguration:
        """返回可落盘的非凭据快照；用于实验可比性与 resume 前复核。"""
        return ProviderRunConfiguration(
            provider=self.provider,
            base_url=self.base_url,
            model=self.model,
            temperature=self.temperature,
            max_tokens=self.max_tokens,
            rpm=self.rpm,
            max_concurrency=self.max_concurrency,
            input_usd_per_mtok=self.input_usd_per_mtok,
            output_usd_per_mtok=self.output_usd_per_mtok,
            cached_input_usd_per_mtok=self.cached_input_usd_per_mtok,
            extra_body=self.extra_body,
            usage_covers_billed_tokens=self.usage_covers_billed_tokens,
        )

    def build(self, *, name: str) -> OpenAICompatibleProvider:
        if not self.is_configured():
            raise ProviderConfigError(
                f"{name} provider 配置不完整 —— 检查 .env 里对应的 "
                "PROVIDER / BASE_URL / API_KEY / MODEL 四项是否都填了。"
            )
        rates = (
            self.input_usd_per_mtok,
            self.output_usd_per_mtok,
            self.cached_input_usd_per_mtok,
        )
        pricing = None
        if all(rate is not None for rate in rates):
            pricing = TokenPricing(
                input_usd_per_mtok=rates[0],
                output_usd_per_mtok=rates[1],
                cached_input_usd_per_mtok=rates[2],
            )
        return OpenAICompatibleProvider(
            base_url=self.base_url,
            model=self.model,
            api_key=self.api_key,
            name=name,
            pricing=pricing,
            min_interval_seconds=(60.0 / self.rpm) if self.rpm > 0 else 0.0,
            max_concurrency=self.max_concurrency,
            extra_body=self.extra_body,
            usage_covers_billed_tokens=self.usage_covers_billed_tokens,
            shared_limiter=_shared_limiter(
                base_url=self.base_url,
                model=self.model,
                min_interval_seconds=(60.0 / self.rpm) if self.rpm > 0 else 0.0,
                max_concurrency=self.max_concurrency,
            ),
        )


def _shared_limiter(
    *, base_url: str, model: str, min_interval_seconds: float, max_concurrency: int
) -> SQLiteRateLimiter | None:
    """All child processes opt into the same DB through one explicit environment key."""
    database_url = os.getenv("REDCELL_SHARED_RATE_LIMIT_DB", "")
    if not database_url:
        return None
    return SQLiteRateLimiter(
        database_url,
        provider_key=f"{base_url.rstrip('/')}|{model}",
        min_interval_seconds=min_interval_seconds,
        max_concurrency=max_concurrency,
        lease_timeout_seconds=300.0,
    )


class ProviderConfigError(RuntimeError):
    """provider 配置缺失或不完整。属于 BAD_CONFIG,不是运行时故障。"""


class TargetSettings(ProviderSettings):
    model_config = _ENV | SettingsConfigDict(env_prefix="REDCELL_TARGET_")


class AttackerSettings(ProviderSettings):
    model_config = _ENV | SettingsConfigDict(env_prefix="REDCELL_ATTACKER_")

    # attacker 默认调高:鼓励话术多样性(与 target 的 0.7 分开)。
    temperature: float = 1.0


class ControllerSettings(ProviderSettings):
    """独立的策略选择模型位；不能静默借用 target 或 attacker 配置。"""

    model_config = _ENV | SettingsConfigDict(env_prefix="REDCELL_CONTROLLER_")
    temperature: float = 0.0
    max_tokens: int = 512


class ProviderPair:
    """target 与 attacker 两个已建好的 provider,以及关闭它们的入口。"""

    def __init__(
        self,
        target: OpenAICompatibleProvider,
        attacker: OpenAICompatibleProvider,
        *,
        attacker_max_tokens: int = 512,
        target_configuration: ProviderRunConfiguration,
        attacker_configuration: ProviderRunConfiguration,
    ) -> None:
        self.target = target
        self.attacker = attacker
        self.attacker_max_tokens = attacker_max_tokens
        self.target_configuration = target_configuration
        self.attacker_configuration = attacker_configuration
        """attacker 单次回复的 token 上限 —— thinking 模型需要更大,见 ProviderSettings。"""

    async def aclose(self) -> None:
        await self.target.aclose()
        await self.attacker.aclose()


def load_attacker() -> OpenAICompatibleProvider:
    """只建 attacker 一位。

    攻击方对照(`redcell attacker-control`)整个流程**不碰 target** ——
    它比较的是攻击方产出的话术,靶场一次都不会被调用。
    因此不该因为 target 那半边配置不全就拒绝启动:
    那会把一道"检查攻击方"的诊断,错误地卡在一个与它无关的前置条件上。
    """
    settings = AttackerSettings()
    provider = settings.build(name="attacker")
    provider.run_configuration = settings.run_configuration()
    return provider


def load_controller() -> tuple[OpenAICompatibleProvider, ProviderRunConfiguration]:
    """构造 Controller 的独立连接与不含凭据的运行快照。"""
    settings = ControllerSettings()
    return settings.build(name="controller"), settings.run_configuration()


def load_target() -> tuple[OpenAICompatibleProvider, ProviderRunConfiguration]:
    """构造 Target 的独立连接与不含凭据的运行快照。

    Replay validation 只会重放已冻结的攻击路径，不应顺带创建 attacker 或
    Controller 连接。把单独加载入口放在配置层，也避免 CLI 复制 env 解析规则。
    """
    settings = TargetSettings()
    return settings.build(name="target"), settings.run_configuration()


def load_providers() -> ProviderPair:
    """从 env / `.env` 读出并建好两个 provider。配置不全时抛 ProviderConfigError。"""
    target_settings = TargetSettings()
    attacker_settings = AttackerSettings()
    return ProviderPair(
        target=target_settings.build(name="target"),
        attacker=attacker_settings.build(name="attacker"),
        attacker_max_tokens=attacker_settings.max_tokens,
        target_configuration=target_settings.run_configuration(),
        attacker_configuration=attacker_settings.run_configuration(),
    )
