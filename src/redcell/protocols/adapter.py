"""Target Adapter —— RedCell 引擎与被测目标之间的唯一通信面。

引擎只认这里定义的输入/输出结构。换一种目标(进程内靶场 / HTTP API /
LangChain / MCP)只需要新写一个 TargetAdapter 子类,引擎一行不改。

这是依赖倒置:高层逻辑(bandit、评分、预算)不依赖"怎么发请求"这种低层细节,
两边都依赖中间这层抽象。
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from enum import StrEnum
from typing import Any

from pydantic import Field

from redcell.protocols.common import ObservabilityLevel, RedCellModel, Role


class Message(RedCellModel):
    role: Role
    content: str


class ResetScope(StrEnum):
    """Adapter 的 reset 能恢复到什么范围。"""

    NONE = "none"
    CONVERSATION = "conversation"
    FULL_STATE = "full_state"


class IdempotencySupport(StrEnum):
    """目标是否能用稳定 idempotency key 去除重复副作用。"""

    NONE = "none"
    SUPPORTED = "supported"
    REQUIRED = "required"


class DeliveryObservability(StrEnum):
    """断线时能否判断请求是否已经被目标接收。"""

    UNKNOWN = "unknown"
    ACKNOWLEDGED = "acknowledged"
    IN_PROCESS = "in_process"


class AdapterCapabilities(RedCellModel):
    """与安全重试有关的静态能力。

    默认全部保守:新 Adapter 没有明确声明时,Orchestrator 不得假定可安全重试。
    """

    reset_scope: ResetScope = ResetScope.NONE
    idempotency: IdempotencySupport = IdempotencySupport.NONE
    delivery_observability: DeliveryObservability = DeliveryObservability.UNKNOWN

    reports_cost: bool = False
    """目标是否会真实填充 `TraceMetadata.cost_usd`。

    存在的意义是让 `max_cost_usd` 预算**要么真的生效,要么当场报错**:
    不报告成本的目标上,成本上限永远不会触发,也永远不会报错 ——
    那是一个假的安全网,比没有安全网更危险。Orchestrator 在 preflight 据此拒绝配置。
    """


class ToolCall(RedCellModel):
    """目标 agent 生成的一次工具调用。

    注意:生成调用 ≠ 调用被执行。前者是 Attempted Action,后者才可能构成
    Realized Impact,两者必须分开记录。
    """

    id: str
    name: str
    arguments: dict[str, Any] = Field(default_factory=dict)


class ToolResult(RedCellModel):
    tool_call_id: str
    name: str
    content: str
    error: str | None = None

    awaiting_confirmation: bool = False
    """这次调用**没有执行**,因为它在等用户确认。⭐

    ## 为什么必须显式表达,而不是从 error 或正文里猜

    "被扣住等确认"既不是错误(agent 什么都没做错,只是还差一步),
    也不是执行(动作根本没发生)。在此之前 trace 只有 `error` 一个开关,
    于是被扣住的调用与已执行的调用**长得一模一样** —— 2026-08-11 的实测里,
    这直接造成两处错判:

    1. 检测器把"合法执行之后又问了一句"误判成确认绕过 ——
       它假定同回合内第一次同签名调用是"询问",而确认从上一回合结转过来时,
       第一次其实是**执行**;
    2. 被扣住的调用会被算成 `executed`,于是 Impact 报成 `REALIZED`,
       而后端其实什么也没做。

    由 Adapter 如实声明,不靠匹配靶场的通知文案 —— 那种写法换个目标就失效。
    """

    @property
    def rejected(self) -> bool:
        """工具层是否拒绝了这次调用(例如被权限检查拦下)。

        这正是 Attempt=True / Impact=NOT_REALIZED 的典型场景:
        agent 想干,但后端守住了。
        """
        return self.error is not None

    @property
    def performed(self) -> bool:
        """后端是否**真的执行**了这次调用。

        拒绝与"等确认"都不算执行 —— 前者被守住,后者还没发生。
        """
        return not self.rejected and not self.awaiting_confirmation


class SideEffect(RedCellModel):
    """目标系统状态真实发生的改变。

    靶场里的工具全是模拟器:退款不动真钱,只往这里追加一条记录。
    这既是安全红线(PRD §16),也让 Impact 变成可以精确断言的事实,
    而不是需要人去猜的东西。
    """

    kind: str
    payload: dict[str, Any] = Field(default_factory=dict)
    tool_call_id: str | None = None


class TraceMetadata(RedCellModel):
    prompt_tokens: int = 0
    completion_tokens: int = 0
    cached_input_tokens: int = 0
    usage_known: bool = True
    latency_ms: float = 0.0
    cost_usd: float = Field(default=0.0, ge=0.0)
    """本次目标调用的实际美元成本。真实 Provider 必须显式填充。"""

    model: str | None = None
    temperature: float | None = None
    extra: dict[str, Any] = Field(default_factory=dict)

    @property
    def total_tokens(self) -> int:
        return self.prompt_tokens + self.completion_tokens


class AdapterInput(RedCellModel):
    messages: list[Message]
    actor: str
    """以谁的身份说话。跨用户越权检测完全依赖这个字段。"""
    request_id: str | None = None
    """一轮外部请求的稳定标识;重试时保持不变。"""
    idempotency_key: str | None = None
    """目标支持时用于去除重复副作用;不支持的 Adapter 可以忽略。"""
    metadata: dict[str, Any] = Field(default_factory=dict)


class AdapterOutput(RedCellModel):
    assistant_message: str = ""
    tool_calls: list[ToolCall] = Field(default_factory=list)
    malformed_tool_calls: int = Field(default=0, ge=0)
    """模型**尝试**调用工具但我们没能解析出来的次数。

    ⚠️ **没有这个计数,"靶场防住了"和"模型不会按格式输出"在数据里长得完全一样** ——
    两者都表现为"零次工具调用"。而这两件事的处置完全相反:
    前者说明防御有效,后者说明这个模型根本不适合当 target。

    2026-08-01 实测踩过这个坑:GLM-4.7-Flash 选对了工具、参数也对,
    只是不输出闭合标签,于是每一次正确的调用都被静默丢弃。
    当时是靠人盯着 preflight 输出看出来的 —— 换个模型未必有人看。

    **显式字段而不是塞进 `TraceMetadata.extra`:** 同一个错误犯过一次了 ——
    成本曾经藏在 `extra["cost_usd"]` 里,忘了填就静默按 0 计费。
    约定俗成的魔法键没有任何东西能保证它被填上。
    """
    tool_results: list[ToolResult] = Field(default_factory=list)
    side_effects: list[SideEffect] = Field(default_factory=list)
    observability: ObservabilityLevel
    """本次输出的可观测性等级。Scoring Engine 据此决定 Impact 能否判定。"""
    trace_metadata: TraceMetadata = Field(default_factory=TraceMetadata)

    def tool_calls_named(self, name: str) -> list[ToolCall]:
        return [tc for tc in self.tool_calls if tc.name == name]

    def result_for(self, tool_call_id: str) -> ToolResult | None:
        return next((r for r in self.tool_results if r.tool_call_id == tool_call_id), None)


class TargetAdapter(ABC):
    """所有目标适配器的接口。"""

    @property
    @abstractmethod
    def adapter_type(self) -> str:
        """写进 ReproductionContext,用于复现时定位是哪种适配器。"""

    @property
    @abstractmethod
    def observability(self) -> ObservabilityLevel:
        """本适配器能观测到多少。决定 Impact 是否可判定。"""

    @property
    def capabilities(self) -> AdapterCapabilities:
        """安全重试能力。未覆盖时返回保守默认值。"""
        return AdapterCapabilities()

    @abstractmethod
    async def send(self, payload: AdapterInput) -> AdapterOutput:
        """发一轮对话,拿回目标的完整可观测行为。"""

    @abstractmethod
    async def reset(self) -> None:
        """把目标状态复位到干净初始态。

        必须在每场 attempt 开始前调用:上一场攻击造成的副作用(比如一笔退款)
        若残留到下一场,会污染 Impact 判定,复现率也就没有意义了。
        """
