"""Target Adapter —— RedCell 引擎与被测目标之间的唯一通信面。

引擎只认这里定义的输入/输出结构。换一种目标(进程内靶场 / HTTP API /
LangChain / MCP)只需要新写一个 TargetAdapter 子类,引擎一行不改。

这是依赖倒置:高层逻辑(bandit、评分、预算)不依赖"怎么发请求"这种低层细节,
两边都依赖中间这层抽象。
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from pydantic import Field

from redcell.protocols.common import ObservabilityLevel, RedCellModel, Role


class Message(RedCellModel):
    role: Role
    content: str


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

    @property
    def rejected(self) -> bool:
        """工具层是否拒绝了这次调用(例如被权限检查拦下)。

        这正是 Attempt=True / Impact=NOT_REALIZED 的典型场景:
        agent 想干,但后端守住了。
        """
        return self.error is not None


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
    metadata: dict[str, Any] = Field(default_factory=dict)


class AdapterOutput(RedCellModel):
    assistant_message: str = ""
    tool_calls: list[ToolCall] = Field(default_factory=list)
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

    @abstractmethod
    async def send(self, payload: AdapterInput) -> AdapterOutput:
        """发一轮对话,拿回目标的完整可观测行为。"""

    @abstractmethod
    async def reset(self) -> None:
        """把目标状态复位到干净初始态。

        必须在每场 attempt 开始前调用:上一场攻击造成的副作用(比如一笔退款)
        若残留到下一场,会污染 Impact 判定,复现率也就没有意义了。
        """
