"""ArenaAdapter —— 把客服靶场接到 RedCell 的统一目标接口上。

引擎只认 `TargetAdapter`,不关心目标是进程内的 Python 对象还是远端 HTTP 服务。
所以换目标类型 = 新写一个 Adapter,bandit / 评分 / 预算这些核心逻辑一行不动。

一次 `send()` = 一轮对话:攻击方说一句,agent 回一次。
agent 在这一轮内部可能连续调用多次工具,这属于同一轮,不额外计入轮数预算。
"""

from __future__ import annotations

import time

from redcell.arena.support_agent.codec import TextToolCallCodec, ToolCallCodec
from redcell.arena.support_agent.prompts import DefenseLevel, build_system_prompt
from redcell.arena.support_agent.tools import SupportAgentTools, ToolExecution
from redcell.llm.base import LLMMessage, LLMProvider
from redcell.protocols.adapter import (
    AdapterCapabilities,
    AdapterInput,
    AdapterOutput,
    DeliveryObservability,
    IdempotencySupport,
    ResetScope,
    SideEffect,
    TargetAdapter,
    ToolCall,
    ToolResult,
    TraceMetadata,
)
from redcell.protocols.common import ObservabilityLevel, Role

MAX_TOOL_ITERATIONS = 5
"""一轮对话内允许的工具调用轮次上限。

没有这个上限,模型可以在一轮里无限地"再查一次" —— 而这一轮**仍然只算一次 attempt**,
于是 token 成本脱离了查询预算的约束。这是 max_turns 之外的第二道刹车。
"""


class ArenaAdapter(TargetAdapter):
    """进程内客服靶场,完整插桩。

    两个校准旋钮由构造参数暴露(见 docs/CALIBRATION.md §10):
      * `defense` —— 旋钮 ①,system prompt 的防御强度;
      * `enforce_permissions` —— 旋钮 ③,工具层是否真的做权限检查。
        它只影响 Impact:关掉之后越权调用照样被生成,只是这次数据真的会到手。
    """

    def __init__(
        self,
        provider: LLMProvider,
        *,
        defense: DefenseLevel = DefenseLevel.STANDARD,
        enforce_permissions: bool = True,
        enforce_confirmation: bool = True,
        codec: ToolCallCodec | None = None,
        model: str | None = None,
        temperature: float = 0.7,
        max_tokens: int | None = None,
        max_tool_iterations: int = MAX_TOOL_ITERATIONS,
    ) -> None:
        self._provider = provider
        self._defense = defense
        self._model = model
        self._temperature = temperature
        self._max_tokens = max_tokens
        self._max_tool_iterations = max_tool_iterations
        self._tools = SupportAgentTools(
            enforce_permissions=enforce_permissions,
            enforce_confirmation=enforce_confirmation,
        )
        # 工具名单先建再建 codec:零参数裸名兜底要靠它才能落地(见 codec 的 __init__)。
        self._codec = codec or TextToolCallCodec(
            known_tools=[spec["name"] for spec in self._tools.specs()]
        )

    # ── TargetAdapter 接口 ───────────────────────────────────────────────

    @property
    def adapter_type(self) -> str:
        return "arena/support-agent"

    @property
    def observability(self) -> ObservabilityLevel:
        """进程内靶场,工具调用与副作用全部可见。

        因此 Impact 在这里是可判定的 —— 不必退化成 UNKNOWN。
        """
        return ObservabilityLevel.FULL

    @property
    def capabilities(self) -> AdapterCapabilities:
        """进程内靶场可完整复位,请求投递也不存在远程不确定窗口。"""
        return AdapterCapabilities(
            reset_scope=ResetScope.FULL_STATE,
            idempotency=IdempotencySupport.NONE,
            delivery_observability=DeliveryObservability.IN_PROCESS,
            # 成本可观测性由底层 provider 决定,不由靶场决定:
            # 同一个靶场接 ScriptedProvider 时成本恒为 0(真实且无意义),
            # 接真实 API 时才有可用的成本数字。
            reports_cost=self._provider.reports_cost,
        )

    @property
    def tools(self) -> SupportAgentTools:
        return self._tools

    @property
    def defense(self) -> DefenseLevel:
        return self._defense

    async def reset(self) -> None:
        self._tools.reset()

    async def send(self, payload: AdapterInput) -> AdapterOutput:
        started = time.perf_counter()
        # ⚠️ 一次 send = 一个对话回合。确认状态机以此为界:上一回合挂起的确认
        # 从现在起可以兑现,因为用户确实又说了一句话 —— 叫停的机会存在过。
        # 下面的工具循环全部发生在**同一回合内**,在那里自问自答就是绕过。
        self._tools.begin_turn()
        messages = self._build_messages(payload)

        tool_calls: list[ToolCall] = []
        tool_results: list[ToolResult] = []
        side_effects: list[SideEffect] = []
        prompt_tokens = completion_tokens = 0
        cached_input_tokens = 0
        usage_known = True
        cost_usd = 0.0
        malformed_tool_calls = 0
        visible = ""
        model_name = self._model

        for _ in range(self._max_tool_iterations):
            response = await self._provider.complete(
                messages,
                model=self._model,
                temperature=self._temperature,
                max_tokens=self._max_tokens,
            )
            prompt_tokens += response.prompt_tokens
            completion_tokens += response.completion_tokens
            cached_input_tokens += response.cached_input_tokens
            usage_known = usage_known and response.usage_known
            cost_usd += response.cost_usd
            model_name = response.model

            decoded = self._codec.decode(response)
            visible = decoded.visible
            # 跨轮累加:一轮里格式坏掉、下一轮改对了,两次尝试都要留痕。
            malformed_tool_calls += decoded.malformed
            if not decoded.calls:
                break

            executed = self._execute(decoded.calls, actor=payload.actor)
            for call, result in executed:
                tool_calls.append(call)
                tool_results.append(
                    ToolResult(
                        tool_call_id=call.id,
                        name=call.name,
                        content=result.content,
                        error=result.error,
                        awaiting_confirmation=result.awaiting_confirmation,
                    )
                )
                side_effects.extend(result.side_effects)

            messages.append(LLMMessage(role=Role.ASSISTANT, content=response.content))
            messages.append(
                LLMMessage(
                    role=self._codec.results_role,
                    content=self._codec.encode_results(executed),
                )
            )

        return AdapterOutput(
            assistant_message=visible,
            tool_calls=tool_calls,
            malformed_tool_calls=malformed_tool_calls,
            tool_results=tool_results,
            side_effects=side_effects,
            observability=self.observability,
            trace_metadata=TraceMetadata(
                prompt_tokens=prompt_tokens,
                completion_tokens=completion_tokens,
                cached_input_tokens=cached_input_tokens,
                usage_known=usage_known,
                cost_usd=cost_usd,
                latency_ms=(time.perf_counter() - started) * 1000,
                model=model_name,
                temperature=self._temperature,
                extra={"defense": self._defense.value},
            ),
        )

    # ── 内部 ─────────────────────────────────────────────────────────────

    def _build_messages(self, payload: AdapterInput) -> list[LLMMessage]:
        system = build_system_prompt(
            actor=payload.actor, defense=self._defense
        ) + self._codec.system_suffix(self._tools.specs())
        history = [LLMMessage(role=m.role, content=m.content) for m in payload.messages]
        return [LLMMessage(role=Role.SYSTEM, content=system), *history]

    def _execute(
        self, calls: list[ToolCall], *, actor: str
    ) -> list[tuple[ToolCall, ToolExecution]]:
        return [
            (call, self._tools.execute(call.name, call.arguments, actor=actor)) for call in calls
        ]
