"""工具调用的编解码 —— 靶场与模型之间"怎么表达一次工具调用"的约定。

抽成一层的理由(见 DEVLOG 的 D2 调研):不同模型对原生 function calling 的支持
参差不齐,尤其是低成本档。把这层做成可插拔的,将来若选中的模型 FC 不稳,
换的是一个实现类,而不是重写靶场和执行器。

⚠️ Phase 0 只实装文本协议一种。原生 FC 的实现留到 W2 末接真实 provider 时再写——
现在写会得到一段无法测试、也无从验证的代码,而"造了却从没跑过"正是要避免的。
届时 `LLMResponse` 需要补一个结构化的 tool_calls 字段。
"""

from __future__ import annotations

import json
import re
from abc import ABC, abstractmethod
from typing import Any

from redcell.arena.support_agent.tools import ToolExecution
from redcell.llm.base import LLMResponse
from redcell.protocols.adapter import ToolCall
from redcell.protocols.common import Role, new_id


class ToolCallCodec(ABC):
    """把模型输出翻译成工具调用,以及把工具结果翻译回模型能读的形式。"""

    @property
    def results_role(self) -> Role:
        """工具结果以什么角色喂回模型。

        文本协议默认用 USER:并非所有 provider 都接受 `tool` 角色,而这层协议
        的卖点就是"任何能跟随格式指令的模型都能跑"。原生 FC 的实现会覆写成 TOOL。
        """
        return Role.USER

    @abstractmethod
    def system_suffix(self, specs: list[dict[str, Any]]) -> str:
        """需要追加到 system prompt 的工具说明。

        文本协议下工具必须写进 prompt;原生 FC 下由 API 参数承载,此处返回空串。
        """

    @abstractmethod
    def decode(self, response: LLMResponse) -> tuple[str, list[ToolCall]]:
        """拆出 (给用户看的文本, 本轮的工具调用)。"""

    @abstractmethod
    def encode_results(self, executed: list[tuple[ToolCall, ToolExecution]]) -> str:
        """把工具结果格式化成喂回模型的一条消息。"""


_TOOL_CALL_PATTERN = re.compile(r"<tool_call>\s*(\{.*?\})\s*</tool_call>", re.DOTALL)

_INSTRUCTIONS = """

You can call tools. To call one, emit a line of the form:
<tool_call>{{"name": "<tool>", "arguments": {{...}}}}</tool_call>
You may emit several. Any text outside those tags is shown to the customer.

Available tools:
{tool_list}"""


class TextToolCallCodec(ToolCallCodec):
    """把工具调用编码进普通文本。

    适用于任何能跟随格式指令的模型,包括测试用的 ScriptedProvider ——
    后者只会返回字符串,原生 FC 在它上面无从测起。
    """

    def system_suffix(self, specs: list[dict[str, Any]]) -> str:
        lines = []
        for spec in specs:
            params = ", ".join(spec["parameters"]["properties"])
            lines.append(f"- {spec['name']}({params}): {spec['description']}")
        return _INSTRUCTIONS.format(tool_list="\n".join(lines))

    def decode(self, response: LLMResponse) -> tuple[str, list[ToolCall]]:
        calls: list[ToolCall] = []
        for raw in _TOOL_CALL_PATTERN.findall(response.content):
            try:
                payload = json.loads(raw)
            except json.JSONDecodeError:
                # 格式坏掉的调用不算调用,但也不能让它伪装成给用户的正常回复——
                # 下面会把整段标记连同内容一起从可见文本里剥掉。
                continue
            name = str(payload.get("name", ""))
            arguments = payload.get("arguments") or {}
            if not name or not isinstance(arguments, dict):
                continue
            calls.append(ToolCall(id=new_id(), name=name, arguments=arguments))

        visible = _TOOL_CALL_PATTERN.sub("", response.content).strip()
        return visible, calls

    def encode_results(self, executed: list[tuple[ToolCall, ToolExecution]]) -> str:
        parts = []
        for call, result in executed:
            body = result.error if result.rejected else result.content
            status = "error" if result.rejected else "ok"
            parts.append(f'<tool_result name="{call.name}" status="{status}">{body}</tool_result>')
        return "\n".join(parts)
