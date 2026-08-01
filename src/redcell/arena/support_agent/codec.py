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
from typing import Any, NamedTuple

from redcell.arena.support_agent.tools import ToolExecution
from redcell.llm.base import LLMResponse
from redcell.protocols.adapter import ToolCall
from redcell.protocols.common import Role, new_id


class DecodedReply(NamedTuple):
    """一次解码的结果。

    `malformed` 单独返回而不是丢掉,是因为**丢掉它会让两件完全不同的事变得无法区分**:
    "靶场防住了"和"模型不会按格式输出工具调用"都表现为零次工具调用。
    详见 `AdapterOutput.malformed_tool_calls`。
    """

    visible: str
    """去掉工具调用标记后,真正给用户看的文本。"""

    calls: list[ToolCall]
    """成功解析出来的工具调用。"""

    malformed: int
    """模型**尝试**调用但没能解析成功的次数。"""


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
    def decode(self, response: LLMResponse) -> DecodedReply:
        """拆出可见文本、工具调用,以及**解析失败的次数**。"""

    @abstractmethod
    def encode_results(self, executed: list[tuple[ToolCall, ToolExecution]]) -> str:
        """把工具结果格式化成喂回模型的一条消息。"""


_OPEN_TAG = "<tool_call>"
_CLOSE_TAG = "</tool_call>"
_DECODER = json.JSONDecoder()

_CLOSE_TAG_PATTERN = re.compile(re.escape(_CLOSE_TAG))

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

    def decode(self, response: LLMResponse) -> DecodedReply:
        """扫描 `<tool_call>` 标记,逐个解析出其后的 JSON 对象。

        ⚠️ **闭合标签 `</tool_call>` 是可选的。** 首版要求成对出现,结果在接入
        GLM-4.7-Flash 时发现:它会输出完全正确的
        `<tool_call>{"name": ..., "arguments": {...}}` 却**不带闭合标签** ——
        于是每一次正确的工具调用都被静默丢弃,在校准数据里伪装成"靶场防住了"。
        这属于 CALIBRATION §2 说的"靶场没跑通,该修 bug 而不是调难度"。

        用 `raw_decode` 而不是贪婪正则来定位 JSON 结束位置:后者在缺少闭合标签时
        无法判断对象到哪结束,可能把后面给用户看的正文一并吞掉。
        """
        content = response.content
        calls: list[ToolCall] = []
        kept: list[str] = []
        malformed = 0
        cursor = 0

        while (start := content.find(_OPEN_TAG, cursor)) != -1:
            kept.append(content[cursor:start])
            after_tag = start + len(_OPEN_TAG)
            brace = content.find("{", after_tag)
            payload: object = None
            end = -1
            if brace != -1:
                try:
                    payload, end = _DECODER.raw_decode(content, brace)
                except json.JSONDecodeError:
                    payload = None

            if payload is None:
                # 坏格式的调用不算调用,但也不能让标记漏进给用户看的正文——
                # 有闭合标签就连它一起吃掉,没有就只吃开标签。
                malformed += 1
                closing = _CLOSE_TAG_PATTERN.search(content, after_tag)
                cursor = closing.end() if closing else after_tag
                continue

            cursor = _consume_optional_close_tag(content, end)
            call = _as_tool_call(payload)
            if call is None:
                # JSON 合法但结构不对(缺 name、arguments 不是对象……)——
                # 模型**确实想调工具**,只是我们用不了。同样要计数。
                malformed += 1
            else:
                calls.append(call)

        kept.append(content[cursor:])
        return DecodedReply(visible="".join(kept).strip(), calls=calls, malformed=malformed)

    def encode_results(self, executed: list[tuple[ToolCall, ToolExecution]]) -> str:
        parts = []
        for call, result in executed:
            body = result.error if result.rejected else result.content
            status = "error" if result.rejected else "ok"
            parts.append(f'<tool_result name="{call.name}" status="{status}">{body}</tool_result>')
        return "\n".join(parts)


def _as_tool_call(payload: object) -> ToolCall | None:
    """把解析出来的 JSON 转成 ToolCall;结构不合用就返回 None(计为坏格式)。"""
    if not isinstance(payload, dict):
        return None
    name = str(payload.get("name", ""))
    arguments = payload.get("arguments") or {}
    if not name or not isinstance(arguments, dict):
        return None
    return ToolCall(id=new_id(), name=name, arguments=arguments)


def _consume_optional_close_tag(content: str, end: int) -> int:
    """JSON 对象之后若紧跟 `</tool_call>`(允许中间有空白),把它一并吃掉。"""
    rest = content[end:]
    stripped = rest.lstrip()
    if stripped.startswith(_CLOSE_TAG):
        return end + (len(rest) - len(stripped)) + len(_CLOSE_TAG)
    return end
