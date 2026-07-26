"""ScriptedProvider —— 确定性、零成本的假 LLM。

用途:
  * 单元测试 / CI:不联网、不花钱、结果完全可复现;
  * W1–W2 开发期:执行器、检测器、预算管理、基线控制器都能在没有 API key
    的情况下完整开发和验证。

它不模拟"模型有多聪明",只负责按脚本吐字符串——
靶场行为是否真实,要等 W2 末接真 API 才能校准。
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence

from redcell.llm.base import LLMMessage, LLMProvider, LLMProviderExhaustedError, LLMResponse


class ScriptedRule:
    """当最后一条 user 消息匹配 pattern 时,返回 response。"""

    def __init__(self, pattern: str, response: str, *, flags: int = re.IGNORECASE) -> None:
        self.pattern = re.compile(pattern, flags)
        self.response = response

    def matches(self, text: str) -> bool:
        return self.pattern.search(text) is not None


class ScriptedProvider(LLMProvider):
    """按脚本返回预设回复。

    三种模式可叠加,优先级从高到低:
      1. `rules`      —— 按最后一条 user 消息做正则匹配;
      2. `responses`  —— 按调用顺序逐条返回;
      3. `default`    —— 兜底。

    三者都不命中且 responses 已耗尽时抛 LLMProviderExhaustedError:
    测试里"比预期多调了一次 LLM"是需要暴露的问题,不该被静默吞掉。
    """

    def __init__(
        self,
        responses: Sequence[str] | None = None,
        *,
        rules: Iterable[ScriptedRule] | None = None,
        default: str | None = None,
        model: str = "scripted",
        tokens_per_call: tuple[int, int] = (0, 0),
    ) -> None:
        self._responses = list(responses or [])
        self._rules = list(rules or [])
        self._default = default
        self._model = model
        self._prompt_tokens, self._completion_tokens = tokens_per_call
        self._cursor = 0
        self.calls: list[list[LLMMessage]] = []
        """记录每次调用收到的完整消息,供测试断言"引擎到底发了什么"。"""

    @property
    def name(self) -> str:
        return "scripted"

    @property
    def call_count(self) -> int:
        return len(self.calls)

    @property
    def remaining(self) -> int:
        return max(0, len(self._responses) - self._cursor)

    def reset(self) -> None:
        self._cursor = 0
        self.calls.clear()

    async def complete(
        self,
        messages: list[LLMMessage],
        *,
        model: str | None = None,
        temperature: float = 0.0,
        max_tokens: int | None = None,
    ) -> LLMResponse:
        self.calls.append(list(messages))
        content = self._resolve(messages)
        return LLMResponse(
            content=content,
            model=model or self._model,
            prompt_tokens=self._prompt_tokens,
            completion_tokens=self._completion_tokens,
            raw={"provider": "scripted", "call_index": len(self.calls) - 1},
        )

    def _resolve(self, messages: list[LLMMessage]) -> str:
        last_user = next(
            (m.content for m in reversed(messages) if m.role.value == "user"),
            "",
        )
        for rule in self._rules:
            if rule.matches(last_user):
                return rule.response

        if self._cursor < len(self._responses):
            content = self._responses[self._cursor]
            self._cursor += 1
            return content

        if self._default is not None:
            return self._default

        raise LLMProviderExhaustedError(
            f"ScriptedProvider 的预设回复已用尽(第 {len(self.calls)} 次调用),"
            "且没有配置 rules 或 default。检查被测代码是否比预期多调了 LLM。"
        )
