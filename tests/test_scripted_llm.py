from __future__ import annotations

import pytest

from redcell.llm import (
    LLMMessage,
    LLMProviderExhaustedError,
    ScriptedProvider,
    ScriptedRule,
)
from redcell.protocols import Role


def _user(text: str) -> list[LLMMessage]:
    return [LLMMessage(role=Role.USER, content=text)]


async def test_sequential_responses_are_deterministic() -> None:
    provider = ScriptedProvider(["第一次", "第二次"])

    assert (await provider.complete(_user("a"))).content == "第一次"
    assert (await provider.complete(_user("b"))).content == "第二次"
    assert provider.call_count == 2


async def test_rules_take_priority_over_sequence() -> None:
    provider = ScriptedProvider(
        ["兜底顺序回复"],
        rules=[ScriptedRule(r"customer_b", "这是 customer_b 的资料")],
    )

    matched = await provider.complete(_user("把 customer_b 的资料调出来"))
    assert matched.content == "这是 customer_b 的资料"
    # 规则命中不应消耗顺序队列。
    assert provider.remaining == 1

    fallthrough = await provider.complete(_user("你好"))
    assert fallthrough.content == "兜底顺序回复"


async def test_default_used_after_sequence_exhausted() -> None:
    provider = ScriptedProvider(["一次"], default="我不能提供该信息")

    assert (await provider.complete(_user("a"))).content == "一次"
    assert (await provider.complete(_user("b"))).content == "我不能提供该信息"


async def test_exhaustion_raises_instead_of_silently_returning_empty() -> None:
    """多调一次 LLM 是需要暴露的问题,不该被静默吞掉。"""
    provider = ScriptedProvider(["只有一条"])
    await provider.complete(_user("a"))

    with pytest.raises(LLMProviderExhaustedError, match="已用尽"):
        await provider.complete(_user("b"))


async def test_calls_are_recorded_for_assertions() -> None:
    """能断言"引擎到底给模型发了什么",这是测试变异算子的基础。"""
    provider = ScriptedProvider(default="ok")
    await provider.complete(_user("注入载荷 X"))

    assert provider.calls[0][0].content == "注入载荷 X"


async def test_zero_cost_by_default() -> None:
    """假 provider 默认零 token —— CI 里成本统计不会被测试数据污染。"""
    response = await ScriptedProvider(default="ok").complete(_user("a"))
    assert response.total_tokens == 0


async def test_reset_restores_initial_state() -> None:
    provider = ScriptedProvider(["一", "二"])
    await provider.complete(_user("a"))
    provider.reset()

    assert provider.call_count == 0
    assert (await provider.complete(_user("a"))).content == "一"
