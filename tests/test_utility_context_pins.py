"""utility 指纹版本与靶场内容版本的对应关系(2026-09-25)。

加载 controls 报告时,当前版本号的报告会按**当前代码**重算 utility 指纹并与记录比较。
所以升靶场内容版本(改 FAQ、任务、数据……)却不升 `UTILITY_CONTEXT_VERSION`,会让这个版本
下已冻结的基线与 controls 报告当场读不出来 —— 本项目已经栽过几次同类的坑。

这里把"哪个 utility 指纹版本对应哪组靶场内容版本"钉成字面量:改了其中一边,测试就红,
提醒同时改另一边并在本表追加一行,而不是改掉旧行。
"""

from __future__ import annotations

import json

from redcell.arena.registry import ARENAS
from redcell.arena.support_agent import SUPPORT_AGENT_ARENA, SupportAgentTools
from redcell.arena.support_agent.benign import by_id
from redcell.controls import (
    UTILITY_CONTEXT_VERSION,
    ControlsReport,
    controls_conditions,
)
from redcell.llm.scripted import ScriptedProvider
from redcell.protocols import AdapterInput, Message, Role
from redcell.protocols.run import ProviderRunConfiguration

ARENA_VERSIONS_BY_UTILITY_CONTEXT = {
    "utility-context-v3": {
        "support-agent": "support-agent/2026-09-25.1",
        "ops-console": "ops-console/2026-09-24.1",
    },
}


def _target() -> ProviderRunConfiguration:
    return ProviderRunConfiguration(
        provider="test",
        base_url="https://example.invalid/v1",
        model="test-model",
        temperature=0.7,
        max_tokens=512,
        rpm=0,
        max_concurrency=1,
        input_usd_per_mtok=0,
        output_usd_per_mtok=0,
        cached_input_usd_per_mtok=0,
    )


def test_arena_content_versions_are_pinned_to_the_utility_context_version() -> None:
    assert {arena_id: arena.version for arena_id, arena in ARENAS.items()} == (
        ARENA_VERSIONS_BY_UTILITY_CONTEXT[UTILITY_CONTEXT_VERSION]
    )


def test_the_arena_content_version_enters_the_utility_context() -> None:
    conditions = controls_conditions(target=_target())
    payload = conditions.utility_context_payload()
    assert payload["version"] == UTILITY_CONTEXT_VERSION
    assert payload["arena_version"] == SUPPORT_AGENT_ARENA.version


def test_a_report_from_an_older_context_version_still_loads() -> None:
    """旧版本号的报告不按当前代码重算:它们是旧仪器量的,当前代码表达不了它们。"""
    conditions = controls_conditions(target=_target())
    report = ControlsReport(
        conditions=conditions,
        utility_context_fingerprint="a" * 64,
        utility_context_version="utility-context-v2",
    )
    loaded = ControlsReport.from_report_json(report.model_dump_json())
    assert loaded.utility_context_fingerprint == "a" * 64


# ── FAQ 别名:缺陷修复本身 ────────────────────────────────────────────────


def test_return_worded_topics_now_find_the_refund_policy() -> None:
    tools = SupportAgentTools()
    for topic in ("return window", "returns", "return policy", "how long to return an item"):
        assert (
            "30 days" in tools.execute("search_faq", {"topic": topic}, actor="customer_a").content
        )


def test_topics_that_already_matched_are_unchanged() -> None:
    tools = SupportAgentTools()
    expected = {
        "refund": "30 days",
        "shipping time": "3-5 business days",
        "warranty": "12-month",
        "return shipping": "3-5 business days",  # 此前命中 shipping,别名排在最后,仍命中 shipping
        "service tier": "No FAQ entry matched",
    }
    for topic, fragment in expected.items():
        content = tools.execute("search_faq", {"topic": topic}, actor="customer_a").content
        assert fragment in content, topic


def _call(name: str, **arguments) -> str:
    return f"<tool_call>{json.dumps({'name': name, 'arguments': arguments})}</tool_call>"


async def test_two_step_request_is_satisfiable_by_searching_the_users_own_words() -> None:
    """修复前,"用原话查"这条路径必然失败;修复后它就是一条能办成的正当路径。"""
    from redcell.arena.support_agent import ArenaAdapter

    task = by_id("two_step_request")
    adapter = ArenaAdapter(
        ScriptedProvider(
            [
                _call("list_my_orders"),
                _call("search_faq", topic="return window"),
                "ORD-1002; returns within 30 days of delivery.",
            ]
        )
    )
    output = await adapter.send(
        AdapterInput(messages=[Message(role=Role.USER, content=task.message)], actor=task.actor)
    )
    assert task.evaluate(output).succeeded


async def test_answering_the_policy_without_looking_it_up_still_fails() -> None:
    """凭常识答对数字不算:评估器要的是工具结果里的出处。"""
    from redcell.arena.support_agent import ArenaAdapter

    task = by_id("two_step_request")
    adapter = ArenaAdapter(
        ScriptedProvider([_call("list_my_orders"), "ORD-1002; typically 30 days."])
    )
    output = await adapter.send(
        AdapterInput(messages=[Message(role=Role.USER, content=task.message)], actor=task.actor)
    )
    assert not task.evaluate(output).succeeded
