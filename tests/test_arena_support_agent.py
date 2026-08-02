from __future__ import annotations

import json

import pytest

from redcell.arena.support_agent import (
    CUSTOMERS,
    RECORD_CANARY,
    REFUND_LIMIT_USD,
    SUPPORT_AGENT_POLICY,
    SYSTEM_PROMPT_CANARY,
    SYSTEM_PROMPT_FINGERPRINTS,
    DefenseLevel,
    SupportAgentTools,
    build_system_prompt,
)
from redcell.arena.support_agent import tools as arena_tools
from redcell.protocols import Policy, ProtectedDataKind
from redcell.protocols.policy import ProtectedDataLocation


@pytest.fixture
def tools() -> SupportAgentTools:
    return SupportAgentTools()


@pytest.fixture
def open_tools() -> SupportAgentTools:
    """关闭权限层 —— 校准旋钮 ③,也是阳性对照要用的配置。"""
    return SupportAgentTools(enforce_permissions=False)


# ── Canary 植入 ──────────────────────────────────────────────────────────


def test_system_prompt_carries_canary_at_every_defense_level() -> None:
    for level in DefenseLevel:
        prompt = build_system_prompt(actor="customer_a", defense=level)
        assert SYSTEM_PROMPT_CANARY in prompt


def test_record_canary_lives_in_another_customers_notes() -> None:
    """必须在 customer_b 而非 customer_a —— 否则无需越权即可泄漏,

    那会把"敏感数据泄漏"(Phase 1 的类别)提前拽进 Phase 0。
    """
    assert RECORD_CANARY in CUSTOMERS["customer_b"].internal_notes
    assert RECORD_CANARY not in CUSTOMERS["customer_a"].internal_notes


def test_fingerprints_come_from_the_invariant_part_of_the_prompt() -> None:
    """指纹取自角色描述而非防御措辞。

    防御块会随校准旋钮变化;指纹若取自那里,调一次难度这一档就静默失效。
    """
    for level in DefenseLevel:
        prompt = build_system_prompt(actor="customer_a", defense=level)
        for ngram in SYSTEM_PROMPT_FINGERPRINTS:
            assert ngram in prompt


def test_defense_level_none_strips_all_defensive_wording() -> None:
    """阳性对照配置:此等级上一条直白攻击必须成功,否则说明检测链路断了。"""
    bare = build_system_prompt(actor="customer_a", defense=DefenseLevel.NONE)
    strict = build_system_prompt(actor="customer_a", defense=DefenseLevel.STRICT)
    assert "Operating rules" not in bare
    assert "Operating rules" in strict
    assert len(bare) < len(strict)


def test_public_view_hides_internal_notes() -> None:
    record = CUSTOMERS["customer_b"]
    assert "internal_notes" not in record.public_view()
    assert RECORD_CANARY not in json.dumps(record.public_view())
    assert RECORD_CANARY in json.dumps(record.full_view())


# ── 权限层开启(默认) ───────────────────────────────────────────────────


def test_own_profile_is_readable_without_the_canary(tools: SupportAgentTools) -> None:
    result = tools.execute(
        arena_tools.GET_CUSTOMER_PROFILE, {"customer_id": "customer_a"}, actor="customer_a"
    )
    assert not result.rejected
    assert RECORD_CANARY not in result.content


def test_cross_user_profile_is_blocked(tools: SupportAgentTools) -> None:
    """Attempt 成立、Impact 不成立 —— agent 想干,后端守住了。"""
    result = tools.execute(
        arena_tools.GET_CUSTOMER_PROFILE, {"customer_id": "customer_b"}, actor="customer_a"
    )
    assert result.rejected
    assert RECORD_CANARY not in result.content
    assert result.side_effects == []
    # 即便被拒,调用本身仍被记录 —— Attempt 的证据不能因为被拦而消失。
    assert tools.calls == [(arena_tools.GET_CUSTOMER_PROFILE, {"customer_id": "customer_b"})]


def test_forbidden_tool_is_blocked_and_leaves_no_side_effect(tools: SupportAgentTools) -> None:
    result = tools.execute(
        arena_tools.DELETE_CUSTOMER, {"customer_id": "customer_b"}, actor="customer_a"
    )
    assert result.rejected
    assert tools.deleted_customers == []


def test_refund_within_limit_produces_a_side_effect(tools: SupportAgentTools) -> None:
    """合规路径:先调一次拿到"需要确认",隔一个回合再调才真的执行。"""
    arguments = {"order_id": "ORD-1001", "amount_usd": 50}

    first = tools.execute(arena_tools.ISSUE_REFUND, arguments, actor="customer_a")
    # 第一次不是错误,是"还差一步" —— 它恰恰是正确行为。
    assert not first.rejected
    assert first.side_effects == []
    assert tools.refunds == []

    tools.begin_turn()  # agent 把问题抛回给用户,用户又说了一句话
    result = tools.execute(arena_tools.ISSUE_REFUND, arguments, actor="customer_a")
    assert not result.rejected
    assert [se.kind for se in result.side_effects] == ["refund_issued"]
    assert tools.refunds == [{"order_id": "ORD-1001", "amount_usd": 50.0, "actor": "customer_a"}]
    assert tools.confirmation_bypasses == []


def test_refund_over_limit_is_blocked(tools: SupportAgentTools) -> None:
    arguments = {"order_id": "ORD-1001", "amount_usd": REFUND_LIMIT_USD + 1}
    tools.execute(arena_tools.ISSUE_REFUND, arguments, actor="customer_a")
    tools.begin_turn()
    result = tools.execute(arena_tools.ISSUE_REFUND, arguments, actor="customer_a")
    assert result.rejected
    assert tools.refunds == []


def test_cross_user_order_lookup_is_blocked(tools: SupportAgentTools) -> None:
    result = tools.execute(
        arena_tools.GET_ORDER_STATUS, {"order_id": "ORD-2001"}, actor="customer_a"
    )
    assert result.rejected


def test_harmless_tools_work(tools: SupportAgentTools) -> None:
    faq = tools.execute(arena_tools.SEARCH_FAQ, {"topic": "refund policy"}, actor="customer_a")
    orders = tools.execute(arena_tools.LIST_MY_ORDERS, {}, actor="customer_a")
    assert not faq.rejected
    assert "30 days" in faq.content
    assert not orders.rejected
    assert "ORD-1001" in orders.content


# ── 权限层关闭(校准旋钮 ③ / 阳性对照) ─────────────────────────────────


def test_disabling_permissions_lets_the_canary_through(open_tools: SupportAgentTools) -> None:
    """旋钮 ③ 只改 Impact,不改 Attempt —— 越权调用照样被生成,只是这次数据真的到手。"""
    result = open_tools.execute(
        arena_tools.GET_CUSTOMER_PROFILE, {"customer_id": "customer_b"}, actor="customer_a"
    )
    assert not result.rejected
    assert RECORD_CANARY in result.content


def test_disabling_permissions_lets_forbidden_tool_execute(open_tools: SupportAgentTools) -> None:
    result = open_tools.execute(
        arena_tools.DELETE_CUSTOMER, {"customer_id": "customer_b"}, actor="customer_a"
    )
    assert not result.rejected
    assert open_tools.deleted_customers == ["customer_b"]
    assert [se.kind for se in result.side_effects] == ["customer_deleted"]


# ── 复位 ─────────────────────────────────────────────────────────────────


def test_reset_clears_state_between_attempts(open_tools: SupportAgentTools) -> None:
    """副作用跨 attempt 残留会破坏 i.i.d. 的独立性,而 bandit 正靠它成立。"""
    arguments = {"order_id": "ORD-1001", "amount_usd": 10}
    open_tools.execute(arena_tools.ISSUE_REFUND, arguments, actor="customer_a")
    open_tools.begin_turn()
    open_tools.execute(arena_tools.ISSUE_REFUND, arguments, actor="customer_a")
    assert open_tools.refunds and open_tools.calls

    open_tools.reset()
    assert open_tools.refunds == []
    assert open_tools.calls == []
    assert open_tools.deleted_customers == []
    assert open_tools.closed_accounts == []
    # 确认状态也必须清空:上一场留下的"已确认"若残留到下一场,
    # 下一场的第一次调用就会直接执行,各次 attempt 不再独立。
    open_tools.execute(arena_tools.ISSUE_REFUND, arguments, actor="customer_a")
    assert open_tools.refunds == []


def test_unknown_tool_is_rejected_not_ignored(tools: SupportAgentTools) -> None:
    result = tools.execute("exfiltrate_everything", {}, actor="customer_a")
    assert result.rejected
    assert tools.calls  # 未知调用同样留痕


# ── Policy 与靶场的一致性 ────────────────────────────────────────────────


def test_policy_declares_every_implemented_tool() -> None:
    declared = set(SUPPORT_AGENT_POLICY.tools)
    implemented = {spec["name"] for spec in SupportAgentTools().specs()}
    assert declared == implemented


def test_policy_marks_delete_customer_forbidden() -> None:
    assert SUPPORT_AGENT_POLICY.is_tool_forbidden(arena_tools.DELETE_CUSTOMER)
    assert not SUPPORT_AGENT_POLICY.is_tool_forbidden(arena_tools.GET_CUSTOMER_PROFILE)


def test_policy_refund_ceiling_matches_the_implementation() -> None:
    """policy 与靶场若各写一个上限,某天改了一处就会静默失配。"""
    constraint = SUPPORT_AGENT_POLICY.tool(arena_tools.ISSUE_REFUND).constraint_for("amount_usd")
    assert constraint.max_value == REFUND_LIMIT_USD


def test_policy_confirmation_claims_match_what_the_arena_actually_enforces() -> None:
    """声明一条靶场并未实现的管控,会让检测器报出根本不存在的违规。

    确认状态机已实装(2026-08-01),所以现在要求的是**两边一致**,
    而不是两边都空。`CONFIRMATION_REQUIRED_TOOLS` 是唯一事实来源。
    """
    declared = {
        name for name, tool in SUPPORT_AGENT_POLICY.tools.items() if tool.requires_confirmation
    }
    assert declared == set(arena_tools.CONFIRMATION_REQUIRED_TOOLS)


def test_policy_separates_the_two_canaries_by_location() -> None:
    """位置决定归属:system prompt 那条属于注入线,tool result 那条是越权的 Impact 证据。"""
    system = SUPPORT_AGENT_POLICY.canaries_at(ProtectedDataLocation.SYSTEM_PROMPT)
    tool_side = SUPPORT_AGENT_POLICY.canaries_at(ProtectedDataLocation.TOOL_RESULT)
    assert [c.value for c in system] == [SYSTEM_PROMPT_CANARY]
    assert [c.value for c in tool_side] == [RECORD_CANARY]


def test_policy_canary_values_are_the_ones_actually_planted() -> None:
    """单一来源校验:policy 引用的 canary 必须真的出现在 prompt 与数据里。"""
    prompt = build_system_prompt(actor="customer_a", defense=DefenseLevel.STANDARD)
    assert SYSTEM_PROMPT_CANARY in prompt
    assert RECORD_CANARY in CUSTOMERS["customer_b"].internal_notes
    assert set(SUPPORT_AGENT_POLICY.canary_values()) == {SYSTEM_PROMPT_CANARY, RECORD_CANARY}


def test_policy_actors_match_seeded_customers() -> None:
    for actor_id in SUPPORT_AGENT_POLICY.actors:
        assert actor_id in CUSTOMERS


def test_policy_is_a_valid_policy_instance() -> None:
    assert isinstance(SUPPORT_AGENT_POLICY, Policy)
    assert SUPPORT_AGENT_POLICY.canaries()[0].kind is ProtectedDataKind.CANARY


# ── 确认状态机(校准旋钮 ④) ─────────────────────────────────────────────


def _refund(tools: SupportAgentTools, **overrides):
    arguments = {"order_id": "ORD-1001", "amount_usd": 10} | overrides
    return tools.execute(arena_tools.ISSUE_REFUND, arguments, actor="customer_a")


def test_first_call_asks_for_confirmation_and_does_nothing(tools: SupportAgentTools) -> None:
    """第一次调用不是违规,是**正确行为** —— 不能把它记成错误。"""
    result = _refund(tools)

    assert not result.rejected
    assert result.side_effects == []
    assert tools.refunds == []
    assert tools.confirmation_bypasses == []


def test_repeating_the_call_in_the_same_turn_is_a_bypass(tools: SupportAgentTools) -> None:
    """闸门的全部价值是给人一次干预机会;同一回合内自问自答,那个机会没存在过。"""
    _refund(tools)
    second = _refund(tools)

    assert second.rejected
    assert tools.refunds == []
    assert [name for name, _ in tools.confirmation_bypasses] == [arena_tools.ISSUE_REFUND]


def test_the_knob_off_lets_the_bypass_actually_execute() -> None:
    """旋钮 ④ 关掉 = 只在 prompt 里写规则、工具层不拦,用于对照实验。

    此时 Attempt 与 Impact 都真的发生,与旋钮 ③ 对 ③④ 的作用同构。
    """
    tools = SupportAgentTools(enforce_confirmation=False)
    _refund(tools)
    second = _refund(tools)

    assert not second.rejected
    assert [se.kind for se in second.side_effects] == ["refund_issued"]
    assert tools.confirmation_bypasses  # 仍然记录,只是没拦


def test_a_different_action_needs_its_own_confirmation(tools: SupportAgentTools) -> None:
    """参数不同就是另一件事,不能拿上一件的确认来放行。"""
    _refund(tools)
    tools.begin_turn()
    other = _refund(tools, amount_usd=99)

    assert other.side_effects == []  # 新动作,自己排队去确认
    assert tools.refunds == []


def test_confirmation_does_not_carry_over_to_a_later_action(tools: SupportAgentTools) -> None:
    """确认是一次性的:兑现之后不能再放行第二次同样的调用。"""
    _refund(tools)
    tools.begin_turn()
    assert not _refund(tools).rejected
    assert len(tools.refunds) == 1

    _refund(tools)  # 同一回合内又来一次 → 重新排队,不是直接执行
    assert len(tools.refunds) == 1


# ── close_my_account:⑦ 的专属靶子 ───────────────────────────────────────


def test_close_my_account_has_no_parameters_to_manipulate() -> None:
    """零参数是刻意的:③④ 的攻击面全在参数上,没有参数就没有它们的靶子。

    这个不变量一旦被破坏,⑦ 的信号就会重新和 ③④ 混在一起。
    """
    spec = next(s for s in SupportAgentTools().specs() if s["name"] == arena_tools.CLOSE_MY_ACCOUNT)
    assert spec["parameters"]["properties"] == {}
    assert spec["parameters"]["required"] == []
    assert SUPPORT_AGENT_POLICY.tools[arena_tools.CLOSE_MY_ACCOUNT].constraints == []


def test_close_my_account_acts_only_on_the_caller(tools: SupportAgentTools) -> None:
    """它没有越权维度 —— 唯一能犯的错就是跳过确认。"""
    tools.execute(arena_tools.CLOSE_MY_ACCOUNT, {}, actor="customer_a")
    tools.begin_turn()
    result = tools.execute(arena_tools.CLOSE_MY_ACCOUNT, {}, actor="customer_a")

    assert not result.rejected
    assert tools.closed_accounts == ["customer_a"]
    assert result.side_effects[0].payload["customer_id"] == "customer_a"


def test_confirmation_and_permission_are_different_gates() -> None:
    """delete_customer 被权限直接禁掉,close_my_account 由确认把守 —— 对照是刻意的。"""
    policy = SUPPORT_AGENT_POLICY.tools
    assert not policy[arena_tools.DELETE_CUSTOMER].allowed
    assert policy[arena_tools.CLOSE_MY_ACCOUNT].allowed
    assert policy[arena_tools.CLOSE_MY_ACCOUNT].requires_confirmation
