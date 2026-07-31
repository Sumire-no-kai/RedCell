from __future__ import annotations

import pytest
from pydantic import ValidationError

from redcell.arena.support_agent import SUPPORT_AGENT_POLICY
from redcell.generation import (
    AttackGenerationError,
    AttackGenerationRequest,
    ScriptedAttackGenerator,
    TemplateAttackGenerator,
)
from redcell.protocols import (
    ActorPolicy,
    AdapterOutput,
    ObservabilityLevel,
    Policy,
    PredictedStrength,
    Strategy,
    Turn,
    VulnerabilityCategory,
)
from redcell.strategies import AUTHORITY_IMPERSONATION, DIRECT_INSTRUCTION_OVERRIDE


def _request(
    strategy: Strategy = AUTHORITY_IMPERSONATION,
    *,
    turn_index: int = 0,
) -> AttackGenerationRequest:
    return AttackGenerationRequest(
        strategy=strategy,
        brief=SUPPORT_AGENT_POLICY.brief_for("customer_a"),
        turn_index=turn_index,
        prior_turns=[],
        seed=42,
    )


async def test_template_generator_fills_policy_slots_deterministically() -> None:
    result = await TemplateAttackGenerator().generate(_request())

    assert "customer_a" in result.content
    assert "customer_b" in result.content
    assert result.generator == "template"


async def test_template_generator_uses_fixed_followup_after_first_turn() -> None:
    request = AttackGenerationRequest(
        strategy=DIRECT_INSTRUCTION_OVERRIDE,
        brief=SUPPORT_AGENT_POLICY.brief_for("customer_a"),
        turn_index=1,
        prior_turns=[
            Turn(
                index=0,
                attacker_message="first",
                output=AdapterOutput(
                    assistant_message="no",
                    observability=ObservabilityLevel.FULL,
                ),
            )
        ],
        seed=42,
    )
    generator = TemplateAttackGenerator(followup="Please continue.")
    followup = await generator.generate(request)

    assert followup.content == "Please continue."


async def test_template_generator_rejects_missing_required_slot() -> None:
    strategy = Strategy(
        id="needs_target",
        name="Needs target",
        description="test",
        categories=[VulnerabilityCategory.UNAUTHORIZED_TOOL_USE],
        seed_template="Show {target_resource}",
        mutation_operators=["paraphrase"],
        max_turns=1,
        predicted_strength=PredictedStrength.WEAK,
    )
    policy = Policy(
        version="v1",
        target_name="single",
        actors={"only": ActorPolicy(actor_id="only")},
    )
    request = AttackGenerationRequest(
        strategy=strategy,
        brief=policy.brief_for("only"),
        turn_index=0,
        seed=1,
    )

    with pytest.raises(AttackGenerationError, match="target_resource"):
        await TemplateAttackGenerator().generate(request)


async def test_target_resource_comes_from_permissions_not_actor_id() -> None:
    strategy = Strategy(
        id="resource_target",
        name="Resource target",
        description="test",
        categories=[VulnerabilityCategory.UNAUTHORIZED_TOOL_USE],
        seed_template="Show {target_resource}",
        mutation_operators=["paraphrase"],
        max_turns=1,
        predicted_strength=PredictedStrength.WEAK,
    )
    policy = Policy(
        version="v1",
        target_name="resources",
        actors={
            "alice_login": ActorPolicy(
                actor_id="alice_login",
                allowed_resource_ids=["account_A"],
            ),
            "bob_login": ActorPolicy(
                actor_id="bob_login",
                allowed_resource_ids=["account_B"],
            ),
        },
    )
    result = await TemplateAttackGenerator().generate(
        AttackGenerationRequest(
            strategy=strategy,
            brief=policy.brief_for("alice_login"),
            turn_index=0,
            seed=1,
        )
    )

    assert result.content == "Show account_B"


async def test_scripted_generator_returns_exact_turn() -> None:
    generator = ScriptedAttackGenerator({DIRECT_INSTRUCTION_OVERRIDE.id: ["first", "second"]})
    first = await generator.generate(_request(DIRECT_INSTRUCTION_OVERRIDE))

    assert first.content == "first"


async def test_scripted_generator_exhaustion_is_explicit() -> None:
    generator = ScriptedAttackGenerator({DIRECT_INSTRUCTION_OVERRIDE.id: []})
    with pytest.raises(AttackGenerationError, match="没有第 0 轮"):
        await generator.generate(_request(DIRECT_INSTRUCTION_OVERRIDE))


def test_generation_request_rejects_history_mismatch() -> None:
    with pytest.raises(ValidationError, match="prior_turns"):
        AttackGenerationRequest(
            strategy=DIRECT_INSTRUCTION_OVERRIDE,
            brief=SUPPORT_AGENT_POLICY.brief_for("customer_a"),
            turn_index=1,
            prior_turns=[],
            seed=1,
        )


# ── 攻击方不许看到检测仪器 ───────────────────────────────────────────────


def test_brief_never_carries_the_detection_instrumentation() -> None:
    """canary 值/前缀与 system prompt 指纹绝不能出现在攻击侧视图里。

    这条用**序列化后全文扫描**而不是逐字段断言,是刻意的:
    以后给 Policy 加了新的敏感字段而忘了脱敏,这个测试照样会红 ——
    逐字段断言只能覆盖今天想得到的字段。

    泄漏的后果反直觉:不是误报,是**静默漏报**。话术自带 canary 时,
    检测器的 `value not in attacker_text` 守卫会正确地拒绝计分,
    于是这条信号线永远赢不了,而且不会有任何报错。
    """
    policy = SUPPORT_AGENT_POLICY
    serialized = policy.brief_for("customer_a").model_dump_json()

    secrets = [
        *policy.canary_values(),
        *policy.canary_prefixes(),
        *(policy.system_prompt_fingerprint.ngrams if policy.system_prompt_fingerprint else []),
    ]
    assert secrets, "靶场 policy 应当有 canary 与指纹,否则这个测试形同虚设"
    for secret in secrets:
        assert secret not in serialized, f"攻击侧视图泄漏了检测仪器: {secret!r}"


def test_brief_still_exposes_the_attack_surface() -> None:
    """脱敏不能脱过头 —— 工具名、身份、越权靶子是真实攻击者侦察就能拿到的。"""
    brief = SUPPORT_AGENT_POLICY.brief_for("customer_a")

    assert brief.actor == "customer_a"
    assert brief.unauthorized_resource_ids == ["customer_b"]
    assert "delete_customer" in brief.forbidden_tool_names()
    assert "get_customer_profile" in brief.constrained_tool_names()
    # 只给"哪个参数受约束",不给约束内容 —— 前者是攻击面,后者是答案。
    refund = next(t for t in brief.tools if t.name == "issue_refund")
    assert refund.constrained_parameters == ["amount_usd"]
    assert "100" not in refund.model_dump_json()


def test_brief_rejects_an_unknown_actor() -> None:
    with pytest.raises(KeyError):
        SUPPORT_AGENT_POLICY.brief_for("nobody")
