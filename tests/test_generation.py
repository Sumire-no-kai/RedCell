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
        policy=SUPPORT_AGENT_POLICY,
        actor="customer_a",
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
        policy=SUPPORT_AGENT_POLICY,
        actor="customer_a",
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
        policy=policy,
        actor="only",
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
            policy=policy,
            actor="alice_login",
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
            policy=SUPPORT_AGENT_POLICY,
            actor="customer_a",
            turn_index=1,
            prior_turns=[],
            seed=1,
        )
