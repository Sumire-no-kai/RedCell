from __future__ import annotations

from redcell.finding_identity import attack_path_signature, finding_signature
from redcell.protocols import (
    ConstraintKind,
    Evidence,
    Finding,
    ImpactBasis,
    ImpactStatus,
    ObservabilityLevel,
    ProtectedDataLocation,
    ToolCall,
    ViolationTriad,
    VulnerabilityCategory,
)


def _finding(*, strategy_id: str, title: str, arguments: dict[str, object]) -> Finding:
    return Finding(
        run_id="run",
        attempt_id="attempt",
        category=VulnerabilityCategory.UNAUTHORIZED_TOOL_USE,
        title=title,
        actor="customer_a",
        strategy_id=strategy_id,
        triad=ViolationTriad(
            attempted_action=True,
            realized_impact=ImpactStatus.REALIZED,
            impact_basis=ImpactBasis.SIDE_EFFECT,
        ),
        evidence=[
            Evidence(
                tool_call=ToolCall(id="call", name="refund_order", arguments=arguments),
                description="x",
            )
        ],
        observability=ObservabilityLevel.FULL,
    )


def test_structure_signature_ignores_title_and_specific_parameter_values() -> None:
    first = _finding(strategy_id="a", title="refund $10", arguments={"amount": 10})
    second = _finding(strategy_id="a", title="refund $500", arguments={"amount": 500})

    assert finding_signature(first) == finding_signature(second)
    assert attack_path_signature(first) == attack_path_signature(second)


def test_attack_path_signature_changes_when_strategy_changes() -> None:
    first = _finding(strategy_id="a", title="x", arguments={})
    second = _finding(strategy_id="b", title="x", arguments={})

    assert finding_signature(first) == finding_signature(second)
    assert attack_path_signature(first) != attack_path_signature(second)


def test_structure_signature_binds_argument_names_and_json_types() -> None:
    amount = _finding(strategy_id="a", title="x", arguments={"amount": 10})
    recipient = _finding(strategy_id="a", title="x", arguments={"recipient": 10})
    string_amount = _finding(strategy_id="a", title="x", arguments={"amount": "10"})

    assert finding_signature(amount) != finding_signature(recipient)
    assert finding_signature(amount) != finding_signature(string_amount)


def test_structure_signature_binds_constraint_semantics() -> None:
    base = _finding(strategy_id="a", title="x", arguments={"amount": 10})
    max_value = base.model_copy(
        update={
            "evidence": [
                base.evidence[0].model_copy(
                    update={
                        "constraint_parameter": "amount",
                        "constraint_kind": ConstraintKind.MAX_VALUE,
                    }
                )
            ]
        }
    )
    actor_bound = base.model_copy(
        update={
            "evidence": [
                base.evidence[0].model_copy(
                    update={
                        "constraint_parameter": "amount",
                        "constraint_kind": ConstraintKind.BOUND_TO_ACTOR,
                    }
                )
            ]
        }
    )

    assert finding_signature(max_value) != finding_signature(actor_bound)


def test_canary_identity_binds_location_and_digest_without_plaintext() -> None:
    first = _finding(strategy_id="a", title="x", arguments={}).model_copy(
        update={
            "category": VulnerabilityCategory.PROMPT_INJECTION,
            "evidence": [
                Evidence(
                    description="canary",
                    matched_value="redcell-secret-one",
                    protected_location=ProtectedDataLocation.SYSTEM_PROMPT,
                )
            ],
        }
    )
    second = first.model_copy(
        update={
            "evidence": [
                first.evidence[0].model_copy(update={"matched_value": "redcell-secret-two"})
            ]
        }
    )

    first_signature = finding_signature(first)
    assert first_signature != finding_signature(second)
    assert "redcell-secret-one" not in first_signature
