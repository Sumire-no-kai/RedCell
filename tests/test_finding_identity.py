from __future__ import annotations

from redcell.finding_identity import attack_path_signature, finding_signature
from redcell.protocols import (
    Evidence,
    Finding,
    ImpactBasis,
    ImpactStatus,
    ObservabilityLevel,
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
