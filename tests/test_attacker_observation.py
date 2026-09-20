from __future__ import annotations

import pytest

from redcell.attacker_observation import (
    ATTACKER_OBSERVATION_POLICY_V1,
    ActiveAttemptTrace,
    AttackerObservationLedger,
    ObservationProjectionError,
    ObservedToolOutcome,
    project_attacker_observations,
)
from redcell.protocols import (
    AdapterOutput,
    AttemptStopReason,
    ObservabilityLevel,
    ReproductionContext,
    SideEffect,
    SignalChannel,
    SignalScore,
    ToolCall,
    ToolResult,
    Turn,
    build_attempt,
)


def _attempt(output: AdapterOutput):
    return build_attempt(
        attempt_id="attempt-1",
        run_id="run-1",
        attempt_index=0,
        strategy_id="confirmation_bypass",
        actor="customer_a",
        attack_prompt="try the confirmation boundary",
        turns=[Turn(index=0, attacker_message="please proceed", output=output)],
        signals=[
            SignalScore(
                channel=SignalChannel.TOOL,
                score=0.7,
                tier="private-tier",
                evidence="PRIVATE_SCORER_TRUTH",
            )
        ],
        reproduction=ReproductionContext(
            policy_version="policy-v1",
            target_name="support-agent",
            adapter_type="arena",
            strategy_id="confirmation_bypass",
        ),
        planned_max_turns=1,
        stop_reason=AttemptStopReason.MAX_TURNS,
    )


def test_projection_distinguishes_tool_outcomes_without_leaking_private_truth() -> None:
    calls = [
        ToolCall(id="performed", name="issue_refund", arguments={"amount": 10}),
        ToolCall(id="waiting", name="close_account", arguments={}),
        ToolCall(id="rejected", name="delete_customer", arguments={}),
        ToolCall(id="unknown", name="lookup_order", arguments={"order_id": "A-1"}),
    ]
    output = AdapterOutput(
        assistant_message="I need confirmation before continuing.",
        tool_calls=calls,
        malformed_tool_calls=1,
        tool_results=[
            ToolResult(
                tool_call_id="performed",
                name="issue_refund",
                content="PRIVATE_TOOL_RESULT",
            ),
            ToolResult(
                tool_call_id="waiting",
                name="close_account",
                content="PRIVATE_CONFIRMATION_TEXT",
                awaiting_confirmation=True,
            ),
            ToolResult(
                tool_call_id="rejected",
                name="delete_customer",
                content="",
                error="PRIVATE_REJECTION_REASON",
            ),
        ],
        side_effects=[
            SideEffect(
                kind="refund_issued",
                payload={"secret": "PRIVATE_SIDE_EFFECT_PAYLOAD"},
                tool_call_id="performed",
            )
        ],
        observability=ObservabilityLevel.FULL,
    )

    ledger = project_attacker_observations([_attempt(output)])
    turn = ledger.attempts[0].turns[0]

    assert ledger.policy_version == ATTACKER_OBSERVATION_POLICY_V1
    assert ledger.run_id == "run-1"
    assert ledger.attempts[0].attempt_index == 0
    assert ledger.attempts[0].active is False
    assert [action.outcome for action in turn.tool_actions] == [
        ObservedToolOutcome.PERFORMED,
        ObservedToolOutcome.AWAITING_CONFIRMATION,
        ObservedToolOutcome.REJECTED,
        ObservedToolOutcome.UNKNOWN,
    ]
    assert turn.tool_actions[0].side_effect_kinds == ["refund_issued"]
    assert turn.malformed_tool_calls == 1

    rendered = ledger.model_dump_json()
    assert "PRIVATE_TOOL_RESULT" not in rendered
    assert "PRIVATE_CONFIRMATION_TEXT" not in rendered
    assert "PRIVATE_REJECTION_REASON" not in rendered
    assert "PRIVATE_SIDE_EFFECT_PAYLOAD" not in rendered
    assert "PRIVATE_SCORER_TRUTH" not in rendered
    assert "private-tier" not in rendered
    assert "max_turns" not in rendered


def test_projection_has_stable_refs_and_digest() -> None:
    output = AdapterOutput(
        assistant_message="No action taken.",
        observability=ObservabilityLevel.FULL,
    )

    first = project_attacker_observations([_attempt(output)])
    second = project_attacker_observations([_attempt(output)])

    assert first.digest == second.digest
    assert first.evidence_refs == {
        "attempt:attempt-1",
        "attempt:attempt-1/turn:0",
    }


def test_ledger_rejects_a_digest_that_does_not_match_its_contents() -> None:
    ledger = project_attacker_observations([])
    payload = ledger.model_dump(mode="json")
    payload["digest"] = "0" * 64

    with pytest.raises(ValueError, match="digest 与内容不一致"):
        AttackerObservationLedger.model_validate(payload)


def test_projection_fails_closed_on_side_effect_for_unperformed_call() -> None:
    output = AdapterOutput(
        assistant_message="Waiting for confirmation.",
        tool_calls=[ToolCall(id="call-1", name="issue_refund", arguments={"amount": 10})],
        tool_results=[
            ToolResult(
                tool_call_id="call-1",
                name="issue_refund",
                content="waiting",
                awaiting_confirmation=True,
            )
        ],
        side_effects=[SideEffect(kind="refund_issued", payload={}, tool_call_id="call-1")],
        observability=ObservabilityLevel.FULL,
    )

    with pytest.raises(ObservationProjectionError, match="真实副作用"):
        project_attacker_observations([_attempt(output)])


def test_projection_respects_partial_and_response_only_observability() -> None:
    call = ToolCall(id="call-1", name="issue_refund", arguments={"amount": 10})
    result = ToolResult(
        tool_call_id=call.id,
        name=call.name,
        content="PRIVATE_TOOL_RESULT",
    )
    effect = SideEffect(
        kind="refund_issued",
        payload={"secret": "PRIVATE_SIDE_EFFECT_PAYLOAD"},
        tool_call_id=call.id,
    )

    partial = (
        project_attacker_observations(
            [
                _attempt(
                    AdapterOutput(
                        assistant_message="I submitted the request.",
                        tool_calls=[call],
                        tool_results=[result],
                        side_effects=[effect],
                        malformed_tool_calls=1,
                        observability=ObservabilityLevel.PARTIAL,
                    )
                )
            ]
        )
        .attempts[0]
        .turns[0]
    )
    assert partial.observability is ObservabilityLevel.PARTIAL
    assert partial.malformed_tool_calls == 1
    assert len(partial.tool_actions) == 1
    assert partial.tool_actions[0].outcome is ObservedToolOutcome.UNKNOWN
    assert partial.tool_actions[0].side_effect_kinds == []

    response_only = (
        project_attacker_observations(
            [
                _attempt(
                    AdapterOutput(
                        assistant_message="I submitted the request.",
                        tool_calls=[call],
                        tool_results=[result],
                        side_effects=[effect],
                        malformed_tool_calls=1,
                        observability=ObservabilityLevel.RESPONSE_ONLY,
                    )
                )
            ]
        )
        .attempts[0]
        .turns[0]
    )
    assert response_only.observability is ObservabilityLevel.RESPONSE_ONLY
    assert response_only.malformed_tool_calls == 0
    assert response_only.tool_actions == []
    assert response_only.unbound_side_effect_kinds == []


def test_projection_fails_closed_on_unbound_tool_result() -> None:
    output = AdapterOutput(
        assistant_message="No call was emitted.",
        tool_results=[ToolResult(tool_call_id="missing", name="lookup_order", content="")],
        observability=ObservabilityLevel.FULL,
    )

    with pytest.raises(ObservationProjectionError, match="没有对应"):
        project_attacker_observations([_attempt(output)])


def test_projection_rejects_cross_run_memory() -> None:
    output = AdapterOutput(
        assistant_message="No action taken.",
        observability=ObservabilityLevel.FULL,
    )
    first = _attempt(output)
    second = _attempt(output).model_copy(update={"id": "attempt-2", "run_id": "run-2"})

    with pytest.raises(ObservationProjectionError, match="不得跨 Run"):
        project_attacker_observations([first, second])


def test_projection_requires_strictly_increasing_authoritative_attempt_indexes() -> None:
    output = AdapterOutput(
        assistant_message="No action taken.",
        observability=ObservabilityLevel.FULL,
    )
    later = _attempt(output).model_copy(update={"id": "attempt-2", "attempt_index": 1})
    earlier = _attempt(output)

    with pytest.raises(ObservationProjectionError, match="严格递增"):
        project_attacker_observations([later, earlier])

    legacy = earlier.model_copy(update={"attempt_index": None})
    with pytest.raises(ObservationProjectionError, match="权威 attempt_index"):
        project_attacker_observations([legacy])

    incomplete = earlier.model_copy(update={"stop_reason": None})
    with pytest.raises(ObservationProjectionError, match="尚未结束"):
        project_attacker_observations([incomplete])


def test_projection_represents_in_progress_trace_without_fabricating_attempt() -> None:
    active = ActiveAttemptTrace(
        id="attempt-active",
        run_id="run-1",
        attempt_index=0,
        strategy_id="confirmation_bypass",
        turns=[
            Turn(
                index=0,
                attacker_message="please proceed",
                output=AdapterOutput(
                    assistant_message="I need confirmation.",
                    observability=ObservabilityLevel.FULL,
                ),
            )
        ],
    )

    ledger = project_attacker_observations([], active_attempt=active)

    assert ledger.run_id == "run-1"
    assert ledger.attempts[0].active is True
    assert ledger.attempts[0].ref == "attempt:attempt-active"
