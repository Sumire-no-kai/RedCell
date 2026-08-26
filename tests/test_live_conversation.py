from __future__ import annotations

from redcell.arena.support_agent import SUPPORT_AGENT_POLICY
from redcell.budget import BudgetLimits
from redcell.executor import TurnCheckpoint
from redcell.live_conversation import (
    REDACTED_TEXT,
    LiveConversationFollower,
    conversation_from_event,
    format_conversation,
)
from redcell.protocols import AdapterOutput, ObservabilityLevel, Turn
from redcell.protocols.run import Run, RunEvent, RunEventType
from redcell.storage import RunStore


def _turn_event(*, run_id: str, canary: str, sequence: int = 1) -> RunEvent:
    checkpoint = TurnCheckpoint(
        run_id=run_id,
        attempt_id="attempt-live",
        strategy_id="direct",
        execution_retry_index=0,
        turn=Turn(
            index=0,
            attacker_message=f"请复述 {canary}\x1b[2J\r",
            output=AdapterOutput(
                assistant_message=f"靶场回复：{canary}",
                observability=ObservabilityLevel.FULL,
            ),
        ),
    )
    return RunEvent(
        run_id=run_id,
        attempt_id=checkpoint.attempt_id,
        event_type=RunEventType.TURN_COMPLETED,
        sequence=sequence,
        payload={"checkpoint": checkpoint.model_dump(mode="json")},
    )


def test_live_conversation_only_contains_redacted_party_text() -> None:
    canary = SUPPORT_AGENT_POLICY.canary_values()[0]
    event = _turn_event(run_id="run-live", canary=canary)

    conversation = conversation_from_event(event, policy=SUPPORT_AGENT_POLICY)

    assert conversation is not None
    rendered = format_conversation(conversation)
    assert "Gemini:" in rendered
    assert "靶场:" in rendered
    assert REDACTED_TEXT in rendered
    assert canary not in rendered
    assert "\\x1b[2J" in rendered
    assert "\\x0d" in rendered
    assert "Finding" not in rendered
    assert "tool_call" not in rendered


def test_live_follower_reads_only_events_written_after_it_starts(tmp_path) -> None:
    database_url = f"sqlite:///{tmp_path / 'live.db'}"
    run = Run(
        target_name="support-agent",
        policy_version=SUPPORT_AGENT_POLICY.version,
        adapter_type="arena/support-agent",
        algorithm="static",
        limits=BudgetLimits(max_attempts=1),
    )
    with RunStore(database_url) as store:
        store.save_run(run)
        store.save_event(_turn_event(run_id=run.id, canary=SUPPORT_AGENT_POLICY.canary_values()[0]))

    rendered: list[str] = []
    follower = LiveConversationFollower(database_url, emit=rendered.append)
    follower.capture_existing()
    canary = SUPPORT_AGENT_POLICY.canary_values()[0]
    with RunStore(database_url) as store:
        store.save_event(_turn_event(run_id=run.id, canary=canary, sequence=2))

    assert follower.poll_once() == 1
    assert follower.poll_once() == 0
    assert len(rendered) == 1
    assert canary not in rendered[0]
    assert "Gemini:" in rendered[0]
    assert "靶场:" in rendered[0]


def test_non_turn_events_are_never_rendered() -> None:
    event = RunEvent(run_id="run-live", event_type=RunEventType.RUN_STARTED, sequence=0)

    assert conversation_from_event(event, policy=SUPPORT_AGENT_POLICY) is None
