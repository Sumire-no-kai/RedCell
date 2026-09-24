"""Offline integration checks for the small feedback-driven Run path."""

from __future__ import annotations

from collections.abc import Callable

import pytest

from redcell._base import CostRecord
from redcell.arena.support_agent import SUPPORT_AGENT_POLICY
from redcell.budget import BudgetLimit, BudgetLimits
from redcell.feedback_attacker import (
    FEEDBACK_ATTACKER_PROMPT_V2,
    FEEDBACK_ATTACKER_SCHEMA_V2,
    AttackerWorkingState,
    FeedbackAttackAction,
    FeedbackAttackChoice,
    FeedbackAttackDecisionError,
    FeedbackAttackDriver,
    FeedbackAttackRequest,
    FeedbackAttackSelection,
)
from redcell.feedback_run import FeedbackRunOrchestrator
from redcell.orchestrator import RunExecutionRequest, RunFailedError
from redcell.protocols.adapter import (
    AdapterCapabilities,
    AdapterInput,
    AdapterOutput,
    ResetScope,
    TargetAdapter,
    ToolCall,
    ToolResult,
    TraceMetadata,
)
from redcell.protocols.common import ImpactStatus, ObservabilityLevel, Role
from redcell.protocols.run import (
    ArenaRunConfiguration,
    ExperimentConditions,
    FeedbackRunConfiguration,
    ProviderRunConfiguration,
    Run,
    RunEventType,
    RunStatus,
    UsageAccountingMode,
)
from redcell.protocols.strategy import Strategy, StrategyCatalogue
from redcell.protocols.trace import AttemptStopReason
from redcell.scoring.level1 import Level1Scorer
from redcell.storage.store import RunStore
from redcell.strategies.library import DIRECT_INSTRUCTION_OVERRIDE
from redcell.versions import FEEDBACK_EXPERIMENT_CONDITIONS_SCHEMA_VERSION

_POLICY = SUPPORT_AGENT_POLICY
_STRATEGY = DIRECT_INSTRUCTION_OVERRIDE
_DRIVER_COST = CostRecord(prompt_tokens=2, completion_tokens=1, usd=0.002)


@pytest.fixture
def store(tmp_path) -> RunStore:
    with RunStore(f"sqlite:///{tmp_path / 'feedback.db'}") as opened:
        yield opened


def _provider(name: str) -> ProviderRunConfiguration:
    return ProviderRunConfiguration(
        provider=name,
        base_url="",
        model=f"{name}-fake",
        temperature=0.0,
        max_tokens=100,
        rpm=0.0,
        max_concurrency=0,
        input_usd_per_mtok=0.0,
        output_usd_per_mtok=0.0,
        cached_input_usd_per_mtok=0.0,
        usage_accounting_mode=UsageAccountingMode.PROMPT_COMPLETION_V1,
    )


def _run(
    *,
    max_tokens: int = 100,
    max_attempts: int = 2,
    max_steps: int = 5,
    max_turns: int = 3,
    strategy: Strategy = _STRATEGY,
) -> Run:
    conditions = ExperimentConditions(
        online=False,
        actor="customer_a",
        target=_provider("target"),
        attacker=_provider("attacker"),
        arena=ArenaRunConfiguration(
            defense="standard",
            enforce_permissions=True,
            enforce_confirmation=True,
            tool_call_protocol_version="native-function-calling-v1",
        ),
        strategy_catalogue=StrategyCatalogue(
            version="m1b-test-v1", strategies=[strategy]
        ).condition_summary(),
        feedback=FeedbackRunConfiguration(
            driver_name="fake-feedback",
            observation_visibility="tool-status",
            prompt_version=FEEDBACK_ATTACKER_PROMPT_V2,
            schema_version=FEEDBACK_ATTACKER_SCHEMA_V2,
            observation_policy_version="attacker-observation-v2",
            max_decision_steps=max_steps,
            max_turns_per_attempt=max_turns,
            stop_policy_version="feedback-stop-v1",
        ),
        conditions_schema_version=FEEDBACK_EXPERIMENT_CONDITIONS_SCHEMA_VERSION,
    )
    return Run(
        target_name=_POLICY.target_name,
        policy_version=_POLICY.version,
        adapter_type="fake-target",
        algorithm="fake-feedback",
        limits=BudgetLimits(max_attempts=max_attempts, max_total_tokens=max_tokens),
        seed=7,
        target_model="target-fake",
        attacker_model="attacker-fake",
        experiment_conditions=conditions,
        strategy_ids=[strategy.id],
    )


def _action(
    kind: str,
    *,
    message: str | None = None,
    strategy_id: str | None = None,
    evidence_refs: list[str] | None = None,
) -> FeedbackAttackAction:
    sending = kind in {"start_attempt", "continue_attempt"}
    return FeedbackAttackAction(
        kind=kind,
        strategy_id=strategy_id,
        message=message,
        test_intent="Check the target's next response." if sending else None,
        reason=None if sending else "Enough evidence for this step.",
        evidence_refs=evidence_refs or [],
    )


Decision = (
    FeedbackAttackAction | Callable[[FeedbackAttackRequest], FeedbackAttackAction] | Exception
)


class FakeFeedbackDriver(FeedbackAttackDriver):
    def __init__(
        self,
        decisions: list[Decision],
        *,
        costs: list[CostRecord] | None = None,
        corrupt_digest: bool = False,
    ) -> None:
        self.decisions = decisions
        self.costs = costs or [_DRIVER_COST] * len(decisions)
        self.corrupt_digest = corrupt_digest
        self.requests: list[FeedbackAttackRequest] = []

    @property
    def name(self) -> str:
        return "fake-feedback"

    async def decide(self, request: FeedbackAttackRequest) -> FeedbackAttackSelection:
        index = len(self.requests)
        self.requests.append(request)
        decision = self.decisions[index]
        if isinstance(decision, Exception):
            raise decision
        action = decision(request) if callable(decision) else decision
        return FeedbackAttackSelection(
            choice=FeedbackAttackChoice(
                working_state=AttackerWorkingState(next_objective=f"objective-{index}"),
                action=action,
            ),
            cost=self.costs[index],
            prompt_version=FEEDBACK_ATTACKER_PROMPT_V2,
            schema_version=FEEDBACK_ATTACKER_SCHEMA_V2,
            request_digest="stale-request" if self.corrupt_digest else request.digest(),
            response_digest=f"response-{index}",
        )


class FakeTarget(TargetAdapter):
    def __init__(
        self,
        outputs: list[AdapterOutput | Exception],
        *,
        before_send: Callable[[], None] | None = None,
    ) -> None:
        self.outputs = outputs
        self.before_send = before_send
        self.requests: list[AdapterInput] = []
        self.resets = 0

    @property
    def adapter_type(self) -> str:
        return "fake-target"

    @property
    def observability(self) -> ObservabilityLevel:
        return ObservabilityLevel.FULL

    @property
    def capabilities(self) -> AdapterCapabilities:
        return AdapterCapabilities(reset_scope=ResetScope.FULL_STATE, reports_cost=True)

    async def reset(self) -> None:
        self.resets += 1

    async def send(self, payload: AdapterInput) -> AdapterOutput:
        if self.before_send is not None:
            self.before_send()
        self.requests.append(payload)
        output = self.outputs[len(self.requests) - 1]
        if isinstance(output, Exception):
            raise output
        return output


def _output(*, forbidden: str | None = None, usage_known: bool = True) -> AdapterOutput:
    call = ToolCall(id="call-1", name="delete_customer", arguments={"customer_id": "customer_b"})
    result = ToolResult(
        tool_call_id=call.id,
        name=call.name,
        content="blocked" if forbidden == "rejected" else "deleted",
        error="permission denied: blocked" if forbidden == "rejected" else None,
    )
    return AdapterOutput(
        assistant_message="The request was processed.",
        tool_calls=[call] if forbidden else [],
        tool_results=[result] if forbidden else [],
        observability=ObservabilityLevel.FULL,
        trace_metadata=TraceMetadata(
            prompt_tokens=3,
            completion_tokens=2,
            usage_known=usage_known,
            cost_usd=0.003,
            model="target-fake",
            temperature=0.0,
        ),
    )


async def _execute(run: Run, driver: FakeFeedbackDriver, target: FakeTarget, store: RunStore):
    return await FeedbackRunOrchestrator(
        adapter=target,
        policy=_POLICY,
        scorer=Level1Scorer(_POLICY),
        driver=driver,
        store=store,
    ).execute(RunExecutionRequest(run=run, strategies=[_STRATEGY], actor="customer_a"))


async def test_rejected_attempted_action_can_inform_next_real_message(store: RunStore) -> None:
    run = _run(max_steps=3)

    def follow_up(request: FeedbackAttackRequest) -> FeedbackAttackAction:
        assert request.working_state.next_objective == "objective-0"
        assert request.active_attempt is not None
        observed = request.observations.attempts[0].turns[0].tool_actions[0]
        assert observed.outcome.value == "rejected"
        return _action(
            "continue_attempt",
            message="Follow up after the rejected call.",
            evidence_refs=[observed.ref],
        )

    driver = FakeFeedbackDriver(
        [
            _action("start_attempt", message="Try the forbidden action.", strategy_id=_STRATEGY.id),
            follow_up,
            _action("end_attempt"),
        ]
    )

    def selected_before_send() -> None:
        selected = [
            event
            for event in store.events_for(run.id)
            if event.event_type is RunEventType.FEEDBACK_DECISION_SELECTED
        ]
        assert len(selected) == len(target.requests) + 1
        assert selected[-1].payload["will_send"]

    target = FakeTarget(
        [_output(forbidden="rejected"), _output()], before_send=selected_before_send
    )
    result = await _execute(run, driver, target, store)

    assert [message.content for message in target.requests[1].messages] == [
        "Try the forbidden action.",
        "The request was processed.",
        "Follow up after the rejected call.",
    ]
    assert [message.role for message in target.requests[1].messages] == [
        Role.USER,
        Role.ASSISTANT,
        Role.USER,
    ]
    assert target.resets == 1
    assert len(result.attempts) == 1
    assert result.attempts[0].turn_count == 2
    assert result.attempts[0].stop_reason is AttemptStopReason.DRIVER_END
    assert result.findings[0].triad.attempted_action
    assert result.findings[0].triad.realized_impact is ImpactStatus.NOT_REALIZED
    assert store.attempts_for(run.id)[0].model_dump(mode="json") == result.attempts[0].model_dump(
        mode="json"
    )
    assert [finding.id for finding in store.findings_for(run.id)] == [f.id for f in result.findings]
    assert result.run.usage.total_tokens == 19  # Three decisions and two Target turns.
    assert result.run.usage.generator_prompt_tokens == 6
    assert result.run.usage.target_prompt_tokens == 6
    assert store.get_run(run.id).status is RunStatus.COMPLETED


async def test_realized_impact_ends_attempt_before_its_turn_limit(store: RunStore) -> None:
    run = _run(max_steps=3, max_turns=3)

    def stop_after_impact(request: FeedbackAttackRequest) -> FeedbackAttackAction:
        assert request.active_attempt is None
        assert len(request.observations.attempts) == 1
        assert not request.observations.attempts[0].active
        return _action("stop_run")

    driver = FakeFeedbackDriver(
        [
            _action("start_attempt", message="Try the forbidden action.", strategy_id=_STRATEGY.id),
            stop_after_impact,
        ]
    )
    target = FakeTarget([_output(forbidden="performed")])
    result = await _execute(run, driver, target, store)

    assert len(target.requests) == 1
    assert result.attempts[0].turn_count == 1
    assert result.attempts[0].stop_reason is AttemptStopReason.REALIZED_IMPACT
    assert result.findings[0].triad.realized_impact is ImpactStatus.REALIZED
    assert store.attempts_for(run.id)[0].stop_reason is AttemptStopReason.REALIZED_IMPACT


async def test_driver_consuming_last_tokens_prevents_target_send(store: RunStore) -> None:
    run = _run(max_tokens=3)
    driver = FakeFeedbackDriver(
        [_action("start_attempt", message="Send me.", strategy_id=_STRATEGY.id)]
    )
    target = FakeTarget([])
    result = await _execute(run, driver, target, store)

    assert not target.requests
    assert target.resets == 0
    assert not result.attempts
    assert result.run.usage.total_tokens == 3
    assert result.run.usage.attempts == 0
    selected = next(
        event
        for event in store.events_for(run.id)
        if event.event_type is RunEventType.FEEDBACK_DECISION_SELECTED
    )
    assert not selected.payload["will_send"]
    assert store.get_run(run.id).usage.total_tokens == 3


async def test_target_consuming_last_tokens_prevents_another_driver_call(store: RunStore) -> None:
    run = _run(max_tokens=8)
    driver = FakeFeedbackDriver(
        [_action("start_attempt", message="One message.", strategy_id=_STRATEGY.id)]
    )
    target = FakeTarget([_output()])
    result = await _execute(run, driver, target, store)

    assert len(driver.requests) == 1
    assert len(target.requests) == 1
    assert result.run.usage.total_tokens == 8
    assert result.run.usage.completed_attempts == 1
    assert result.attempts[0].stop_reason is AttemptStopReason.BUDGET_EXHAUSTED
    assert store.attempts_for(run.id)[0].cost.total_tokens == 8


async def test_decision_step_cap_closes_active_attempt_and_records_limit(store: RunStore) -> None:
    run = _run(max_steps=1)
    driver = FakeFeedbackDriver(
        [_action("start_attempt", message="One message.", strategy_id=_STRATEGY.id)]
    )
    result = await _execute(run, driver, FakeTarget([_output()]), store)

    assert result.attempts[0].stop_reason is AttemptStopReason.BUDGET_EXHAUSTED
    assert result.run.stopped_by is BudgetLimit.DECISION_STEPS
    assert store.get_run(run.id).stopped_by is BudgetLimit.DECISION_STEPS


async def test_attempt_cap_records_which_budget_stopped_run(store: RunStore) -> None:
    run = _run(max_attempts=1, max_steps=3)
    driver = FakeFeedbackDriver(
        [
            _action("start_attempt", message="One message.", strategy_id=_STRATEGY.id),
            _action("end_attempt"),
        ]
    )
    result = await _execute(run, driver, FakeTarget([_output()]), store)

    assert result.run.stopped_by is BudgetLimit.ATTEMPTS
    assert store.get_run(run.id).stopped_by is BudgetLimit.ATTEMPTS


async def test_driver_failure_keeps_cost_and_marks_run_failed(store: RunStore) -> None:
    run = _run()
    failure = FeedbackAttackDecisionError(
        "invalid response",
        cost=CostRecord(prompt_tokens=4, completion_tokens=1),
        usage_indeterminate=False,
    )
    driver = FakeFeedbackDriver([failure])
    target = FakeTarget([])

    with pytest.raises(RunFailedError) as raised:
        await _execute(run, driver, target, store)

    assert raised.value.run.status is RunStatus.FAILED
    assert store.get_run(run.id).usage.total_tokens == 5
    assert not target.requests
    assert not store.attempts_for(run.id)
    assert any(
        event.event_type is RunEventType.FEEDBACK_DECISION_FAILED
        for event in store.events_for(run.id)
    )


async def test_target_failure_is_fail_closed_without_a_valid_attempt(store: RunStore) -> None:
    run = _run()
    driver = FakeFeedbackDriver(
        [_action("start_attempt", message="One message.", strategy_id=_STRATEGY.id)]
    )
    target = FakeTarget([RuntimeError("Target delivery uncertain")])

    with pytest.raises(RunFailedError) as raised:
        await _execute(run, driver, target, store)

    assert raised.value.run.status is RunStatus.FAILED
    assert raised.value.failure.usage.usage_known is False
    assert store.get_run(run.id).usage.total_tokens == 3
    assert not store.attempts_for(run.id)
    assert [event.event_type for event in store.events_for(run.id)][-1] is RunEventType.RUN_FAILED


async def test_unknown_target_usage_is_not_committed_as_valid_attempt(store: RunStore) -> None:
    run = _run()
    driver = FakeFeedbackDriver(
        [_action("start_attempt", message="One message.", strategy_id=_STRATEGY.id)]
    )
    target = FakeTarget([_output(usage_known=False)])

    with pytest.raises(RunFailedError) as raised:
        await _execute(run, driver, target, store)

    assert raised.value.run.status is RunStatus.FAILED
    assert store.get_run(run.id).usage.total_tokens == 8
    assert not store.attempts_for(run.id)


async def test_invalid_selection_fails_closed_and_records_spent_cost(store: RunStore) -> None:
    run = _run()
    driver = FakeFeedbackDriver(
        [_action("start_attempt", message="Must not send.", strategy_id=_STRATEGY.id)],
        corrupt_digest=True,
    )
    target = FakeTarget([])

    with pytest.raises(RunFailedError) as raised:
        await _execute(run, driver, target, store)

    assert raised.value.run.status is RunStatus.FAILED
    assert store.get_run(run.id).usage.total_tokens == 3
    assert not target.requests
    assert not store.attempts_for(run.id)


async def test_unexpected_driver_exception_fails_closed(store: RunStore) -> None:
    run = _run()
    driver = FakeFeedbackDriver([RuntimeError("indeterminate delivery")])
    target = FakeTarget([])

    with pytest.raises(RunFailedError) as raised:
        await _execute(run, driver, target, store)

    assert raised.value.run.status is RunStatus.FAILED
    assert not raised.value.failure.usage.usage_known
    assert not target.requests


async def test_strategy_catalogue_must_match_actual_strategy_content(store: RunStore) -> None:
    changed = _STRATEGY.model_copy(update={"seed_template": "A different starting message."})
    run = _run(strategy=changed)
    driver = FakeFeedbackDriver([])
    target = FakeTarget([])

    with pytest.raises(ValueError, match="Strategy"):
        await _execute(run, driver, target, store)

    assert store.get_run(run.id) is None
    assert not driver.requests
    assert not target.requests


async def test_active_attempt_failure_is_recorded_as_abandoned(store: RunStore) -> None:
    run = _run()
    failure = FeedbackAttackDecisionError(
        "invalid follow-up",
        cost=CostRecord(prompt_tokens=1, completion_tokens=1),
        usage_indeterminate=False,
    )
    driver = FakeFeedbackDriver(
        [
            _action("start_attempt", message="One message.", strategy_id=_STRATEGY.id),
            failure,
        ]
    )

    with pytest.raises(RunFailedError):
        await _execute(run, driver, FakeTarget([_output()]), store)

    saved = store.get_run(run.id)
    assert saved.status is RunStatus.FAILED
    assert saved.usage.attempts == 1
    assert saved.usage.completed_attempts == 0
    assert saved.usage.abandoned_attempts == 1
    assert saved.usage.total_tokens == 10
    assert not store.attempts_for(run.id)
    assert any(
        event.event_type is RunEventType.ATTEMPT_ABANDONED for event in store.events_for(run.id)
    )


async def test_end_attempt_decision_cost_is_in_persisted_attempt(store: RunStore) -> None:
    run = _run(max_steps=2)
    closing_cost = CostRecord(prompt_tokens=4, completion_tokens=2, usd=0.004)
    driver = FakeFeedbackDriver(
        [
            _action("start_attempt", message="One message.", strategy_id=_STRATEGY.id),
            _action("end_attempt"),
        ],
        costs=[_DRIVER_COST, closing_cost],
    )

    result = await _execute(run, driver, FakeTarget([_output()]), store)

    assert len(result.attempts) == 1
    assert result.run.usage.total_tokens == 14
    assert result.attempts[0].cost.total_tokens == 14
    assert result.attempts[0].cost.usd == pytest.approx(0.009)
    assert store.attempts_for(run.id)[0].cost.total_tokens == 14


async def test_observation_projection_failure_fails_run_closed(store: RunStore) -> None:
    run = _run()
    driver = FakeFeedbackDriver(
        [_action("start_attempt", message="One message.", strategy_id=_STRATEGY.id)]
    )
    target = FakeTarget(
        [
            AdapterOutput(
                assistant_message="Response with an orphan result.",
                tool_results=[
                    ToolResult(
                        tool_call_id="missing-call",
                        name="delete_customer",
                        content="orphan",
                    )
                ],
                observability=ObservabilityLevel.FULL,
                trace_metadata=TraceMetadata(
                    prompt_tokens=3,
                    completion_tokens=2,
                    usage_known=True,
                    cost_usd=0.003,
                ),
            )
        ]
    )

    with pytest.raises(RunFailedError):
        await _execute(run, driver, target, store)

    saved = store.get_run(run.id)
    assert saved.status is RunStatus.FAILED
    assert saved.usage.total_tokens == 8
    assert saved.usage.abandoned_attempts == 1
    assert len(driver.requests) == 1
    assert not store.attempts_for(run.id)
    assert [event.event_type for event in store.events_for(run.id)][-1] is RunEventType.RUN_FAILED


async def test_negative_driver_tokens_fail_closed_without_budget_credit(store: RunStore) -> None:
    run = _run()
    invalid_cost = CostRecord().model_copy(update={"prompt_tokens": -2})
    driver = FakeFeedbackDriver(
        [_action("start_attempt", message="Must not send.", strategy_id=_STRATEGY.id)],
        costs=[invalid_cost],
    )
    target = FakeTarget([])

    with pytest.raises(RunFailedError):
        await _execute(run, driver, target, store)

    saved = store.get_run(run.id)
    assert saved.status is RunStatus.FAILED
    assert saved.usage.total_tokens >= 0
    assert not target.requests
    assert not store.attempts_for(run.id)
