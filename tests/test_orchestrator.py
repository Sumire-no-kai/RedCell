from __future__ import annotations

from collections.abc import Iterator

import pytest
from sqlalchemy.exc import OperationalError

from redcell.arena.support_agent.policy import SUPPORT_AGENT_POLICY
from redcell.budget import BudgetLimits
from redcell.executor import ConversationExecutor
from redcell.failures import (
    DeliveryStatus,
    FailureKind,
    FailureRecord,
    FailureStage,
    RetrySafety,
    SideEffectStatus,
    TransientAgentError,
)
from redcell.generation import (
    AttackGenerationRequest,
    AttackGenerator,
    AttackMessage,
    ScriptedAttackGenerator,
)
from redcell.orchestrator import (
    OrchestratorReuseError,
    RunAlreadyExistsError,
    RunExecutionRequest,
    RunFailedError,
    RunOrchestrator,
)
from redcell.protocols import (
    AdapterCapabilities,
    AdapterInput,
    AdapterOutput,
    DeliveryObservability,
    IdempotencySupport,
    ObservabilityLevel,
    ResetScope,
    TargetAdapter,
)
from redcell.protocols.run import Run, RunEventType, RunStatus
from redcell.retry import RetryPolicy
from redcell.scoring import Level1Scorer
from redcell.search import ControllerDecisionOutcome, StaticController
from redcell.storage import RunStore
from redcell.strategies import DIRECT_INSTRUCTION_OVERRIDE


def _one_turn_strategy():
    return DIRECT_INSTRUCTION_OVERRIDE.model_copy(update={"max_turns": 1})


def _run(*, max_attempts: int = 1) -> Run:
    return Run(
        target_name=SUPPORT_AGENT_POLICY.target_name,
        policy_version=SUPPORT_AGENT_POLICY.version,
        adapter_type="test",
        algorithm="static",
        limits=BudgetLimits(max_attempts=max_attempts),
        seed=42,
    )


class FlakyAdapter(TargetAdapter):
    def __init__(
        self,
        *,
        failures_before_success: int,
        capabilities: AdapterCapabilities,
    ) -> None:
        self.failures_before_success = failures_before_success
        self._capabilities = capabilities
        self.send_calls = 0
        self.reset_calls = 0
        self.request_ids: list[str | None] = []
        self.idempotency_keys: list[str | None] = []

    @property
    def adapter_type(self) -> str:
        return "test"

    @property
    def observability(self) -> ObservabilityLevel:
        return ObservabilityLevel.FULL

    @property
    def capabilities(self) -> AdapterCapabilities:
        return self._capabilities

    async def reset(self) -> None:
        self.reset_calls += 1

    async def send(self, payload: AdapterInput) -> AdapterOutput:
        self.send_calls += 1
        self.request_ids.append(payload.request_id)
        self.idempotency_keys.append(payload.idempotency_key)
        if self.send_calls <= self.failures_before_success:
            raise TimeoutError("temporary target timeout")
        return AdapterOutput(
            assistant_message="No.",
            observability=ObservabilityLevel.FULL,
        )


class StableAdapter(FlakyAdapter):
    def __init__(self) -> None:
        super().__init__(
            failures_before_success=0,
            capabilities=AdapterCapabilities(
                reset_scope=ResetScope.FULL_STATE,
                delivery_observability=DeliveryObservability.IN_PROCESS,
            ),
        )


class FlakyGenerator(AttackGenerator):
    def __init__(self, failures_before_success: int) -> None:
        self.failures_before_success = failures_before_success
        self.calls = 0

    @property
    def name(self) -> str:
        return "flaky"

    async def generate(self, request: AttackGenerationRequest) -> AttackMessage:
        self.calls += 1
        if self.calls <= self.failures_before_success:
            raise TransientAgentError(
                FailureRecord(
                    kind=FailureKind.AGENT_TRANSIENT,
                    stage=FailureStage.GENERATION,
                    code="generation_temporarily_unavailable",
                    message="temporary",
                    cause_type="test.FlakyGenerator",
                    retry_safety=RetrySafety.SAFE,
                    delivery_status=DeliveryStatus.NOT_SENT,
                    side_effect_status=SideEffectStatus.NONE,
                )
            )
        return AttackMessage(content="test attack", generator=self.name)


def _executor(adapter: TargetAdapter, generator: AttackGenerator) -> ConversationExecutor:
    return ConversationExecutor(
        adapter=adapter,
        generator=generator,
        scorer=Level1Scorer(SUPPORT_AGENT_POLICY),
        policy=SUPPORT_AGENT_POLICY,
    )


async def _no_sleep(_seconds: float) -> None:
    return None


async def _execute(
    *,
    store: RunStore,
    adapter: TargetAdapter,
    generator: AttackGenerator,
    max_attempts: int = 1,
    retry_policy: RetryPolicy | None = None,
):
    strategy = _one_turn_strategy()
    orchestrator = RunOrchestrator(
        executor=_executor(adapter, generator),
        controller=StaticController([strategy.id]),
        store=store,
        retry_policy=retry_policy or RetryPolicy(base_delay_seconds=0, max_delay_seconds=0),
        sleep=_no_sleep,
    )
    return await orchestrator.execute(
        RunExecutionRequest(
            run=_run(max_attempts=max_attempts),
            strategies=[strategy],
            actor="customer_a",
        )
    )


@pytest.fixture
def store(tmp_path) -> Iterator[RunStore]:
    with RunStore(f"sqlite:///{tmp_path / 'orchestrator.db'}") as opened:
        yield opened


async def test_serial_run_reaches_budget_and_commits_every_outcome(store: RunStore) -> None:
    adapter = StableAdapter()
    strategy = _one_turn_strategy()
    generator = ScriptedAttackGenerator({strategy.id: ["first attack"]})

    result = await _execute(
        store=store,
        adapter=adapter,
        generator=generator,
        max_attempts=2,
    )

    assert result.run.status is RunStatus.COMPLETED
    assert result.run.usage.attempts == 2
    assert result.run.usage.completed_attempts == 2
    assert result.run.usage.abandoned_attempts == 0
    assert len(store.attempts_for(result.run.id)) == 2
    assert len(store.decisions_for(result.run.id)) == 2
    assert adapter.send_calls == 2
    event_types = [event.event_type for event in store.events_for(result.run.id)]
    assert event_types[0] is RunEventType.RUN_STARTED
    assert event_types[-1] is RunEventType.RUN_COMPLETED
    assert event_types.count(RunEventType.TURN_COMPLETED) == 2
    assert event_types.count(RunEventType.ATTEMPT_COMMITTED) == 2


async def test_network_failure_gets_broader_retry_and_stable_ids(store: RunStore) -> None:
    adapter = FlakyAdapter(
        failures_before_success=3,
        capabilities=AdapterCapabilities(
            reset_scope=ResetScope.FULL_STATE,
            idempotency=IdempotencySupport.NONE,
            delivery_observability=DeliveryObservability.IN_PROCESS,
        ),
    )
    strategy = _one_turn_strategy()
    result = await _execute(
        store=store,
        adapter=adapter,
        generator=ScriptedAttackGenerator({strategy.id: ["attack"]}),
        retry_policy=RetryPolicy(
            max_network_retries=4,
            base_delay_seconds=0,
            max_delay_seconds=0,
        ),
    )

    assert result.run.status is RunStatus.COMPLETED
    assert result.run.usage.retries == 3
    assert adapter.send_calls == 4
    assert adapter.reset_calls == 4
    assert len(set(adapter.request_ids)) == 1
    assert len(set(adapter.idempotency_keys)) == 1
    assert adapter.request_ids == adapter.idempotency_keys


async def test_agent_transient_failure_retries_only_twice(store: RunStore) -> None:
    generator = FlakyGenerator(failures_before_success=2)
    result = await _execute(
        store=store,
        adapter=StableAdapter(),
        generator=generator,
        retry_policy=RetryPolicy(
            max_agent_retries=2,
            base_delay_seconds=0,
            max_delay_seconds=0,
        ),
    )

    assert result.run.status is RunStatus.COMPLETED
    assert result.run.usage.retries == 2
    assert generator.calls == 3


async def test_agent_retry_exhaustion_does_not_become_a_valid_negative(
    store: RunStore,
) -> None:
    generator = FlakyGenerator(failures_before_success=100)

    with pytest.raises(RunFailedError) as raised:
        await _execute(
            store=store,
            adapter=StableAdapter(),
            generator=generator,
            retry_policy=RetryPolicy(
                max_agent_retries=2,
                base_delay_seconds=0,
                max_delay_seconds=0,
            ),
        )

    assert generator.calls == 3
    assert raised.value.run.usage.retries == 2
    assert raised.value.run.usage.abandoned_attempts == 1
    assert raised.value.run.usage.completed_attempts == 0
    assert raised.value.failure.kind is FailureKind.EXPERIMENT_INVALID


async def test_ambiguous_remote_timeout_is_serious_and_not_retried(
    store: RunStore,
) -> None:
    adapter = FlakyAdapter(
        failures_before_success=100,
        capabilities=AdapterCapabilities(),
    )
    strategy = _one_turn_strategy()

    with pytest.raises(RunFailedError) as raised:
        await _execute(
            store=store,
            adapter=adapter,
            generator=ScriptedAttackGenerator({strategy.id: ["attack"]}),
        )

    assert adapter.send_calls == 1
    assert raised.value.failure.kind is FailureKind.AMBIGUOUS_SIDE_EFFECT
    persisted = store.get_run(raised.value.run.id)
    assert persisted is not None
    assert persisted.status is RunStatus.FAILED
    assert not store.attempts_for(persisted.id)
    assert store.decisions_for(persisted.id)[0].outcome is ControllerDecisionOutcome.ABANDONED


async def test_persistence_retry_never_reexecutes_target(
    store: RunStore,
    monkeypatch,
) -> None:
    adapter = StableAdapter()
    strategy = _one_turn_strategy()
    original = store.commit_attempt_outcome
    commit_calls = 0

    def flaky_commit(**kwargs) -> None:
        nonlocal commit_calls
        commit_calls += 1
        if commit_calls <= 2:
            raise OperationalError("commit", {}, RuntimeError("database is locked"))
        original(**kwargs)

    monkeypatch.setattr(store, "commit_attempt_outcome", flaky_commit)

    result = await _execute(
        store=store,
        adapter=adapter,
        generator=ScriptedAttackGenerator({strategy.id: ["attack"]}),
        retry_policy=RetryPolicy(
            max_persistence_retries=4,
            base_delay_seconds=0,
            max_delay_seconds=0,
        ),
    )

    assert result.run.status is RunStatus.COMPLETED
    assert commit_calls == 3
    assert adapter.send_calls == 1


async def test_orchestrator_instance_is_single_use_and_preserves_completed_run(
    store: RunStore,
) -> None:
    strategy = _one_turn_strategy()
    request = RunExecutionRequest(
        run=_run(),
        strategies=[strategy],
        actor="customer_a",
    )
    orchestrator = RunOrchestrator(
        executor=_executor(
            StableAdapter(),
            ScriptedAttackGenerator({strategy.id: ["attack"]}),
        ),
        controller=StaticController([strategy.id]),
        store=store,
        retry_policy=RetryPolicy(base_delay_seconds=0, max_delay_seconds=0),
        sleep=_no_sleep,
    )

    completed = await orchestrator.execute(request)
    events_before = store.events_for(completed.run.id)

    with pytest.raises(OrchestratorReuseError):
        await orchestrator.execute(request)

    persisted = store.get_run(completed.run.id)
    assert persisted is not None
    assert persisted.status is RunStatus.COMPLETED
    assert store.events_for(completed.run.id) == events_before


async def test_existing_run_id_is_rejected_without_overwriting_history(
    store: RunStore,
) -> None:
    strategy = _one_turn_strategy()
    request = RunExecutionRequest(
        run=_run(),
        strategies=[strategy],
        actor="customer_a",
    )

    first = RunOrchestrator(
        executor=_executor(
            StableAdapter(),
            ScriptedAttackGenerator({strategy.id: ["attack"]}),
        ),
        controller=StaticController([strategy.id]),
        store=store,
        retry_policy=RetryPolicy(base_delay_seconds=0, max_delay_seconds=0),
        sleep=_no_sleep,
    )
    completed = await first.execute(request)
    events_before = store.events_for(completed.run.id)

    second = RunOrchestrator(
        executor=_executor(
            StableAdapter(),
            ScriptedAttackGenerator({strategy.id: ["different attack"]}),
        ),
        controller=StaticController([strategy.id]),
        store=store,
        retry_policy=RetryPolicy(base_delay_seconds=0, max_delay_seconds=0),
        sleep=_no_sleep,
    )

    with pytest.raises(RunAlreadyExistsError):
        await second.execute(request)

    persisted = store.get_run(completed.run.id)
    assert persisted is not None
    assert persisted.status is RunStatus.COMPLETED
    assert store.events_for(completed.run.id) == events_before
