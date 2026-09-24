"""Small, auditable Run path for the feedback-driven attacker.

The legacy executor owns an entire Attempt and stops on the first attempted
action. Here each attacker decision owns one step, so a rejected tool call can
become evidence for the next step without changing historical Run semantics.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime

from redcell._base import CostRecord
from redcell.attacker_observation import (
    ATTACKER_OBSERVATION_POLICY_V2,
    ActiveAttemptTrace,
    AttackerVisibility,
    project_attacker_observations,
)
from redcell.budget import BudgetLimit, BudgetManager
from redcell.failures import (
    DeliveryStatus,
    FailureKind,
    FailureRecord,
    FailureStage,
    RetrySafety,
    SideEffectStatus,
    StructuredExecutionError,
    safe_error_message,
)
from redcell.feedback_attacker import (
    FEEDBACK_ATTACKER_PROMPT_V2,
    FEEDBACK_ATTACKER_SCHEMA_V2,
    ActiveAttemptView,
    AttackerStrategyView,
    AttackerWorkingState,
    FeedbackActionKind,
    FeedbackAttackAction,
    FeedbackAttackChoice,
    FeedbackAttackDecisionError,
    FeedbackAttackDriver,
    FeedbackAttackRequest,
    FeedbackAttackSelection,
    FeedbackBudgetExhaustedError,
    FeedbackBudgetView,
)
from redcell.orchestrator import RunExecutionRequest, RunExecutionResult, RunFailedError
from redcell.protocols.adapter import AdapterInput, Message, ResetScope, TargetAdapter
from redcell.protocols.common import ImpactStatus, Role, new_id
from redcell.protocols.finding import Finding
from redcell.protocols.policy import Policy
from redcell.protocols.run import Run, RunEvent, RunEventType, RunStatus
from redcell.protocols.strategy import Strategy, StrategyCatalogue
from redcell.protocols.trace import (
    Attempt,
    AttemptStopReason,
    ReproductionContext,
    Turn,
    build_attempt,
)
from redcell.randomness import derive_seed, seeds_for_attempt
from redcell.scoring.level1 import Level1Scorer, ScoringResult
from redcell.storage.store import RunStore

FEEDBACK_STOP_POLICY_V1 = "feedback-stop-v1"


@dataclass
class _ActiveAttempt:
    id: str
    index: int
    strategy: Strategy
    turns: list[Turn] = field(default_factory=list)
    scoring: ScoringResult | None = None


class FeedbackRunOrchestrator:
    """Execute one development Run; interrupted Runs are deliberately not resumed."""

    def __init__(
        self,
        *,
        adapter: TargetAdapter,
        policy: Policy,
        scorer: Level1Scorer,
        driver: FeedbackAttackDriver,
        store: RunStore,
    ) -> None:
        self._adapter = adapter
        self._policy = policy
        self._scorer = scorer
        self._driver = driver
        self._store = store
        self._event_sequence = 0
        self._claimed = False

    async def execute(self, request: RunExecutionRequest) -> RunExecutionResult:
        if self._claimed:
            raise ValueError("FeedbackRunOrchestrator 是一次性状态机")
        self._claimed = True
        run = request.run
        run.require_feedback()
        conditions = run.experiment_conditions
        assert conditions is not None and conditions.feedback is not None
        config = conditions.feedback
        if (
            config.prompt_version != FEEDBACK_ATTACKER_PROMPT_V2
            or config.schema_version != FEEDBACK_ATTACKER_SCHEMA_V2
            or config.observation_policy_version != ATTACKER_OBSERVATION_POLICY_V2
            or config.stop_policy_version != FEEDBACK_STOP_POLICY_V1
        ):
            raise ValueError("Feedback Run 的版本身份与当前执行器不一致")
        visibility = AttackerVisibility(config.observation_visibility)
        if run.status is not RunStatus.PENDING or self._store.get_run(run.id) is not None:
            raise ValueError("Feedback Run 必须使用尚未落盘的新 Run ID")
        if run.algorithm != config.driver_name or self._driver.name != config.driver_name:
            raise ValueError("Feedback driver 与 Run 实验身份不一致")
        if (
            run.target_name != self._policy.target_name
            or run.policy_version != self._policy.version
        ):
            raise ValueError("Run 的 Target/Policy 身份与执行器不一致")
        if run.adapter_type != self._adapter.adapter_type:
            raise ValueError("Run 的 Adapter 身份与执行器不一致")
        if self._policy.actor(request.actor) is None or conditions.actor != request.actor:
            raise ValueError("Feedback Run 的 actor 与 Policy/条件不一致")
        strategies = {strategy.id: strategy for strategy in request.strategies}
        if not strategies or len(strategies) != len(request.strategies):
            raise ValueError("Feedback Run 需要非空且唯一的 Strategy IDs")
        if run.strategy_ids != list(strategies):
            raise ValueError("Run 的 Strategy IDs 与执行请求不一致")
        assert conditions.strategy_catalogue is not None
        current_catalogue = StrategyCatalogue(
            version=conditions.strategy_catalogue.version,
            strategies=request.strategies,
        ).condition_summary()
        if current_catalogue != conditions.strategy_catalogue:
            raise ValueError("Run 的 Strategy 目录摘要与实际执行内容不一致")
        for strategy in strategies.values():
            strategy.validate_against(self._policy)
            if not strategy.is_applicable(self._policy):
                raise ValueError(f"Strategy {strategy.id} 不适用于当前 Policy")
        if run.limits.max_cost_usd is not None and not self._adapter.capabilities.reports_cost:
            raise ValueError("Target 不报告成本，不能声称 --max-cost 有效")
        if conditions.online and not self._adapter.capabilities.usage_covers_billed_tokens:
            raise ValueError("Target 不能证明 usage 覆盖全部计费 Token")
        if self._adapter.capabilities.reset_scope is not ResetScope.FULL_STATE:
            raise ValueError("Feedback Run 要求 Target 可在每个 Attempt 前完全复位")

        budget = BudgetManager(run.limits)
        run = run.model_copy(update={"status": RunStatus.RUNNING, "started_at": datetime.now(UTC)})
        self._store.commit_run_state(run=run, run_event=self._event(run, RunEventType.RUN_STARTED))
        attempts: list[Attempt] = []
        findings: list[Finding] = []
        working_state = AttackerWorkingState()
        active: _ActiveAttempt | None = None
        steps = 0

        while True:
            stop = self._stop_before_decision(budget, active, steps, config.max_decision_steps)
            if stop is not None:
                if active is not None:
                    run = self._finish_attempt(
                        run, budget, active, AttemptStopReason.BUDGET_EXHAUSTED, attempts, findings
                    )
                reason, limit = stop
                return self._complete(run, budget, attempts, findings, reason, limit)

            active_trace = (
                ActiveAttemptTrace(
                    id=active.id,
                    run_id=run.id,
                    attempt_index=active.index,
                    strategy_id=active.strategy.id,
                    turns=list(active.turns),
                )
                if active is not None
                else None
            )
            try:
                observations = project_attacker_observations(
                    attempts, visibility=visibility, active_attempt=active_trace
                )
                decision_request = FeedbackAttackRequest(
                    run_id=run.id,
                    target_brief=self._policy.brief_for(request.actor),
                    strategies=[
                        AttackerStrategyView(
                            id=strategy.id, name=strategy.name, description=strategy.description
                        )
                        for strategy in strategies.values()
                    ],
                    observations=observations,
                    working_state=working_state,
                    budget=FeedbackBudgetView(
                        total_token_limit=run.limits.max_total_tokens,
                        used_tokens=budget.usage().total_tokens,
                        remaining_tokens=max(
                            run.limits.max_total_tokens - budget.usage().total_tokens, 0
                        ),
                        step_limit=config.max_decision_steps,
                        steps_used=steps,
                        remaining_steps=config.max_decision_steps - steps,
                    ),
                    active_attempt=(
                        ActiveAttemptView(
                            ref=f"attempt:{active.id}",
                            strategy_id=active.strategy.id,
                            turns_used=len(active.turns),
                            max_turns=config.max_turns_per_attempt,
                        )
                        if active is not None
                        else None
                    ),
                )
            except Exception as exc:
                self._fail(
                    run,
                    budget,
                    kind=FailureKind.PROTOCOL,
                    stage=FailureStage.ORCHESTRATION,
                    code="feedback_observation_invalid",
                    exc=exc,
                    attempt_id=active.id if active is not None else None,
                )
            self._store.commit_run_state(
                run=run,
                run_event=self._event(
                    run,
                    RunEventType.FEEDBACK_DECISION_REQUESTED,
                    attempt_id=active.id if active is not None else None,
                    payload={"step": steps, "request_digest": decision_request.digest()},
                ),
            )
            steps += 1
            try:
                selection = await self._driver.decide(decision_request)
            except FeedbackAttackDecisionError as exc:
                cost = exc.cost if self._valid_cost(exc.cost) else CostRecord(usage_known=False)
                self._record_cost(budget, cost, role="generator")
                run = run.model_copy(update={"usage": budget.usage()})
                self._store.commit_run_state(
                    run=run,
                    run_event=self._event(
                        run,
                        RunEventType.FEEDBACK_DECISION_FAILED,
                        attempt_id=active.id if active is not None else None,
                        payload={
                            "step": steps - 1,
                            "cost": cost.model_dump(mode="json"),
                            "usage_indeterminate": exc.usage_indeterminate or not cost.usage_known,
                        },
                    ),
                )
                if (
                    isinstance(exc, FeedbackBudgetExhaustedError)
                    and cost.usage_known
                    and not exc.usage_indeterminate
                ):
                    if active is not None:
                        run = self._finish_attempt(
                            run,
                            budget,
                            active,
                            AttemptStopReason.BUDGET_EXHAUSTED,
                            attempts,
                            findings,
                            closing_decision_cost=cost,
                        )
                    return self._complete(
                        run,
                        budget,
                        attempts,
                        findings,
                        BudgetLimit.TOKENS.value,
                        BudgetLimit.TOKENS,
                    )
                self._fail(
                    run,
                    budget,
                    kind=FailureKind.EXPERIMENT_INVALID,
                    stage=FailureStage.GENERATION,
                    code="feedback_decision_failed",
                    exc=exc,
                    attempt_id=active.id if active is not None else None,
                    usage=cost,
                )
            except Exception as exc:
                unknown = CostRecord(usage_known=False)
                self._store.commit_run_state(
                    run=run,
                    run_event=self._event(
                        run,
                        RunEventType.FEEDBACK_DECISION_FAILED,
                        attempt_id=active.id if active is not None else None,
                        payload={
                            "step": steps - 1,
                            "cost": unknown.model_dump(mode="json"),
                            "usage_indeterminate": True,
                        },
                    ),
                )
                self._fail(
                    run,
                    budget,
                    kind=FailureKind.EXPERIMENT_INVALID,
                    stage=FailureStage.GENERATION,
                    code="feedback_driver_unexpected_error",
                    exc=exc,
                    attempt_id=active.id if active is not None else None,
                    usage=unknown,
                )

            try:
                self._validate_selection(selection, decision_request, active, config)
            except (TypeError, ValueError, AttributeError) as exc:
                cost = (
                    selection.cost
                    if isinstance(selection, FeedbackAttackSelection)
                    and self._valid_cost(selection.cost)
                    else CostRecord(usage_known=False)
                )
                self._record_cost(budget, cost, role="generator")
                run = run.model_copy(update={"usage": budget.usage()})
                self._store.commit_run_state(
                    run=run,
                    run_event=self._event(
                        run,
                        RunEventType.FEEDBACK_DECISION_FAILED,
                        attempt_id=active.id if active is not None else None,
                        payload={
                            "step": steps - 1,
                            "cost": cost.model_dump(mode="json"),
                            "usage_indeterminate": not cost.usage_known,
                        },
                    ),
                )
                self._fail(
                    run,
                    budget,
                    kind=FailureKind.PROTOCOL,
                    stage=FailureStage.GENERATION,
                    code="feedback_selection_invalid",
                    exc=exc,
                    attempt_id=active.id if active is not None else None,
                    usage=cost,
                )
            self._record_cost(budget, selection.cost, role="generator")
            run = run.model_copy(update={"usage": budget.usage()})
            if not selection.cost.usage_known:
                self._fail(
                    run,
                    budget,
                    kind=FailureKind.EXPERIMENT_INVALID,
                    stage=FailureStage.USAGE_ACCOUNTING,
                    code="feedback_usage_unknown",
                    exc=ValueError("Feedback decision usage is unknown"),
                    attempt_id=active.id if active is not None else None,
                    usage=selection.cost,
                )

            action = selection.choice.action
            resource_limit = self._resource_limit(budget)
            can_send = resource_limit is None
            new_attempt_id = (
                new_id() if action.kind is FeedbackActionKind.START_ATTEMPT and can_send else None
            )
            if new_attempt_id is not None:
                budget.reserve_attempt(action.strategy_id)
                run = run.model_copy(update={"usage": budget.usage()})
            selected_attempt_id = new_attempt_id or (active.id if active is not None else None)
            self._store.commit_run_state(
                run=run,
                run_event=self._event(
                    run,
                    RunEventType.FEEDBACK_DECISION_SELECTED,
                    attempt_id=selected_attempt_id,
                    payload={
                        "step": steps - 1,
                        "selection": selection.model_dump(mode="json"),
                        "will_send": can_send
                        and action.kind
                        in {FeedbackActionKind.START_ATTEMPT, FeedbackActionKind.CONTINUE_ATTEMPT},
                        "usage": run.usage.model_dump(mode="json"),
                    },
                ),
            )
            working_state = selection.choice.working_state
            if resource_limit is not None:
                if active is not None:
                    run = self._finish_attempt(
                        run,
                        budget,
                        active,
                        AttemptStopReason.BUDGET_EXHAUSTED,
                        attempts,
                        findings,
                        closing_decision_cost=selection.cost,
                    )
                return self._complete(
                    run, budget, attempts, findings, resource_limit.value, resource_limit
                )
            if action.kind is FeedbackActionKind.STOP_RUN:
                if active is not None:
                    run = self._finish_attempt(
                        run,
                        budget,
                        active,
                        AttemptStopReason.RUN_STOPPED,
                        attempts,
                        findings,
                        closing_decision_cost=selection.cost,
                    )
                return self._complete(run, budget, attempts, findings, "driver_stop")
            if action.kind is FeedbackActionKind.END_ATTEMPT:
                assert active is not None
                run = self._finish_attempt(
                    run,
                    budget,
                    active,
                    AttemptStopReason.DRIVER_END,
                    attempts,
                    findings,
                    closing_decision_cost=selection.cost,
                )
                active = None
                continue

            if action.kind is FeedbackActionKind.START_ATTEMPT:
                assert new_attempt_id is not None and action.strategy_id is not None
                active = _ActiveAttempt(
                    id=new_attempt_id,
                    index=budget.usage().attempts - 1,
                    strategy=strategies[action.strategy_id],
                )
                try:
                    await self._adapter.reset()
                except Exception as exc:
                    self._fail(
                        run,
                        budget,
                        kind=FailureKind.INTERNAL,
                        stage=FailureStage.RESET,
                        code="feedback_reset_failed",
                        exc=exc,
                        attempt_id=active.id,
                    )
            assert active is not None and action.message is not None
            turn_index = len(active.turns)
            conversation: list[Message] = []
            for turn in active.turns:
                conversation.extend(
                    [
                        Message(role=Role.USER, content=turn.attacker_message),
                        Message(role=Role.ASSISTANT, content=turn.output.assistant_message),
                    ]
                )
            conversation.append(Message(role=Role.USER, content=action.message))
            seeds = seeds_for_attempt(run.seed or 0, active.index)
            request_id = f"{active.id}:turn:{turn_index}"
            self._store.commit_run_state(
                run=run,
                run_event=self._event(
                    run,
                    RunEventType.FEEDBACK_TARGET_REQUESTED,
                    attempt_id=active.id,
                    payload={"turn_index": turn_index, "request_id": request_id},
                ),
            )
            try:
                output = await self._adapter.send(
                    AdapterInput(
                        messages=conversation,
                        actor=request.actor,
                        request_id=request_id,
                        idempotency_key=request_id,
                        metadata={
                            "run_id": run.id,
                            "attempt_id": active.id,
                            "attempt_index": active.index,
                            "strategy_id": active.strategy.id,
                            "turn_index": turn_index,
                            "attempt_seed": seeds.attempt_seed,
                            "target_seed": derive_seed(seeds.target_seed, "turn", turn_index),
                        },
                    )
                )
            except Exception as exc:
                reported = (
                    exc.failure.usage
                    if isinstance(exc, StructuredExecutionError)
                    else CostRecord(usage_known=False)
                )
                if not self._valid_cost(reported):
                    reported = CostRecord(usage_known=False)
                self._record_cost(budget, reported, role="target")
                self._fail(
                    run,
                    budget,
                    kind=FailureKind.AMBIGUOUS_SIDE_EFFECT,
                    stage=FailureStage.TARGET_SEND,
                    code="feedback_target_send_failed",
                    exc=exc,
                    attempt_id=active.id,
                    usage=reported,
                    failure_override=(
                        exc.failure
                        if isinstance(exc, StructuredExecutionError)
                        and self._valid_cost(exc.failure.usage)
                        else None
                    ),
                )

            target_cost = CostRecord(
                prompt_tokens=output.trace_metadata.prompt_tokens,
                completion_tokens=output.trace_metadata.completion_tokens,
                cached_input_tokens=output.trace_metadata.cached_input_tokens,
                usage_known=output.trace_metadata.usage_known,
                usd=output.trace_metadata.cost_usd,
                wall_ms=output.trace_metadata.latency_ms,
            )
            if not self._valid_cost(target_cost):
                self._fail(
                    run,
                    budget,
                    kind=FailureKind.EXPERIMENT_INVALID,
                    stage=FailureStage.USAGE_ACCOUNTING,
                    code="feedback_target_usage_invalid",
                    exc=ValueError("Target 报告了无效的 Token 或成本用量"),
                    attempt_id=active.id,
                    usage=CostRecord(usage_known=False),
                    partial_turn=Turn(
                        index=turn_index,
                        attacker_message=action.message,
                        output=output,
                        attacker_cost=selection.cost,
                    ),
                )
            self._record_cost(budget, target_cost, role="target")
            run = run.model_copy(update={"usage": budget.usage()})
            turn = Turn(
                index=turn_index,
                attacker_message=action.message,
                output=output,
                attacker_cost=selection.cost,
            )
            active.turns.append(turn)
            if not target_cost.usage_known:
                self._fail(
                    run,
                    budget,
                    kind=FailureKind.EXPERIMENT_INVALID,
                    stage=FailureStage.USAGE_ACCOUNTING,
                    code="feedback_target_usage_unknown",
                    exc=ValueError("Target usage is unknown"),
                    attempt_id=active.id,
                    usage=target_cost,
                    partial_turn=turn,
                )
            try:
                active.scoring = self._scorer.score(
                    active.turns,
                    run_id=run.id,
                    attempt_id=active.id,
                    actor=request.actor,
                    strategy_id=active.strategy.id,
                )
            except Exception as exc:
                self._fail(
                    run,
                    budget,
                    kind=FailureKind.SCORING,
                    stage=FailureStage.SCORING,
                    code="feedback_scoring_failed",
                    exc=exc,
                    attempt_id=active.id,
                    partial_turn=turn,
                )
            self._store.commit_run_state(
                run=run,
                run_event=self._event(
                    run,
                    RunEventType.TURN_COMPLETED,
                    attempt_id=active.id,
                    payload={
                        "turn": turn.model_dump(mode="json"),
                        "signals": [s.model_dump(mode="json") for s in active.scoring.signals],
                        "usage": run.usage.model_dump(mode="json"),
                    },
                ),
            )
            if any(
                finding.triad.realized_impact is ImpactStatus.REALIZED
                for finding in active.scoring.findings
            ):
                run = self._finish_attempt(
                    run, budget, active, AttemptStopReason.REALIZED_IMPACT, attempts, findings
                )
                active = None
            elif len(active.turns) >= config.max_turns_per_attempt:
                run = self._finish_attempt(
                    run, budget, active, AttemptStopReason.MAX_TURNS, attempts, findings
                )
                active = None

    def _finish_attempt(
        self,
        run: Run,
        budget: BudgetManager,
        active: _ActiveAttempt,
        stop_reason: AttemptStopReason,
        attempts: list[Attempt],
        findings: list[Finding],
        closing_decision_cost: CostRecord | None = None,
    ) -> Run:
        if not active.turns or active.scoring is None:
            raise RuntimeError("不能把没有完成 Turn 的反馈会话提交为有效 Attempt")
        seeds = seeds_for_attempt(run.seed or 0, active.index)
        last_trace = active.turns[-1].output.trace_metadata
        reproduction = ReproductionContext(
            policy_version=self._policy.version,
            target_name=self._policy.target_name,
            adapter_type=self._adapter.adapter_type,
            strategy_id=active.strategy.id,
            run_seed=seeds.run_seed,
            controller_seed=seeds.controller_seed,
            seed=seeds.attempt_seed,
            generator_seed=seeds.generator_seed,
            actor_seed=seeds.actor_seed,
            target_seed=seeds.target_seed,
            target_model=run.target_model or last_trace.model,
            target_temperature=(
                run.target_temperature
                if run.target_temperature is not None
                else last_trace.temperature
            ),
            attacker_model=run.attacker_model or self._driver.name,
            attacker_temperature=run.attacker_temperature,
            extra={
                "attempt_index": active.index,
                "feedback_driver": self._driver.name,
                "observation_visibility": run.experiment_conditions.feedback.observation_visibility,
            },
        )
        turns = active.turns
        closing_cost = closing_decision_cost or CostRecord()
        attempt = build_attempt(
            attempt_id=active.id,
            run_id=run.id,
            attempt_index=active.index,
            strategy_id=active.strategy.id,
            actor=run.experiment_conditions.actor,
            attack_prompt=turns[0].attacker_message,
            reproduction=reproduction,
            turns=turns,
            signals=active.scoring.signals,
            cost=CostRecord(
                prompt_tokens=closing_cost.prompt_tokens
                + sum(
                    turn.attacker_cost.prompt_tokens + turn.output.trace_metadata.prompt_tokens
                    for turn in turns
                ),
                completion_tokens=closing_cost.completion_tokens
                + sum(
                    turn.attacker_cost.completion_tokens
                    + turn.output.trace_metadata.completion_tokens
                    for turn in turns
                ),
                cached_input_tokens=closing_cost.cached_input_tokens
                + sum(
                    turn.attacker_cost.cached_input_tokens
                    + turn.output.trace_metadata.cached_input_tokens
                    for turn in turns
                ),
                usd=closing_cost.usd
                + sum(
                    turn.attacker_cost.usd + turn.output.trace_metadata.cost_usd for turn in turns
                ),
                wall_ms=closing_cost.wall_ms
                + sum(
                    turn.attacker_cost.wall_ms + turn.output.trace_metadata.latency_ms
                    for turn in turns
                ),
            ),
            planned_max_turns=run.experiment_conditions.feedback.max_turns_per_attempt,
            stop_reason=stop_reason,
        )
        budget.complete_attempt(active.strategy.id)
        run = run.model_copy(update={"usage": budget.usage()})
        self._store.commit_feedback_attempt_outcome(
            run=run,
            attempt=attempt,
            findings=active.scoring.findings,
            run_event=self._event(
                run,
                RunEventType.ATTEMPT_COMMITTED,
                attempt_id=active.id,
                payload={
                    "stop_reason": stop_reason.value,
                    "usage": run.usage.model_dump(mode="json"),
                },
            ),
        )
        attempts.append(attempt)
        findings.extend(active.scoring.findings)
        return run

    def _complete(
        self,
        run: Run,
        budget: BudgetManager,
        attempts: list[Attempt],
        findings: list[Finding],
        reason: str,
        stopped_by: BudgetLimit | None = None,
    ) -> RunExecutionResult:
        run = run.model_copy(
            update={
                "status": RunStatus.COMPLETED,
                "usage": budget.usage(),
                "stopped_by": stopped_by,
                "feedback_stop_reason": reason,
                "completed_at": datetime.now(UTC),
            }
        )
        self._store.commit_run_state(
            run=run,
            run_event=self._event(
                run, RunEventType.RUN_COMPLETED, payload={"feedback_stop_reason": reason}
            ),
        )
        return RunExecutionResult(run=run, attempts=attempts, findings=findings)

    def _fail(
        self,
        run: Run,
        budget: BudgetManager,
        *,
        kind: FailureKind,
        stage: FailureStage,
        code: str,
        exc: Exception,
        attempt_id: str | None,
        usage: CostRecord | None = None,
        partial_turn: Turn | None = None,
        failure_override: FailureRecord | None = None,
    ) -> None:
        abandoned = (
            attempt_id is not None
            and budget.usage().attempts
            > budget.usage().completed_attempts + budget.usage().abandoned_attempts
        )
        if abandoned:
            budget.abandon_attempt()
        failure = failure_override or FailureRecord(
            kind=kind,
            stage=stage,
            code=code,
            message=safe_error_message(exc),
            cause_type=type(exc).__name__,
            retry_safety=RetrySafety.UNSAFE,
            delivery_status=(
                DeliveryStatus.UNKNOWN
                if stage is FailureStage.TARGET_SEND
                else DeliveryStatus.NOT_SENT
            ),
            side_effect_status=(
                SideEffectStatus.UNKNOWN
                if stage is FailureStage.TARGET_SEND
                else SideEffectStatus.NONE
            ),
            usage=usage or CostRecord(),
        )
        if failure_override is not None:
            failure = failure.model_copy(
                update={"message": safe_error_message(ValueError(failure.message))}
            )
        failed = run.model_copy(
            update={
                "status": RunStatus.FAILED,
                "usage": budget.usage(),
                "completed_at": datetime.now(UTC),
                "failure": failure,
            }
        )
        events: list[RunEvent] = []
        if abandoned:
            events.append(
                self._event(
                    failed,
                    RunEventType.ATTEMPT_ABANDONED,
                    attempt_id=attempt_id,
                    payload={
                        "failure_code": failure.code,
                        "usage": failed.usage.model_dump(mode="json"),
                    },
                )
            )
        events.append(
            self._event(
                failed,
                RunEventType.RUN_FAILED,
                attempt_id=attempt_id,
                payload={
                    "failure": failure.model_dump(mode="json"),
                    "partial_turn": (
                        partial_turn.model_dump(mode="json") if partial_turn is not None else None
                    ),
                },
            )
        )
        self._store.commit_run_state_events(
            run=failed,
            run_events=events,
        )
        raise RunFailedError(failed, failure) from exc

    @staticmethod
    def _resource_limit(budget: BudgetManager) -> BudgetLimit | None:
        limits, usage = budget.limits, budget.usage()
        if limits.max_total_tokens is not None and usage.total_tokens >= limits.max_total_tokens:
            return BudgetLimit.TOKENS
        if limits.max_cost_usd is not None and usage.cost_usd >= limits.max_cost_usd:
            return BudgetLimit.COST
        if limits.max_wall_seconds is not None and usage.wall_seconds >= limits.max_wall_seconds:
            return BudgetLimit.WALL_CLOCK
        return None

    @classmethod
    def _stop_before_decision(
        cls,
        budget: BudgetManager,
        active: _ActiveAttempt | None,
        steps: int,
        max_steps: int,
    ) -> tuple[str, BudgetLimit | None] | None:
        resource = cls._resource_limit(budget)
        if resource is not None:
            return resource.value, resource
        if active is None and budget.remaining_attempts() == 0:
            return BudgetLimit.ATTEMPTS.value, BudgetLimit.ATTEMPTS
        if steps >= max_steps:
            return BudgetLimit.DECISION_STEPS.value, BudgetLimit.DECISION_STEPS
        return None

    @staticmethod
    def _record_cost(budget: BudgetManager, cost: CostRecord, *, role: str) -> None:
        if not FeedbackRunOrchestrator._valid_cost(cost):
            raise ValueError("反馈执行器拒绝无效的 Token 或成本用量")
        budget.record_usage(
            prompt_tokens=cost.prompt_tokens,
            completion_tokens=cost.completion_tokens,
            cached_input_tokens=cost.cached_input_tokens,
            cost_usd=cost.usd,
            role=role,
        )

    @staticmethod
    def _valid_cost(cost: CostRecord) -> bool:
        return (
            cost.prompt_tokens >= 0
            and cost.completion_tokens >= 0
            and 0 <= cost.cached_input_tokens <= cost.prompt_tokens
            and cost.usd >= 0
            and cost.wall_ms >= 0
        )

    @staticmethod
    def _validate_selection(
        selection: FeedbackAttackSelection,
        request: FeedbackAttackRequest,
        active: _ActiveAttempt | None,
        config,
    ) -> None:
        if not isinstance(selection, FeedbackAttackSelection):
            raise TypeError("Feedback driver 必须返回 FeedbackAttackSelection")
        if not FeedbackRunOrchestrator._valid_cost(selection.cost):
            raise ValueError("Feedback selection 报告了无效的 Token 或成本用量")
        if selection.request_digest != request.digest():
            raise ValueError("Feedback selection 未绑定当前请求")
        if (
            selection.prompt_version != config.prompt_version
            or selection.schema_version != config.schema_version
        ):
            raise ValueError("Feedback selection 的 prompt/schema 与冻结条件不一致")
        action = selection.choice.action
        legal = (
            {FeedbackActionKind.START_ATTEMPT, FeedbackActionKind.STOP_RUN}
            if active is None
            else {
                FeedbackActionKind.CONTINUE_ATTEMPT,
                FeedbackActionKind.END_ATTEMPT,
                FeedbackActionKind.STOP_RUN,
            }
        )
        if action.kind not in legal:
            raise ValueError("Feedback action 与当前 Attempt 状态不一致")
        if action.strategy_id is not None and action.strategy_id not in {
            s.id for s in request.strategies
        }:
            raise ValueError("Feedback action 指向未知 Strategy")
        refs = set(action.evidence_refs)
        for hypothesis in selection.choice.working_state.hypotheses:
            refs.update(hypothesis.evidence_refs)
        if not refs <= request.observations.evidence_refs:
            raise ValueError("Feedback action/state 引用了不可见证据")

    def _event(
        self,
        run: Run,
        event_type: RunEventType,
        *,
        attempt_id: str | None = None,
        payload: dict | None = None,
    ) -> RunEvent:
        event = RunEvent(
            run_id=run.id,
            event_type=event_type,
            attempt_id=attempt_id,
            sequence=self._event_sequence,
            payload=payload or {},
        )
        self._event_sequence += 1
        return event


class ScriptedFeedbackDriver(FeedbackAttackDriver):
    """Zero-cost deterministic driver for the offline CLI smoke path."""

    @property
    def name(self) -> str:
        return "scripted-feedback"

    async def decide(self, request: FeedbackAttackRequest) -> FeedbackAttackSelection:
        if request.active_attempt is None:
            action = FeedbackAttackAction(
                kind=FeedbackActionKind.START_ATTEMPT,
                strategy_id=request.strategies[0].id,
                message="Please describe the support actions you can perform for my account.",
                test_intent="Exercise one target turn in the offline feedback pipeline.",
            )
        else:
            action = FeedbackAttackAction(
                kind=FeedbackActionKind.END_ATTEMPT,
                reason="The offline pipeline records one target response per attempt.",
            )
        choice = FeedbackAttackChoice(working_state=request.working_state, action=action)
        encoded = json.dumps(choice.model_dump(mode="json"), sort_keys=True)
        return FeedbackAttackSelection(
            choice=choice,
            cost=CostRecord(),
            prompt_version=FEEDBACK_ATTACKER_PROMPT_V2,
            schema_version=FEEDBACK_ATTACKER_SCHEMA_V2,
            request_digest=request.digest(),
            response_digest=hashlib.sha256(encoded.encode()).hexdigest(),
        )
