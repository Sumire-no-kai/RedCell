"""串行 Run Orchestrator。

调用方只提交 Run 配置、Strategy 集合和默认 Actor;本模块隐藏预算准入、
Controller 状态机、安全重试、语义检查点、原子提交和终态清理。
"""

from __future__ import annotations

import asyncio
import random
import secrets
from collections.abc import Awaitable, Callable, Sequence
from datetime import UTC, datetime
from functools import partial
from typing import TypeVar

from sqlalchemy.exc import OperationalError

from redcell.budget import BudgetLimit, BudgetManager
from redcell.controller import (
    ControllerDriver,
    ControllerInvocation,
    ControllerInvocationStatus,
    ControllerSelectionError,
    LLMControllerAdapter,
    UsageStatus,
)
from redcell.executor import (
    AttemptExecutionError,
    ConversationExecutor,
    ExecutionRequest,
    ExecutionResult,
    TurnCheckpoint,
)
from redcell.failures import (
    DeliveryStatus,
    FailureKind,
    FailureRecord,
    FailureStage,
    RetrySafety,
    SeriousExecutionError,
    SideEffectStatus,
    safe_error_message,
)
from redcell.generation import GenerationMemory
from redcell.history import build_controller_evidence, build_generation_memory
from redcell.protocols.common import RedCellModel, new_id
from redcell.protocols.finding import Finding
from redcell.protocols.run import GenerationMemoryMode, Run, RunEvent, RunEventType, RunStatus
from redcell.protocols.strategy import Strategy
from redcell.protocols.trace import Attempt, CostRecord
from redcell.randomness import controller_seed_for, derive_seed
from redcell.retry import ReliabilityPolicy, RetryPolicy
from redcell.search.base import (
    ControllerDecision,
    ControllerDecisionOutcome,
    ControllerProtocolError,
    SearchController,
)
from redcell.storage.store import RunStore

Sleep = Callable[[float], Awaitable[None]]
UtcNow = Callable[[], datetime]
T = TypeVar("T")


class RunExecutionRequest(RedCellModel):
    run: Run
    strategies: list[Strategy]
    actor: str


class RunExecutionResult(RedCellModel):
    run: Run
    attempts: list[Attempt]
    findings: list[Finding]


class RunFailedError(RuntimeError):
    """Run 已被可靠地标记为 FAILED,调用层仍需明确处理失败。"""

    def __init__(self, run: Run, failure: FailureRecord) -> None:
        super().__init__(f"Run {run.id} 失败: {failure.code}: {failure.message}")
        self.run = run
        self.failure = failure


class OrchestratorReuseError(RuntimeError):
    """同一个有状态 Orchestrator 实例被用于第二个 execute 调用。"""


class RunAlreadyExistsError(RuntimeError):
    """Store 中已经存在同一 run_id;拒绝覆盖既有运行历史。"""


class RunResumeError(RuntimeError):
    """A persisted Run cannot safely be resumed with the supplied runtime."""


class RunOrchestrator:
    """一条窄接口背后的完整串行运行状态机。

    实例是一次性的:Controller 决策历史与事件序号都属于一个 Run。
    新 Run 必须创建新的 Controller 和 RunOrchestrator。
    """

    def __init__(
        self,
        *,
        executor: ConversationExecutor,
        controller: SearchController | None = None,
        driver: ControllerDriver | None = None,
        store: RunStore,
        retry_policy: RetryPolicy | None = None,
        reliability_policy: ReliabilityPolicy | None = None,
        sleep: Sleep = asyncio.sleep,
        utcnow: UtcNow | None = None,
    ) -> None:
        self._executor = executor
        if (controller is None) == (driver is None):
            raise ValueError("必须且只能提供 controller 或 driver")
        self._controller = controller
        self._driver = driver
        self._driver_decisions: list[ControllerDecision] = []
        self._driver_pending: int | None = None
        self._store = store
        self._retry_policy = retry_policy or RetryPolicy()
        self._reliability = reliability_policy or ReliabilityPolicy()
        self._sleep = sleep
        self._utcnow = utcnow or (lambda: datetime.now(UTC))
        self._event_sequence = 0
        self._claimed = False

    async def execute(self, request: RunExecutionRequest) -> RunExecutionResult:
        """执行一个新的 PENDING Run 到预算终点。"""
        return await self._run(request, resume=False)

    async def resume(self, request: RunExecutionRequest) -> RunExecutionResult:
        """从已原子提交的 Attempt 边界继续一个 RUNNING Run。"""
        return await self._run(request, resume=True)

    async def _run(
        self,
        request: RunExecutionRequest,
        *,
        resume: bool,
    ) -> RunExecutionResult:
        if self._claimed:
            raise OrchestratorReuseError("RunOrchestrator 是一次性状态机;新 Run 必须创建新实例")
        self._claimed = True

        run = request.run.model_copy(deep=True)
        strategies = list(request.strategies)
        run = self._prepare_run(run, strategies)
        # 必须在这里播种,不能交给调用方:run.seed 可能刚在 _prepare_run 里生成,
        # 调用方构造 Controller 时还不知道它。preflight 会复核这一条真的生效了。
        retry_rng = random.Random(derive_seed(run.seed or 0, "retry-backoff"))
        existing = await self._persist(lambda: self._store.get_run(run.id), retry_rng)
        if existing is not None and not resume:
            raise RunAlreadyExistsError(
                f"Run '{run.id}' 已存在;请使用 resume 命令恢复 RUNNING Run,不要覆盖历史。"
            )
        if resume:
            if existing is None:
                raise RunResumeError(f"Run '{run.id}' 不存在,无法恢复")
            run = existing
            events = await self._persist(lambda: self._store.events_for(run.id), retry_rng)
            self._event_sequence = max((event.sequence for event in events), default=-1) + 1
            retry_rng = random.Random(derive_seed(run.seed or 0, "retry-backoff-resume"))
        elif self._controller is not None:
            self._controller.seed(controller_seed_for(run.seed or 0))

        try:
            if resume:
                self._preflight_resume(run, strategies, request.actor)
            else:
                self._preflight(run, strategies, request.actor)
        except Exception as exc:
            if resume:
                raise RunResumeError(f"Run '{run.id}' 不能安全恢复:{exc}") from exc
            failure = _serious_failure(exc, FailureStage.PREFLIGHT)
            failed = self._failed_run(run, failure)
            event = self._event(
                failed,
                RunEventType.RUN_FAILED,
                payload={"failure": failure.model_dump(mode="json")},
            )
            await self._persist(
                lambda: self._store.commit_run_state(run=failed, run_event=event),
                retry_rng,
            )
            raise RunFailedError(failed, failure) from exc

        if not resume:
            run = run.model_copy(
                update={
                    "status": RunStatus.RUNNING,
                    "started_at": self._utcnow(),
                    "strategy_ids": [strategy.id for strategy in strategies],
                    # 把实际生效的可靠性阈值钉进 Run,而且必须在**首次落盘之前** ——
                    # 事后只看结果是看不出当时用的是哪一组阈值的,而它决定了
                    # "这次 run 算不算数"。中途崩溃的 run 也因此带着它。
                    "reliability": self._reliability,
                }
            )
            started = self._event(run, RunEventType.RUN_STARTED)
            await self._persist(
                lambda: self._store.commit_run_state(run=run, run_event=started),
                retry_rng,
            )
            budget = BudgetManager(run.limits)
            attempts: list[Attempt] = []
            findings: list[Finding] = []
            consecutive_abandoned = 0
            consecutive_abandoned_selections = 0
        else:
            budget = BudgetManager.from_usage(run.limits, run.usage)
            run, budget = await self._resolve_interrupted_attempt(run, budget, retry_rng)
            invocations = await self._persist(
                lambda: self._store.controller_invocations_for(run.id), retry_rng
            )
            decisions = await self._persist(lambda: self._store.decisions_for(run.id), retry_rng)
            requested = [
                invocation
                for invocation in invocations
                if invocation.status is ControllerInvocationStatus.REQUESTED
            ]
            if requested:
                for invocation in requested:
                    terminal = invocation.model_copy(
                        update={
                            "status": ControllerInvocationStatus.INDETERMINATE,
                            "usage_status": UsageStatus.UNKNOWN,
                            "failure": {"code": "resume_after_requested_invocation"},
                        }
                    )
                    await self._persist(
                        lambda terminal=terminal: self._store.save_controller_invocation(terminal),
                        retry_rng,
                    )
                failure = _indeterminate_controller_failure(
                    {"code": "resume_after_requested_invocation"}
                )
                failed = self._failed_run(run, failure)
                failed_event = self._event(
                    failed,
                    RunEventType.RUN_FAILED,
                    payload={"failure": failure.model_dump(mode="json")},
                )
                await self._persist(
                    partial(self._store.commit_run_state, run=failed, run_event=failed_event),
                    retry_rng,
                )
                raise RunFailedError(failed, failure)
            referenced_invocations = {
                decision.invocation_id
                for decision in decisions
                if decision.invocation_id is not None
            }
            orphaned_succeeded = [
                invocation
                for invocation in invocations
                if invocation.status is ControllerInvocationStatus.SUCCEEDED
                and invocation.id not in referenced_invocations
            ]
            if orphaned_succeeded:
                for invocation in orphaned_succeeded:
                    budget.record_usage(
                        prompt_tokens=invocation.cost.prompt_tokens,
                        completion_tokens=invocation.cost.completion_tokens,
                        cached_input_tokens=invocation.cost.cached_input_tokens,
                        cost_usd=invocation.cost.usd,
                        role="controller",
                    )
                failure = _orphaned_controller_invocation_failure(orphaned_succeeded)
                failed = self._failed_run(run.model_copy(update={"usage": budget.usage()}), failure)
                failed_event = self._event(
                    failed,
                    RunEventType.RUN_FAILED,
                    payload={"failure": failure.model_dump(mode="json")},
                )
                await self._persist(
                    partial(self._store.commit_run_state, run=failed, run_event=failed_event),
                    retry_rng,
                )
                raise RunFailedError(failed, failure)
            if self._controller is not None:
                self._controller = self._restore_controller(run, decisions)
            else:
                self._restore_driver(decisions)
            attempts = await self._persist(lambda: self._store.attempts_for(run.id), retry_rng)
            findings = await self._persist(lambda: self._store.findings_for(run.id), retry_rng)
            consecutive_abandoned = _trailing_abandoned(decisions)
            consecutive_abandoned_selections = _trailing_selection_abandonments(events)

        by_id = {strategy.id: strategy for strategy in strategies}
        current_attempt_id: str | None = None
        current_result: ExecutionResult | None = None
        last_abandoned_failure: FailureRecord | None = None

        try:
            while budget.exhausted() is None:
                available = budget.available_strategies(list(by_id))
                if not available:
                    run = self._completed_run(
                        run,
                        budget,
                        stopped_by=BudgetLimit.STRATEGY_SHARE,
                    )
                    break

                try:
                    strategy_id = await self._select_strategy(
                        run, available, attempts, budget, retry_rng, request.actor
                    )
                except ControllerSelectionError as exc:
                    if exc.invocation.status is ControllerInvocationStatus.INDETERMINATE:
                        failure = _indeterminate_controller_failure(exc.invocation.failure)
                        failed = self._failed_run(
                            run.model_copy(update={"usage": budget.usage()}), failure
                        )
                        failed_event = self._event(
                            failed,
                            RunEventType.RUN_FAILED,
                            payload={"failure": failure.model_dump(mode="json")},
                        )
                        await self._persist(
                            partial(
                                self._store.commit_run_state,
                                run=failed,
                                run_event=failed_event,
                            ),
                            retry_rng,
                        )
                        raise RunFailedError(failed, failure) from exc
                    budget.abandon_selection()
                    consecutive_abandoned_selections += 1
                    run = run.model_copy(update={"usage": budget.usage()})
                    if run.selection_reliability.invalidates(
                        successful=run.usage.successful_selections,
                        abandoned=run.usage.abandoned_selections,
                        consecutive_abandoned=consecutive_abandoned_selections,
                    ):
                        failure = _selection_reliability_failure(run, exc.invocation.failure)
                        failed = self._failed_run(run, failure)
                        failed_event = self._event(
                            failed,
                            RunEventType.RUN_FAILED,
                            payload={"failure": failure.model_dump(mode="json")},
                        )
                        await self._persist(
                            partial(
                                self._store.commit_run_state,
                                run=failed,
                                run_event=failed_event,
                            ),
                            retry_rng,
                        )
                        raise RunFailedError(failed, failure) from exc
                    event = self._event(
                        run,
                        RunEventType.SELECTION_ABANDONED,
                        payload={
                            "selection_abandonment": exc.invocation.model_dump(mode="json"),
                            "usage": run.usage.model_dump(mode="json"),
                        },
                    )
                    await self._persist(
                        partial(self._store.commit_run_state, run=run, run_event=event), retry_rng
                    )
                    continue
                consecutive_abandoned_selections = 0
                strategy = by_id[strategy_id]
                attempt_index = budget.usage().attempts
                attempt_id = new_id()
                current_attempt_id = attempt_id
                budget.reserve_attempt(strategy_id)
                run = run.model_copy(update={"usage": budget.usage()})

                pending_decision = self._latest_decision()
                if pending_decision is None or pending_decision.attempt_index != attempt_index:
                    raise RuntimeError("Controller decision index 与逻辑 Attempt index 不一致")
                selected_event = self._event(
                    run,
                    RunEventType.DECISION_SELECTED,
                    attempt_id=attempt_id,
                    payload={
                        "decision": pending_decision.model_dump(mode="json"),
                        "usage": run.usage.model_dump(mode="json"),
                    },
                )
                await self._persist(
                    partial(
                        self._store.commit_decision_selected,
                        run=run,
                        attempt_id=attempt_id,
                        decision=pending_decision,
                        run_event=selected_event,
                    ),
                    retry_rng,
                )

                execution_request = ExecutionRequest(
                    attempt_id=attempt_id,
                    run_id=run.id,
                    strategy=strategy,
                    actor=request.actor,
                    run_seed=run.seed or 0,
                    attempt_index=attempt_index,
                    target_model=run.target_model,
                    target_temperature=run.target_temperature,
                    attacker_model=run.attacker_model,
                    attacker_temperature=run.attacker_temperature,
                    cross_attempt_memory=self._generation_memory(run, attempts, strategy_id),
                )

                try:
                    result = await self._execute_with_retry(
                        run=run,
                        request=execution_request,
                        budget=budget,
                        retry_rng=retry_rng,
                    )
                    current_result = result
                except AttemptExecutionError as exc:
                    budget.abandon_attempt()
                    self._abandon_selection(strategy_id, _failure_reason(exc.failure))
                    consecutive_abandoned += 1
                    last_abandoned_failure = exc.failure
                    run = run.model_copy(update={"usage": budget.usage()})

                    invalid = exc.failure.serious or self._reliability.invalidates_run(
                        logical_attempts=run.usage.attempts,
                        abandoned_attempts=run.usage.abandoned_attempts,
                        consecutive_abandoned=consecutive_abandoned,
                    )
                    terminal_failure = (
                        exc.failure
                        if exc.failure.serious
                        else _reliability_failure(run, exc.failure)
                    )
                    if invalid:
                        run = self._failed_run(run, terminal_failure)

                    abandoned_event = self._event(
                        run,
                        RunEventType.ATTEMPT_ABANDONED,
                        attempt_id=attempt_id,
                        payload={
                            "failure": exc.failure.model_dump(mode="json"),
                            "usage": run.usage.model_dump(mode="json"),
                            "partial_turns": [
                                turn.model_dump(mode="json") for turn in exc.partial_turns
                            ],
                        },
                    )
                    events = [abandoned_event]
                    if invalid:
                        events.append(
                            self._event(
                                run,
                                RunEventType.RUN_FAILED,
                                payload={"failure": terminal_failure.model_dump(mode="json")},
                            )
                        )
                    await self._persist(
                        partial(
                            self._store.commit_abandonment,
                            run=run,
                            attempt_id=attempt_id,
                            decision=self._require_latest_decision(),
                            run_events=events,
                        ),
                        retry_rng,
                    )
                    if invalid:
                        raise RunFailedError(run, terminal_failure) from exc
                    current_attempt_id = None
                    current_result = None
                    continue

                if not result.attempt.cost.usage_known:
                    generator_cost, target_cost = _attempt_role_costs(result.attempt)
                    budget.record_attempt_usage(
                        total=result.attempt.cost,
                        generator=generator_cost,
                        target=target_cost,
                    )
                    budget.abandon_attempt()
                    failure = _unknown_attempt_usage_failure(
                        generator_known=generator_cost.usage_known,
                        target_known=target_cost.usage_known,
                    )
                    self._abandon_selection(strategy_id, _failure_reason(failure))
                    failed = self._failed_run(
                        run.model_copy(update={"usage": budget.usage()}), failure
                    )
                    events = [
                        self._event(
                            failed,
                            RunEventType.ATTEMPT_ABANDONED,
                            attempt_id=attempt_id,
                            payload={
                                "failure": failure.model_dump(mode="json"),
                                "usage": failed.usage.model_dump(mode="json"),
                                "partial_turns": [
                                    turn.model_dump(mode="json") for turn in result.attempt.turns
                                ],
                            },
                        ),
                        self._event(
                            failed,
                            RunEventType.RUN_FAILED,
                            payload={"failure": failure.model_dump(mode="json")},
                        ),
                    ]
                    await self._persist(
                        partial(
                            self._store.commit_abandonment,
                            run=failed,
                            attempt_id=attempt_id,
                            decision=self._require_latest_decision(),
                            run_events=events,
                        ),
                        retry_rng,
                    )
                    raise RunFailedError(failed, failure)

                generator_cost, target_cost = _attempt_role_costs(result.attempt)
                budget.record_attempt_usage(
                    total=result.attempt.cost,
                    generator=generator_cost,
                    target=target_cost,
                )
                budget.complete_attempt(strategy_id)
                self._complete_selection(strategy_id, result.attempt.reward)
                consecutive_abandoned = 0
                run = run.model_copy(update={"usage": budget.usage()})
                committed_event = self._event(
                    run,
                    RunEventType.ATTEMPT_COMMITTED,
                    attempt_id=attempt_id,
                    payload={
                        "reward": result.attempt.reward,
                        "finding_ids": [finding.id for finding in result.findings],
                        "usage": run.usage.model_dump(mode="json"),
                    },
                )
                await self._persist(
                    partial(
                        self._store.commit_attempt_outcome,
                        run=run,
                        attempt=result.attempt,
                        findings=result.findings,
                        decision=self._require_latest_decision(),
                        run_event=committed_event,
                    ),
                    retry_rng,
                )
                attempts.append(result.attempt)
                findings.extend(result.findings)
                current_attempt_id = None
                current_result = None

            if run.status is not RunStatus.COMPLETED:
                stopped_by = budget.exhausted()
                if stopped_by is None:
                    raise RuntimeError("Orchestrator 离开循环但预算没有终止原因")
                run = self._completed_run(run, budget, stopped_by=stopped_by)

            if self._reliability.invalidates_completed_run(
                logical_attempts=run.usage.attempts,
                completed_attempts=run.usage.completed_attempts,
                abandoned_attempts=run.usage.abandoned_attempts,
            ):
                basis = last_abandoned_failure or _empty_run_failure()
                failure = _reliability_failure(run, basis)
                run = self._failed_run(run, failure)
                failed_event = self._event(
                    run,
                    RunEventType.RUN_FAILED,
                    payload={"failure": failure.model_dump(mode="json")},
                )
                await self._persist(
                    partial(
                        self._store.commit_run_state,
                        run=run,
                        run_event=failed_event,
                    ),
                    retry_rng,
                )
                raise RunFailedError(run, failure)

            completed = self._event(
                run,
                RunEventType.RUN_COMPLETED,
                payload={"usage": run.usage.model_dump(mode="json")},
            )
            await self._persist(
                lambda: self._store.commit_run_state(run=run, run_event=completed),
                retry_rng,
            )
            return RunExecutionResult(run=run, attempts=attempts, findings=findings)
        except asyncio.CancelledError:
            await asyncio.shield(
                self._abort(
                    run,
                    budget,
                    retry_rng,
                    current_attempt_id,
                    current_result,
                )
            )
            raise
        except RunFailedError:
            raise
        except Exception as exc:
            failure = _serious_failure(exc, FailureStage.ORCHESTRATION)
            failed = self._failed_run(
                run.model_copy(update={"usage": budget.usage()}),
                failure,
            )
            if self._has_pending_selection():
                strategy_id = self._require_latest_decision().selected_strategy_id
                self._abandon_selection(strategy_id, _failure_reason(failure))
                budget.abandon_attempt()
                failed = failed.model_copy(update={"usage": budget.usage()})
            failed_event = self._event(
                failed,
                RunEventType.RUN_FAILED,
                attempt_id=(current_attempt_id if current_result is not None else None),
                payload={"failure": failure.model_dump(mode="json")},
            )
            latest_decision = self._latest_decision()
            if (
                current_attempt_id is not None
                and current_result is not None
                and latest_decision is not None
                and latest_decision.outcome is ControllerDecisionOutcome.COMPLETED
            ):
                await self._persist(
                    partial(
                        self._store.commit_attempt_outcome,
                        run=failed,
                        attempt=current_result.attempt,
                        findings=current_result.findings,
                        decision=latest_decision,
                        run_event=failed_event,
                    ),
                    retry_rng,
                )
            elif (
                current_attempt_id is not None
                and latest_decision is not None
                and latest_decision.outcome is ControllerDecisionOutcome.ABANDONED
            ):
                abandoned_event = self._event(
                    failed,
                    RunEventType.ATTEMPT_ABANDONED,
                    attempt_id=current_attempt_id,
                    payload={
                        "failure": failure.model_dump(mode="json"),
                        "usage": failed.usage.model_dump(mode="json"),
                    },
                )
                await self._persist(
                    partial(
                        self._store.commit_abandonment,
                        run=failed,
                        attempt_id=current_attempt_id,
                        decision=latest_decision,
                        run_events=[abandoned_event, failed_event],
                    ),
                    retry_rng,
                )
            else:
                await self._persist(
                    lambda: self._store.commit_run_state(
                        run=failed,
                        run_event=failed_event,
                    ),
                    retry_rng,
                )
            raise RunFailedError(failed, failure) from exc

    async def _execute_with_retry(
        self,
        *,
        run: Run,
        request: ExecutionRequest,
        budget: BudgetManager,
        retry_rng: random.Random,
    ) -> ExecutionResult:
        retry_index = 0
        while True:
            current = request.model_copy(update={"execution_retry_index": retry_index})
            try:
                return await self._executor.execute(
                    current,
                    on_turn_completed=lambda checkpoint: self._checkpoint(
                        run,
                        checkpoint,
                        retry_rng,
                    ),
                )
            except AttemptExecutionError as exc:
                budget.record_attempt_usage(
                    total=exc.cost,
                    generator=exc.generator_cost,
                    target=exc.target_cost,
                )
                max_retries = self._retry_policy.max_retries_for(exc.failure)
                if exc.failure.stage is FailureStage.PERSISTENCE or retry_index >= max_retries:
                    raise

                retry_index += 1
                budget.record_retry()
                delay = self._retry_policy.delay_seconds(
                    exc.failure,
                    retry_index,
                    rng=retry_rng,
                )
                retry_event = self._event(
                    run.model_copy(update={"usage": budget.usage()}),
                    RunEventType.RETRY_SCHEDULED,
                    attempt_id=request.attempt_id,
                    payload={
                        "retry_number": retry_index,
                        "delay_seconds": delay,
                        "failure": exc.failure.model_dump(mode="json"),
                    },
                )
                retry_run = run.model_copy(update={"usage": budget.usage()})
                await self._persist(
                    partial(
                        self._store.commit_run_state,
                        run=retry_run,
                        run_event=retry_event,
                    ),
                    retry_rng,
                )
                await self._sleep(delay)

    async def _checkpoint(
        self,
        run: Run,
        checkpoint: TurnCheckpoint,
        retry_rng: random.Random,
    ) -> None:
        run_event = self._event(
            run,
            RunEventType.TURN_COMPLETED,
            attempt_id=checkpoint.attempt_id,
            payload={"checkpoint": checkpoint.model_dump(mode="json")},
        )
        await self._persist(lambda: self._store.save_event(run_event), retry_rng)

    async def _abort(
        self,
        run: Run,
        budget: BudgetManager,
        retry_rng: random.Random,
        current_attempt_id: str | None,
        current_result: ExecutionResult | None,
    ) -> None:
        if self._has_pending_selection():
            selected = self._require_latest_decision().selected_strategy_id
            self._abandon_selection(selected, "user cancelled")
            budget.abandon_attempt()
        aborted = run.model_copy(
            update={
                "status": RunStatus.ABORTED,
                "usage": budget.usage(),
                "completed_at": self._utcnow(),
            }
        )
        event = self._event(aborted, RunEventType.RUN_ABORTED)
        latest_decision = self._latest_decision()
        if (
            current_attempt_id is not None
            and current_result is not None
            and latest_decision is not None
            and latest_decision.outcome is ControllerDecisionOutcome.COMPLETED
        ):
            await self._persist(
                partial(
                    self._store.commit_attempt_outcome,
                    run=aborted,
                    attempt=current_result.attempt,
                    findings=current_result.findings,
                    decision=latest_decision,
                    run_event=event.model_copy(update={"attempt_id": current_attempt_id}),
                ),
                retry_rng,
            )
        elif (
            current_attempt_id is not None
            and latest_decision is not None
            and latest_decision.outcome is ControllerDecisionOutcome.ABANDONED
        ):
            abandoned = self._event(
                aborted,
                RunEventType.ATTEMPT_ABANDONED,
                attempt_id=current_attempt_id,
                payload={
                    "reason": "user cancelled",
                    "usage": aborted.usage.model_dump(mode="json"),
                },
            )
            await self._persist(
                partial(
                    self._store.commit_abandonment,
                    run=aborted,
                    attempt_id=current_attempt_id,
                    decision=latest_decision,
                    run_events=[abandoned, event],
                ),
                retry_rng,
            )
        else:
            await self._persist(
                lambda: self._store.commit_run_state(run=aborted, run_event=event),
                retry_rng,
            )

    async def _persist(
        self,
        operation: Callable[[], T],
        retry_rng: random.Random,
    ) -> T:
        """执行一次有界重试的 Store 操作;写入只重放同一组稳定 ID。"""
        retry_number = 0
        while True:
            try:
                return operation()
            except OperationalError as exc:
                transient = _persistence_failure(exc, fatal=False)
                max_retries = self._retry_policy.max_retries_for(transient)
                if retry_number >= max_retries:
                    raise SeriousExecutionError(_persistence_failure(exc, fatal=True)) from exc
                retry_number += 1
                delay = self._retry_policy.delay_seconds(
                    transient,
                    retry_number,
                    rng=retry_rng,
                )
                await self._sleep(delay)
            except SeriousExecutionError:
                raise
            except Exception as exc:
                raise SeriousExecutionError(_persistence_failure(exc, fatal=True)) from exc

    def _prepare_run(self, run: Run, strategies: Sequence[Strategy]) -> Run:
        seed = run.seed if run.seed is not None else secrets.randbits(63)
        strategy_ids = [strategy.id for strategy in strategies]
        return run.model_copy(update={"seed": seed, "strategy_ids": strategy_ids})

    def _preflight(self, run: Run, strategies: list[Strategy], actor: str) -> None:
        if run.status is not RunStatus.PENDING:
            raise ValueError("RunOrchestrator 只能启动 PENDING Run")
        if run.limits.max_attempts is None:
            raise ValueError("RunOrchestrator 必须设置 max_attempts,防止无法停止的 Run")
        if not strategies:
            raise ValueError("Run 至少需要一个 Strategy")
        strategy_ids = [strategy.id for strategy in strategies]
        if len(strategy_ids) != len(set(strategy_ids)):
            raise ValueError("Run strategies 不能包含重复 id")
        if self._controller is not None and self._controller.decisions:
            raise ValueError("Controller 已有历史,不能复用于新 Run")
        if run.algorithm != self._controller_name():
            raise ValueError(
                f"Run.algorithm='{run.algorithm}' 与 Controller '{self._controller_name()}' 不一致"
            )
        expected_seed = controller_seed_for(run.seed or 0)
        if self._controller is not None and self._controller.controller_seed != expected_seed:
            # 子类若覆写 seed() 而没有真正生效,这里当场炸;否则记录下来的
            # controller_seed 会是一个假数字,而重放失败要到很久以后才发现。
            raise ValueError(
                f"Controller 的种子({self._controller.controller_seed})与从 run.seed "
                f"派生的值({expected_seed})不一致;记录下来的 controller_seed 将无法重放"
            )
        # ⚠️ **两侧都要检查。** attacker 的开销自 2026-08-02 起计入 Run 预算,
        # 只校验 target 会留下同一个盲点:上限只管住一半,却看起来在管全部。
        blind = [
            side
            for side, ok in (
                ("目标", self._executor.adapter_capabilities.reports_cost),
                ("攻击方", self._executor.generator_reports_cost),
            )
            if not ok
        ]
        if run.limits.max_cost_usd is not None and blind:
            raise ValueError(
                f"{'与'.join(blind)}不报告成本(reports_cost=False),"
                "max_cost_usd 将少算这一侧的开销 —— 那是一个假的安全网。"
                "请移除该上限,或给对应 provider 填上真实单价(TokenPricing)"
            )
        if run.target_name != self._executor.target_name:
            raise ValueError("Run.target_name 与 Executor Policy 不一致")
        if run.policy_version != self._executor.policy_version:
            raise ValueError("Run.policy_version 与 Executor Policy 不一致")
        if run.adapter_type != self._executor.adapter_type:
            raise ValueError("Run.adapter_type 与 TargetAdapter 不一致")

        for strategy in strategies:
            self._executor.validate(
                ExecutionRequest(
                    attempt_id=f"preflight:{strategy.id}",
                    run_id=run.id,
                    strategy=strategy,
                    actor=actor,
                    run_seed=run.seed or 0,
                    attempt_index=0,
                )
            )

    def _preflight_resume(self, run: Run, strategies: list[Strategy], actor: str) -> None:
        """Validate a continuation without changing the persisted experiment."""
        if run.status is not RunStatus.RUNNING:
            raise ValueError("只有状态为 RUNNING 的 Run 可以恢复")
        if run.seed is None:
            raise ValueError("缺少 run.seed,无法重建随机决策历史")
        if run.limits.max_attempts is None:
            raise ValueError("Run 缺少 max_attempts,无法保证恢复后能停止")
        strategy_ids = [strategy.id for strategy in strategies]
        if strategy_ids != run.strategy_ids:
            raise ValueError("当前 Strategy 集合/顺序与落盘 Run 不一致")
        if run.algorithm != self._controller_name():
            raise ValueError("Run.algorithm 与当前 Controller 不一致")
        if self._controller is not None and self._controller.decisions:
            raise ValueError("Controller 已有历史,不能用于恢复")
        if run.target_name != self._executor.target_name:
            raise ValueError("Run.target_name 与 Executor Policy 不一致")
        if run.policy_version != self._executor.policy_version:
            raise ValueError("Run.policy_version 与 Executor Policy 不一致")
        if run.adapter_type != self._executor.adapter_type:
            raise ValueError("Run.adapter_type 与 TargetAdapter 不一致")
        blind = [
            side
            for side, ok in (
                ("目标", self._executor.adapter_capabilities.reports_cost),
                ("攻击方", self._executor.generator_reports_cost),
            )
            if not ok
        ]
        if run.limits.max_cost_usd is not None and blind:
            raise ValueError("恢复运行时任一侧不报告成本,无法守住已记录的 max_cost")
        for strategy in strategies:
            self._executor.validate(
                ExecutionRequest(
                    attempt_id=f"resume-preflight:{strategy.id}",
                    run_id=run.id,
                    strategy=strategy,
                    actor=actor,
                    run_seed=run.seed,
                    attempt_index=0,
                )
            )

    async def _resolve_interrupted_attempt(
        self,
        run: Run,
        budget: BudgetManager,
        retry_rng: random.Random,
    ) -> tuple[Run, BudgetManager]:
        """Atomically abandon a selected-but-uncommitted attempt before resuming.

        We intentionally never replay this attempt.  Between selection being
        committed and process death, the target may already have observed a
        request or tool side effect; replaying would make the trace lie.
        """
        pending = await self._persist(lambda: self._store.pending_decision_for(run.id), retry_rng)
        if pending is None:
            event = self._event(
                run,
                RunEventType.RUN_RESUMED,
                payload={"recovery_boundary": "attempt", "recovered_pending_attempt_id": None},
            )
            await self._persist(
                lambda: self._store.commit_run_state(run=run, run_event=event), retry_rng
            )
            return run, budget

        attempt_id, decision = pending
        payload = decision.model_dump(mode="python")
        payload.update(
            outcome=ControllerDecisionOutcome.ABANDONED,
            observed_score=None,
            failure_reason="resume: attempt interrupted before outcome was atomically committed",
        )
        abandoned = ControllerDecision.model_validate(payload)
        budget.abandon_attempt()
        recovered = run.model_copy(update={"usage": budget.usage()})
        abandoned_event = self._event(
            recovered,
            RunEventType.ATTEMPT_ABANDONED,
            attempt_id=attempt_id,
            payload={
                "reason": abandoned.failure_reason,
                "recovered_on_resume": True,
                "usage": recovered.usage.model_dump(mode="json"),
            },
        )
        resumed_event = self._event(
            recovered,
            RunEventType.RUN_RESUMED,
            payload={"recovery_boundary": "attempt", "recovered_pending_attempt_id": attempt_id},
        )
        await self._persist(
            partial(
                self._store.commit_abandonment,
                run=recovered,
                attempt_id=attempt_id,
                decision=abandoned,
                run_events=[abandoned_event, resumed_event],
            ),
            retry_rng,
        )
        return recovered, budget

    def _restore_controller(
        self,
        run: Run,
        decisions: Sequence[ControllerDecision],
    ) -> SearchController:
        self._controller.restore(
            controller_seed=controller_seed_for(run.seed or 0), decisions=decisions
        )
        return self._controller

    def _restore_driver(self, decisions: Sequence[ControllerDecision]) -> None:
        if any(decision.outcome is ControllerDecisionOutcome.PENDING for decision in decisions):
            raise RunResumeError("LLM driver 恢复前必须先处理 pending decision")
        self._driver_decisions = [decision.model_copy(deep=True) for decision in decisions]
        self._driver_pending = None
        if isinstance(self._driver, LLMControllerAdapter):
            self._driver.resume_at(len(decisions))

    def _controller_name(self) -> str:
        return self._controller.name if self._controller is not None else self._driver.name  # type: ignore[union-attr]

    async def _select_strategy(
        self,
        run: Run,
        available: list[str],
        attempts: list[Attempt],
        budget: BudgetManager,
        retry_rng: random.Random,
        actor: str,
    ) -> str:
        if self._controller is not None:
            return self._controller.select(available)
        if run.limits.max_total_tokens is None:
            raise ValueError("LLM Controller Run 必须设置 max_total_tokens")
        evidence = build_controller_evidence(
            attempts,
            brief=self._executor.target_brief(actor),
            available_strategy_ids=available,
            total_token_limit=run.limits.max_total_tokens,
            used_tokens=budget.usage().total_tokens,
        )
        try:
            selection = await self._driver.select(  # type: ignore[union-attr]
                evidence,
                on_requested=lambda invocation: self._persist(
                    lambda: self._store.save_controller_invocation(invocation), retry_rng
                ),
            )
        except ControllerSelectionError as exc:
            invocation = exc.invocation
            await self._persist(
                lambda: self._store.save_controller_invocation(invocation), retry_rng
            )
            budget.record_usage(
                prompt_tokens=invocation.cost.prompt_tokens,
                completion_tokens=invocation.cost.completion_tokens,
                cached_input_tokens=invocation.cost.cached_input_tokens,
                cost_usd=invocation.cost.usd,
                role="controller",
            )
            raise
        if selection.invocation is not None:
            await self._persist(
                lambda: self._store.save_controller_invocation(selection.invocation), retry_rng
            )
            budget.record_usage(
                prompt_tokens=selection.invocation.cost.prompt_tokens,
                completion_tokens=selection.invocation.cost.completion_tokens,
                cached_input_tokens=selection.invocation.cost.cached_input_tokens,
                cost_usd=selection.invocation.cost.usd,
                role="controller",
            )
        decision = ControllerDecision(
            attempt_index=budget.usage().attempts,
            controller=self._driver.name,  # type: ignore[union-attr]
            available_strategy_ids=list(available),
            selected_strategy_id=selection.choice.selected_strategy_id,
            invocation_id=selection.invocation.id if selection.invocation else None,
            decision_state={
                "rationale": selection.choice.rationale,
                "evidence_refs": selection.choice.evidence_refs,
                "evidence_digest": evidence.digest(),
                "repaired": selection.repaired,
            },
        )
        self._driver_decisions.append(decision)
        self._driver_pending = decision.attempt_index
        budget.complete_selection()
        return decision.selected_strategy_id

    def _complete_selection(self, strategy_id: str, score: float) -> None:
        if self._controller is not None:
            self._controller.update(strategy_id, score)
            return
        decision = self._require_latest_decision()
        if decision.selected_strategy_id != strategy_id:
            raise RuntimeError("LLM Controller completion 与选择 Strategy 不一致")
        self._driver_decisions[-1] = decision.model_copy(
            update={"observed_score": score, "outcome": ControllerDecisionOutcome.COMPLETED}
        )
        self._driver_pending = None

    def _abandon_selection(self, strategy_id: str, reason: str) -> None:
        if self._controller is not None:
            self._controller.abandon(strategy_id, reason)
            return
        decision = self._require_latest_decision()
        if decision.selected_strategy_id != strategy_id:
            raise RuntimeError("LLM Controller abandonment 与选择 Strategy 不一致")
        self._driver_decisions[-1] = decision.model_copy(
            update={"outcome": ControllerDecisionOutcome.ABANDONED, "failure_reason": reason}
        )
        self._driver_pending = None

    def _latest_decision(self) -> ControllerDecision | None:
        if self._controller is not None:
            return self._controller.latest_decision
        return self._driver_decisions[-1].model_copy(deep=True) if self._driver_decisions else None

    def _has_pending_selection(self) -> bool:
        return (
            self._controller.has_pending_decision
            if self._controller is not None
            else self._driver_pending is not None
        )

    @staticmethod
    def _generation_memory(
        run: Run, attempts: list[Attempt], strategy_id: str
    ) -> GenerationMemory | None:
        """仅显式 memory-enabled 条件才从已提交 Attempt 构造 Generator memory。"""
        conditions = run.experiment_conditions
        if (
            conditions is None
            or conditions.generation_memory is None
            or conditions.generation_memory.mode is GenerationMemoryMode.OFF
        ):
            return None
        memory = conditions.generation_memory
        if memory.limits is None or memory.policy_version is None:
            raise RuntimeError("memory-enabled Run 缺少冻结的 memory policy/limits")
        return build_generation_memory(
            attempts,
            current_strategy_id=strategy_id,
            policy_version=memory.policy_version,
            limits=memory.limits,
        )

    def _require_latest_decision(self) -> ControllerDecision:
        """取最近一次决策;不存在即为内部不变量被破坏,不静默兜底。"""
        decision = self._latest_decision()
        if decision is None:
            raise RuntimeError("Controller 没有任何决策,但流程已经进入需要决策的分支")
        return decision

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

    def _completed_run(
        self,
        run: Run,
        budget: BudgetManager,
        *,
        stopped_by: BudgetLimit,
    ) -> Run:
        return run.model_copy(
            update={
                "status": RunStatus.COMPLETED,
                "usage": budget.usage(),
                "stopped_by": stopped_by,
                "completed_at": self._utcnow(),
                "failure": None,
            }
        )

    def _failed_run(self, run: Run, failure: FailureRecord) -> Run:
        return run.model_copy(
            update={
                "status": RunStatus.FAILED,
                "completed_at": self._utcnow(),
                "failure": failure,
            }
        )


def _failure_reason(failure: FailureRecord) -> str:
    return f"{failure.kind.value}:{failure.code}"


def _attempt_role_costs(attempt: Attempt) -> tuple[CostRecord, CostRecord]:
    """Split committed Attempt usage without changing its single total budget."""
    generator = CostRecord(
        prompt_tokens=sum(turn.attacker_cost.prompt_tokens for turn in attempt.turns),
        completion_tokens=sum(turn.attacker_cost.completion_tokens for turn in attempt.turns),
        cached_input_tokens=sum(turn.attacker_cost.cached_input_tokens for turn in attempt.turns),
        usage_known=all(turn.attacker_cost.usage_known for turn in attempt.turns),
        usd=sum(turn.attacker_cost.usd for turn in attempt.turns),
    )
    target = CostRecord(
        prompt_tokens=sum(turn.output.trace_metadata.prompt_tokens for turn in attempt.turns),
        completion_tokens=sum(
            turn.output.trace_metadata.completion_tokens for turn in attempt.turns
        ),
        cached_input_tokens=sum(
            turn.output.trace_metadata.cached_input_tokens for turn in attempt.turns
        ),
        usage_known=all(turn.output.trace_metadata.usage_known for turn in attempt.turns),
        usd=sum(turn.output.trace_metadata.cost_usd for turn in attempt.turns),
    )
    return generator, target


def _trailing_abandoned(decisions: Sequence[ControllerDecision]) -> int:
    """Count the current abandonment streak for reliability checks after resume."""
    streak = 0
    for decision in reversed(decisions):
        if decision.outcome is not ControllerDecisionOutcome.ABANDONED:
            break
        streak += 1
    return streak


def _trailing_selection_abandonments(events: Sequence[RunEvent]) -> int:
    streak = 0
    for event in reversed(events):
        if event.event_type is RunEventType.SELECTION_ABANDONED:
            streak += 1
            continue
        if event.event_type in {RunEventType.DECISION_SELECTED, RunEventType.RUN_STARTED}:
            break
    return streak


def _serious_failure(exc: Exception, stage: FailureStage) -> FailureRecord:
    if isinstance(exc, SeriousExecutionError):
        return exc.failure
    if isinstance(exc, ControllerProtocolError):
        kind = FailureKind.PROTOCOL
    elif isinstance(exc, (ValueError, TypeError, KeyError)):
        kind = FailureKind.CONFIGURATION
    else:
        kind = FailureKind.INTERNAL
    return FailureRecord(
        kind=kind,
        stage=stage,
        code=type(exc).__name__,
        message=safe_error_message(exc),
        cause_type=f"{type(exc).__module__}.{type(exc).__qualname__}",
        retry_safety=RetrySafety.UNSAFE,
        delivery_status=DeliveryStatus.UNKNOWN,
        side_effect_status=SideEffectStatus.UNKNOWN,
    )


def _persistence_failure(exc: Exception, *, fatal: bool) -> FailureRecord:
    return FailureRecord(
        kind=(FailureKind.PERSISTENCE_FATAL if fatal else FailureKind.PERSISTENCE_TRANSIENT),
        stage=FailureStage.PERSISTENCE,
        code=type(exc).__name__,
        message=safe_error_message(exc),
        cause_type=f"{type(exc).__module__}.{type(exc).__qualname__}",
        retry_safety=RetrySafety.UNSAFE if fatal else RetrySafety.SAFE,
        delivery_status=DeliveryStatus.NOT_SENT,
        side_effect_status=SideEffectStatus.NONE,
    )


def _reliability_failure(run: Run, last_failure: FailureRecord) -> FailureRecord:
    return FailureRecord(
        kind=FailureKind.EXPERIMENT_INVALID,
        stage=FailureStage.ORCHESTRATION,
        code="reliability_budget_exceeded",
        message=("可恢复故障在重试后仍过多,本 Run 的有效样本不足以支持可信结论"),
        cause_type=last_failure.cause_type,
        retry_safety=RetrySafety.UNSAFE,
        delivery_status=last_failure.delivery_status,
        side_effect_status=last_failure.side_effect_status,
        usage=CostRecord(),
        details={
            "logical_attempts": run.usage.attempts,
            "abandoned_attempts": run.usage.abandoned_attempts,
            "last_failure_kind": last_failure.kind.value,
        },
    )


def _selection_reliability_failure(run: Run, last_failure: dict[str, str] | None) -> FailureRecord:
    return FailureRecord(
        kind=FailureKind.EXPERIMENT_INVALID,
        stage=FailureStage.CONTROLLER_SELECTION,
        code="controller_selection_reliability_exceeded",
        message="Controller selection 连续失败或超过冻结阈值，本 Run 不可用于实验结论",
        cause_type="redcell.controller.ControllerSelectionError",
        retry_safety=RetrySafety.UNSAFE,
        delivery_status=DeliveryStatus.NOT_SENT,
        side_effect_status=SideEffectStatus.NONE,
        details={
            "successful_selections": run.usage.successful_selections,
            "abandoned_selections": run.usage.abandoned_selections,
            "last_selection_failure": (last_failure or {}).get("code"),
        },
    )


def _indeterminate_controller_failure(last_failure: dict[str, str] | None) -> FailureRecord:
    return FailureRecord(
        kind=FailureKind.EXPERIMENT_INVALID,
        stage=FailureStage.CONTROLLER_SELECTION,
        code="controller_invocation_indeterminate",
        message="Controller request has unknown delivery or token usage; this Gate Run is censored",
        cause_type="redcell.controller.ControllerSelectionError",
        retry_safety=RetrySafety.UNSAFE,
        delivery_status=DeliveryStatus.UNKNOWN,
        side_effect_status=SideEffectStatus.UNKNOWN,
        details={"controller_failure": (last_failure or {}).get("code")},
    )


def _orphaned_controller_invocation_failure(
    invocations: Sequence[ControllerInvocation],
) -> FailureRecord:
    return FailureRecord(
        kind=FailureKind.EXPERIMENT_INVALID,
        stage=FailureStage.CONTROLLER_SELECTION,
        code="orphaned_succeeded_controller_invocation",
        message=(
            "A paid Controller response was persisted without its Decision; "
            "the Run cannot safely replay or infer that selection"
        ),
        cause_type="redcell.controller.ControllerInvocation",
        retry_safety=RetrySafety.UNSAFE,
        delivery_status=DeliveryStatus.SENT,
        side_effect_status=SideEffectStatus.NONE,
        details={"invocation_ids": ",".join(invocation.id for invocation in invocations)},
    )


def _unknown_attempt_usage_failure(*, generator_known: bool, target_known: bool) -> FailureRecord:
    return FailureRecord(
        kind=FailureKind.EXPERIMENT_INVALID,
        stage=FailureStage.USAGE_ACCOUNTING,
        code="provider_usage_missing",
        message="Generator or Target response omitted auditable Token usage",
        cause_type="redcell.llm.base.LLMResponse",
        retry_safety=RetrySafety.UNSAFE,
        delivery_status=DeliveryStatus.SENT,
        side_effect_status=SideEffectStatus.UNKNOWN,
        details={
            "generator_usage_known": generator_known,
            "target_usage_known": target_known,
        },
    )


def _empty_run_failure() -> FailureRecord:
    return FailureRecord(
        kind=FailureKind.EXPERIMENT_INVALID,
        stage=FailureStage.ORCHESTRATION,
        code="no_valid_attempts",
        message="Run 没有产生任何可判定的有效 Attempt",
        cause_type="redcell.orchestrator.RunOrchestrator",
        retry_safety=RetrySafety.UNSAFE,
        delivery_status=DeliveryStatus.NOT_SENT,
        side_effect_status=SideEffectStatus.NONE,
    )
