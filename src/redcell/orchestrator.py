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
from redcell.protocols.common import RedCellModel, new_id
from redcell.protocols.finding import Finding
from redcell.protocols.run import Run, RunEvent, RunEventType, RunStatus
from redcell.protocols.strategy import Strategy
from redcell.protocols.trace import Attempt, CostRecord
from redcell.randomness import derive_seed
from redcell.retry import ReliabilityPolicy, RetryPolicy
from redcell.search.base import (
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


class RunOrchestrator:
    """一条窄接口背后的完整串行运行状态机。

    实例是一次性的:Controller 决策历史与事件序号都属于一个 Run。
    新 Run 必须创建新的 Controller 和 RunOrchestrator。
    """

    def __init__(
        self,
        *,
        executor: ConversationExecutor,
        controller: SearchController,
        store: RunStore,
        retry_policy: RetryPolicy | None = None,
        reliability_policy: ReliabilityPolicy | None = None,
        sleep: Sleep = asyncio.sleep,
        utcnow: UtcNow | None = None,
    ) -> None:
        self._executor = executor
        self._controller = controller
        self._store = store
        self._retry_policy = retry_policy or RetryPolicy()
        self._reliability = reliability_policy or ReliabilityPolicy()
        self._sleep = sleep
        self._utcnow = utcnow or (lambda: datetime.now(UTC))
        self._event_sequence = 0
        self._claimed = False

    async def execute(self, request: RunExecutionRequest) -> RunExecutionResult:
        """执行到预算终点;严重错误会持久化 FAILED 后抛 RunFailedError。"""
        if self._claimed:
            raise OrchestratorReuseError("RunOrchestrator 是一次性状态机;新 Run 必须创建新实例")
        self._claimed = True

        run = request.run.model_copy(deep=True)
        strategies = list(request.strategies)
        run = self._prepare_run(run, strategies)
        retry_rng = random.Random(derive_seed(run.seed or 0, "retry-backoff"))
        existing = await self._persist(lambda: self._store.get_run(run.id), retry_rng)
        if existing is not None:
            raise RunAlreadyExistsError(
                f"Run '{run.id}' 已存在;拒绝覆盖既有状态与事件。"
                "断点恢复必须使用未来独立的 resume interface"
            )

        try:
            self._preflight(run, strategies, request.actor)
        except Exception as exc:
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

        run = run.model_copy(
            update={
                "status": RunStatus.RUNNING,
                "started_at": self._utcnow(),
                "strategy_ids": [strategy.id for strategy in strategies],
            }
        )
        started = self._event(run, RunEventType.RUN_STARTED)
        await self._persist(
            lambda: self._store.commit_run_state(run=run, run_event=started),
            retry_rng,
        )

        budget = BudgetManager(run.limits)
        by_id = {strategy.id: strategy for strategy in strategies}
        attempts: list[Attempt] = []
        findings: list[Finding] = []
        consecutive_abandoned = 0
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

                strategy_id = self._controller.select(available)
                strategy = by_id[strategy_id]
                attempt_index = budget.usage().attempts
                attempt_id = new_id()
                current_attempt_id = attempt_id
                budget.reserve_attempt(strategy_id)
                run = run.model_copy(update={"usage": budget.usage()})

                pending_decision = self._controller.decisions[-1]
                if pending_decision.attempt_index != attempt_index:
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
                    self._controller.abandon(strategy_id, _failure_reason(exc.failure))
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
                            decision=self._controller.decisions[-1],
                            run_events=events,
                        ),
                        retry_rng,
                    )
                    if invalid:
                        raise RunFailedError(run, terminal_failure) from exc
                    current_attempt_id = None
                    current_result = None
                    continue

                budget.record_usage(
                    prompt_tokens=result.attempt.cost.prompt_tokens,
                    completion_tokens=result.attempt.cost.completion_tokens,
                    cost_usd=result.attempt.cost.usd,
                )
                budget.complete_attempt()
                self._controller.update(strategy_id, result.attempt.reward)
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
                        decision=self._controller.decisions[-1],
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
            if _has_pending_decision(self._controller):
                strategy_id = self._controller.decisions[-1].selected_strategy_id
                self._controller.abandon(strategy_id, _failure_reason(failure))
                budget.abandon_attempt()
                failed = failed.model_copy(update={"usage": budget.usage()})
            failed_event = self._event(
                failed,
                RunEventType.RUN_FAILED,
                attempt_id=(current_attempt_id if current_result is not None else None),
                payload={"failure": failure.model_dump(mode="json")},
            )
            latest_decision = self._controller.decisions[-1] if self._controller.decisions else None
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
                    payload={"failure": failure.model_dump(mode="json")},
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
                budget.record_usage(
                    prompt_tokens=exc.cost.prompt_tokens,
                    completion_tokens=exc.cost.completion_tokens,
                    cost_usd=exc.cost.usd,
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
        if _has_pending_decision(self._controller):
            selected = self._controller.decisions[-1].selected_strategy_id
            self._controller.abandon(selected, "user cancelled")
            budget.abandon_attempt()
        aborted = run.model_copy(
            update={
                "status": RunStatus.ABORTED,
                "usage": budget.usage(),
                "completed_at": self._utcnow(),
            }
        )
        event = self._event(aborted, RunEventType.RUN_ABORTED)
        latest_decision = self._controller.decisions[-1] if self._controller.decisions else None
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
                payload={"reason": "user cancelled"},
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
        if self._controller.decisions:
            raise ValueError("Controller 已有历史,不能复用于新 Run")
        if run.algorithm != self._controller.name:
            raise ValueError(
                f"Run.algorithm='{run.algorithm}' 与 Controller '{self._controller.name}' 不一致"
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


def _has_pending_decision(controller: SearchController) -> bool:
    return bool(
        controller.decisions
        and controller.decisions[-1].outcome is ControllerDecisionOutcome.PENDING
    )


def _failure_reason(failure: FailureRecord) -> str:
    return f"{failure.kind.value}:{failure.code}"


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
