"""ConversationExecutor —— 执行一场完整 Attempt 的深模块。

调用方只需提供“一场测试要试什么”;逐轮生成、目标通信、证据累积、确定性判定、
提前停止、成本汇总和复现上下文都收敛在此处。
"""

from __future__ import annotations

import inspect
from collections.abc import Awaitable, Callable
from typing import Any

from pydantic import Field

from redcell.failures import (
    AmbiguousSideEffectError,
    DeliveryStatus,
    FailureKind,
    FailureRecord,
    FailureStage,
    RetrySafety,
    SideEffectStatus,
    StructuredExecutionError,
    safe_error_message,
)
from redcell.generation import AttackGenerationError, AttackGenerationRequest, AttackGenerator
from redcell.llm.openai_compatible import (
    ProviderConfigurationError,
    ProviderProtocolError,
    ProviderRateLimitedError,
    ProviderTransientError,
)
from redcell.protocols.adapter import (
    AdapterCapabilities,
    AdapterInput,
    IdempotencySupport,
    Message,
    ResetScope,
    TargetAdapter,
)
from redcell.protocols.common import RedCellModel, Role, new_id
from redcell.protocols.finding import Finding
from redcell.protocols.policy import Policy
from redcell.protocols.strategy import Strategy
from redcell.protocols.trace import (
    Attempt,
    AttemptStopReason,
    CostRecord,
    ReproductionContext,
    Turn,
    build_attempt,
)
from redcell.randomness import AttemptSeeds, derive_seed, seeds_for_attempt
from redcell.retry import RETRY_AFTER_KEY
from redcell.scoring.level1 import Level1Scorer, ScoringResult


class ExecutionRequest(RedCellModel):
    attempt_id: str = Field(default_factory=new_id)
    run_id: str
    strategy: Strategy
    actor: str
    run_seed: int = Field(ge=0)
    attempt_index: int = Field(ge=0)
    execution_retry_index: int = Field(default=0, ge=0)
    parent_attempt_id: str | None = None
    target_model: str | None = None
    target_temperature: float | None = None
    attacker_model: str | None = None
    attacker_temperature: float | None = None


class ExecutionResult(RedCellModel):
    attempt: Attempt
    findings: list[Finding]


class TurnCheckpoint(RedCellModel):
    """一个已经完整执行并完成评分的 Turn,可安全作为恢复检查点。"""

    run_id: str
    attempt_id: str
    strategy_id: str
    execution_retry_index: int = Field(ge=0)
    turn: Turn
    findings: list[Finding] = Field(default_factory=list)


TurnCheckpointHandler = Callable[[TurnCheckpoint], Awaitable[None] | None]


class AttemptExecutionError(RuntimeError):
    """一场 Attempt 未正常完成。

    partial_turns 保留诊断证据,但调用方不能把它伪装成 reward=0 的有效 Attempt。
    重试次数和 Run 失效阈值由后续 orchestrator 策略决定,本模块不擅自拍板。
    """

    def __init__(
        self,
        *,
        attempt_id: str,
        strategy_id: str,
        partial_turns: list[Turn],
        cause: Exception,
        failure: FailureRecord,
    ) -> None:
        super().__init__(
            f"Attempt {attempt_id} 执行失败(strategy={strategy_id}): "
            f"{type(cause).__name__}: {cause}"
        )
        self.attempt_id = attempt_id
        self.strategy_id = strategy_id
        self.partial_turns = list(partial_turns)
        self.cause = cause
        self.failure = failure

    @property
    def cost(self) -> CostRecord:
        return self.failure.usage


class ConversationExecutor:
    """通过同一接口执行单轮/多轮 Strategy。"""

    def __init__(
        self,
        *,
        adapter: TargetAdapter,
        generator: AttackGenerator,
        scorer: Level1Scorer,
        policy: Policy,
    ) -> None:
        self._adapter = adapter
        self._generator = generator
        self._scorer = scorer
        self._policy = policy

    async def execute(
        self,
        request: ExecutionRequest,
        *,
        on_turn_completed: TurnCheckpointHandler | None = None,
    ) -> ExecutionResult:
        """执行一场原子 Attempt。

        正常返回的 Attempt 一定有完整停止原因;任一步异常则抛
        AttemptExecutionError,不会返回看似有效的零分记录。
        """
        self._validate_request(request)
        attempt_id = request.attempt_id
        brief = self._policy.brief_for(request.actor)
        seeds = seeds_for_attempt(request.run_seed, request.attempt_index)
        turns: list[Turn] = []
        conversation: list[Message] = []
        scoring: ScoringResult | None = None
        stop_reason = AttemptStopReason.MAX_TURNS

        try:
            await self._adapter.reset()
        except Exception as exc:
            raise self._attempt_error(
                request=request,
                stage=FailureStage.RESET,
                turns=turns,
                cause=exc,
            ) from exc

        for turn_index in range(request.strategy.max_turns):
            try:
                attack = await self._generator.generate(
                    AttackGenerationRequest(
                        strategy=request.strategy,
                        # 只给攻击面,不给检测仪器 —— 见 TargetBrief。
                        brief=brief,
                        turn_index=turn_index,
                        prior_turns=turns,
                        seed=derive_seed(seeds.generator_seed, "turn", turn_index),
                    )
                )
            except Exception as exc:
                raise self._attempt_error(
                    request=request,
                    stage=FailureStage.GENERATION,
                    turns=turns,
                    cause=exc,
                ) from exc

            conversation.append(Message(role=Role.USER, content=attack.content))

            try:
                output = await self._adapter.send(
                    AdapterInput(
                        messages=list(conversation),
                        actor=request.actor,
                        request_id=_turn_request_id(attempt_id, turn_index),
                        idempotency_key=_turn_request_id(attempt_id, turn_index),
                        metadata=_adapter_metadata(request, seeds, turn_index),
                    )
                )
            except Exception as exc:
                raise self._attempt_error(
                    request=request,
                    stage=FailureStage.TARGET_SEND,
                    turns=turns,
                    cause=exc,
                ) from exc

            turns.append(
                Turn(
                    index=turn_index,
                    attacker_message=attack.content,
                    output=output,
                    attacker_cost=attack.cost,
                    attacker_generation_retries=attack.generation_retries,
                )
            )
            conversation.append(Message(role=Role.ASSISTANT, content=output.assistant_message))

            try:
                scoring = self._scorer.score(
                    turns,
                    run_id=request.run_id,
                    attempt_id=attempt_id,
                    actor=request.actor,
                    strategy_id=request.strategy.id,
                )
            except Exception as exc:
                raise self._attempt_error(
                    request=request,
                    stage=FailureStage.SCORING,
                    turns=turns,
                    cause=exc,
                ) from exc

            if on_turn_completed is not None:
                checkpoint = TurnCheckpoint(
                    run_id=request.run_id,
                    attempt_id=attempt_id,
                    strategy_id=request.strategy.id,
                    execution_retry_index=request.execution_retry_index,
                    turn=turns[-1],
                    findings=scoring.findings,
                )
                try:
                    maybe_awaitable = on_turn_completed(checkpoint)
                    if inspect.isawaitable(maybe_awaitable):
                        await maybe_awaitable
                except Exception as exc:
                    raise self._attempt_error(
                        request=request,
                        stage=FailureStage.PERSISTENCE,
                        turns=turns,
                        cause=exc,
                    ) from exc

            if scoring.has_attempt_success:
                stop_reason = AttemptStopReason.ATTEMPT_SUCCESS
                break

        if scoring is None:
            # Strategy.max_turns 的 schema 下界为 1;到这里说明内部不变量被破坏。
            raise RuntimeError("Executor 未执行任何 Turn")

        reproduction = _reproduction_context(
            request=request,
            seeds=seeds,
            generator_name=self._generator.name,
            turns=turns,
            adapter_type=self._adapter.adapter_type,
            policy=self._policy,
        )
        attempt = build_attempt(
            attempt_id=attempt_id,
            run_id=request.run_id,
            strategy_id=request.strategy.id,
            actor=request.actor,
            attack_prompt=turns[0].attacker_message,
            reproduction=reproduction,
            turns=turns,
            signals=scoring.signals,
            cost=_cost_of(turns),
            planned_max_turns=request.strategy.max_turns,
            stop_reason=stop_reason,
        )
        return ExecutionResult(attempt=attempt, findings=scoring.findings)

    @property
    def adapter_capabilities(self) -> AdapterCapabilities:
        return self._adapter.capabilities

    @property
    def generator_reports_cost(self) -> bool:
        """attacker 那一侧报不报得出成本 —— 预算守卫要用。"""
        return self._generator.reports_cost

    @property
    def target_name(self) -> str:
        return self._policy.target_name

    @property
    def policy_version(self) -> str:
        return self._policy.version

    @property
    def adapter_type(self) -> str:
        return self._adapter.adapter_type

    def validate(self, request: ExecutionRequest) -> None:
        """供 Orchestrator 在消耗预算前执行 preflight。"""
        self._validate_request(request)

    def _attempt_error(
        self,
        *,
        request: ExecutionRequest,
        stage: FailureStage,
        turns: list[Turn],
        cause: Exception,
    ) -> AttemptExecutionError:
        failure = _classify_failure(
            cause,
            stage=stage,
            capabilities=self._adapter.capabilities,
            partial_cost=_cost_of(turns),
        )
        return AttemptExecutionError(
            attempt_id=request.attempt_id,
            strategy_id=request.strategy.id,
            partial_turns=turns,
            cause=cause,
            failure=failure,
        )

    def _validate_request(self, request: ExecutionRequest) -> None:
        if self._policy.actor(request.actor) is None:
            raise ValueError(f"Policy 中没有 actor '{request.actor}'")
        request.strategy.validate_against(self._policy)
        if not request.strategy.is_applicable(self._policy):
            raise ValueError(
                f"策略 '{request.strategy.id}' 不适用于 target '{self._policy.target_name}'"
            )


def _adapter_metadata(
    request: ExecutionRequest,
    seeds: AttemptSeeds,
    turn_index: int,
) -> dict[str, Any]:
    return {
        "run_id": request.run_id,
        "attempt_id": request.attempt_id,
        "attempt_index": request.attempt_index,
        "execution_retry_index": request.execution_retry_index,
        "strategy_id": request.strategy.id,
        "turn_index": turn_index,
        "attempt_seed": seeds.attempt_seed,
        "target_seed": derive_seed(seeds.target_seed, "turn", turn_index),
    }


def _turn_request_id(attempt_id: str, turn_index: int) -> str:
    return f"{attempt_id}:turn:{turn_index}"


def _cost_of(turns: list[Turn]) -> CostRecord:
    """一场 attempt 的总开销 = target 侧 + **attacker 侧**。

    ⚠️ **attacker 那一项曾经整个漏掉。** 当时 `AttackMessage` 只带文本,
    生成话术的 token 与费用在 `LLMMutationGenerator` 里就被丢弃了,
    于是 `max_total_tokens` / `max_cost_usd` **挡不住攻击方的开销** ——
    设了上限却只管住一半,是一张假的安全网。接入付费 attacker 之前必须先补上。

    墙钟只取 target 侧:attacker 的等待已经包含在整场 attempt 的耗时里,
    两边相加会把同一段时间算两次。
    """
    return CostRecord(
        prompt_tokens=sum(
            t.output.trace_metadata.prompt_tokens + t.attacker_cost.prompt_tokens for t in turns
        ),
        completion_tokens=sum(
            t.output.trace_metadata.completion_tokens + t.attacker_cost.completion_tokens
            for t in turns
        ),
        usd=sum(t.output.trace_metadata.cost_usd + t.attacker_cost.usd for t in turns),
        wall_ms=sum(t.output.trace_metadata.latency_ms for t in turns),
    )


def _reproduction_context(
    *,
    request: ExecutionRequest,
    seeds: AttemptSeeds,
    generator_name: str,
    turns: list[Turn],
    adapter_type: str,
    policy: Policy,
) -> ReproductionContext:
    last_trace = turns[-1].output.trace_metadata
    return ReproductionContext(
        policy_version=policy.version,
        target_name=policy.target_name,
        adapter_type=adapter_type,
        strategy_id=request.strategy.id,
        mutation_operators=[op.value for op in request.strategy.mutation_operators],
        parent_attempt_id=request.parent_attempt_id,
        run_seed=seeds.run_seed,
        controller_seed=seeds.controller_seed,
        seed=seeds.attempt_seed,
        generator_seed=seeds.generator_seed,
        actor_seed=seeds.actor_seed,
        target_seed=seeds.target_seed,
        target_model=request.target_model or last_trace.model,
        target_temperature=(
            request.target_temperature
            if request.target_temperature is not None
            else last_trace.temperature
        ),
        attacker_model=request.attacker_model or generator_name,
        attacker_temperature=request.attacker_temperature,
        extra={
            "attempt_index": request.attempt_index,
            "execution_retry_index": request.execution_retry_index,
            "generator": generator_name,
        },
    )


def _classify_failure(
    exc: Exception,
    *,
    stage: FailureStage,
    capabilities: AdapterCapabilities,
    partial_cost: CostRecord,
) -> FailureRecord:
    if isinstance(exc, StructuredExecutionError):
        failure = exc.failure
        return failure.model_copy(
            update={"usage": _sum_costs(partial_cost, failure.usage)},
        )

    if stage is FailureStage.SCORING:
        return _failure(
            exc,
            kind=FailureKind.SCORING,
            stage=stage,
            retry_safety=RetrySafety.UNSAFE,
            cost=partial_cost,
        )

    if stage is FailureStage.PERSISTENCE:
        return _failure(
            exc,
            kind=FailureKind.PERSISTENCE_FATAL,
            stage=stage,
            retry_safety=RetrySafety.UNSAFE,
            cost=partial_cost,
        )

    if isinstance(exc, AttackGenerationError):
        return _failure(
            exc,
            kind=FailureKind.CONFIGURATION,
            stage=stage,
            retry_safety=RetrySafety.UNSAFE,
            delivery=DeliveryStatus.NOT_SENT,
            side_effect=SideEffectStatus.NONE,
            cost=partial_cost,
        )

    if isinstance(exc, ProviderRateLimitedError):
        # 429 与超时的关键区别:服务端在**处理之前**就拒绝了,
        # 所以送达状态是确定的 NOT_SENT,重试无条件安全 ——
        # 不需要走 _network_failure 里那套"可能已产生副作用"的判定。
        details: dict[str, str | int | float | bool | None] = {}
        if exc.retry_after_seconds is not None:
            details[RETRY_AFTER_KEY] = exc.retry_after_seconds
        return _failure(
            exc,
            kind=FailureKind.RATE_LIMITED,
            stage=stage,
            # 当日配额耗尽虽然同样"确定没送达",但它**不该被重试** ——
            # 重试到明天之前都不会好,只会把 Run 的重试预算白白烧光,
            # 最后以一条看不出真实原因的"限流"失败收场。
            retry_safety=(RetrySafety.UNSAFE if exc.daily_quota_exhausted else RetrySafety.SAFE),
            delivery=DeliveryStatus.NOT_SENT,
            side_effect=SideEffectStatus.NONE,
            cost=partial_cost,
            details=details,
        )

    if isinstance(exc, ProviderConfigurationError):
        return _failure(
            exc,
            kind=FailureKind.CONFIGURATION,
            stage=stage,
            retry_safety=RetrySafety.UNSAFE,
            delivery=DeliveryStatus.NOT_SENT,
            side_effect=SideEffectStatus.NONE,
            cost=partial_cost,
        )

    if isinstance(exc, ProviderProtocolError):
        # HTTP 200 但结构不对:请求确实送达并被处理了,只是我们读不懂回复。
        # 重试通常无济于事 —— 多半是端点变了或对方改了协议,需要人看一眼。
        return _failure(
            exc,
            kind=FailureKind.PROTOCOL,
            stage=stage,
            retry_safety=RetrySafety.UNSAFE,
            delivery=DeliveryStatus.SENT,
            cost=partial_cost,
        )

    if isinstance(exc, (ProviderTransientError, TimeoutError, ConnectionError)):
        return _network_failure(
            exc,
            stage=stage,
            capabilities=capabilities,
            cost=partial_cost,
        )

    if isinstance(exc, (ValueError, TypeError, KeyError)):
        return _failure(
            exc,
            kind=FailureKind.CONFIGURATION,
            stage=stage,
            retry_safety=RetrySafety.UNSAFE,
            delivery=DeliveryStatus.NOT_SENT,
            side_effect=SideEffectStatus.NONE,
            cost=partial_cost,
        )

    return _failure(
        exc,
        kind=FailureKind.INTERNAL,
        stage=stage,
        retry_safety=RetrySafety.UNSAFE,
        cost=partial_cost,
    )


def _network_failure(
    exc: Exception,
    *,
    stage: FailureStage,
    capabilities: AdapterCapabilities,
    cost: CostRecord,
) -> FailureRecord:
    if stage in {FailureStage.GENERATION, FailureStage.RESET}:
        return _failure(
            exc,
            kind=FailureKind.NETWORK_TRANSIENT,
            stage=stage,
            retry_safety=RetrySafety.SAFE,
            delivery=DeliveryStatus.NOT_SENT,
            side_effect=SideEffectStatus.NONE,
            cost=cost,
        )

    if capabilities.idempotency in {
        IdempotencySupport.SUPPORTED,
        IdempotencySupport.REQUIRED,
    }:
        retry_safety = RetrySafety.REQUIRES_IDEMPOTENCY_KEY
    elif capabilities.reset_scope is ResetScope.FULL_STATE:
        retry_safety = RetrySafety.REQUIRES_RESET
    else:
        failure = _failure(
            exc,
            kind=FailureKind.AMBIGUOUS_SIDE_EFFECT,
            stage=stage,
            retry_safety=RetrySafety.UNSAFE,
            delivery=DeliveryStatus.UNKNOWN,
            side_effect=SideEffectStatus.UNKNOWN,
            cost=cost,
        )
        return AmbiguousSideEffectError(failure).failure

    return _failure(
        exc,
        kind=FailureKind.NETWORK_TRANSIENT,
        stage=stage,
        retry_safety=retry_safety,
        delivery=DeliveryStatus.UNKNOWN,
        side_effect=SideEffectStatus.UNKNOWN,
        cost=cost,
    )


def _failure(
    exc: Exception,
    *,
    kind: FailureKind,
    stage: FailureStage,
    retry_safety: RetrySafety,
    cost: CostRecord,
    delivery: DeliveryStatus = DeliveryStatus.UNKNOWN,
    side_effect: SideEffectStatus = SideEffectStatus.UNKNOWN,
    details: dict[str, str | int | float | bool | None] | None = None,
) -> FailureRecord:
    return FailureRecord(
        kind=kind,
        stage=stage,
        code=type(exc).__name__,
        message=safe_error_message(exc),
        cause_type=f"{type(exc).__module__}.{type(exc).__qualname__}",
        retry_safety=retry_safety,
        delivery_status=delivery,
        side_effect_status=side_effect,
        usage=cost,
        details=details or {},
    )


def _sum_costs(left: CostRecord, right: CostRecord) -> CostRecord:
    return CostRecord(
        prompt_tokens=left.prompt_tokens + right.prompt_tokens,
        completion_tokens=left.completion_tokens + right.completion_tokens,
        usd=left.usd + right.usd,
        wall_ms=left.wall_ms + right.wall_ms,
    )
