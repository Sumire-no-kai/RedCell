"""ConversationExecutor —— 执行一场完整 Attempt 的深模块。

调用方只需提供“一场测试要试什么”;逐轮生成、目标通信、证据累积、确定性判定、
提前停止、成本汇总和复现上下文都收敛在此处。
"""

from __future__ import annotations

from typing import Any

from pydantic import Field

from redcell.generation import AttackGenerationRequest, AttackGenerator
from redcell.protocols.adapter import AdapterInput, Message, TargetAdapter
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
from redcell.scoring.level1 import Level1Scorer, ScoringResult


class ExecutionRequest(RedCellModel):
    run_id: str
    strategy: Strategy
    actor: str
    run_seed: int = Field(ge=0)
    attempt_index: int = Field(ge=0)
    parent_attempt_id: str | None = None
    target_model: str | None = None
    target_temperature: float | None = None
    attacker_model: str | None = None
    attacker_temperature: float | None = None


class ExecutionResult(RedCellModel):
    attempt: Attempt
    findings: list[Finding]


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
    ) -> None:
        super().__init__(
            f"Attempt {attempt_id} 执行失败(strategy={strategy_id}): "
            f"{type(cause).__name__}: {cause}"
        )
        self.attempt_id = attempt_id
        self.strategy_id = strategy_id
        self.partial_turns = list(partial_turns)
        self.cause = cause


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

    async def execute(self, request: ExecutionRequest) -> ExecutionResult:
        """执行一场原子 Attempt。

        正常返回的 Attempt 一定有完整停止原因;任一步异常则抛
        AttemptExecutionError,不会返回看似有效的零分记录。
        """
        self._validate_request(request)
        attempt_id = new_id()
        seeds = seeds_for_attempt(request.run_seed, request.attempt_index)
        turns: list[Turn] = []
        conversation: list[Message] = []
        scoring: ScoringResult | None = None
        stop_reason = AttemptStopReason.MAX_TURNS

        try:
            await self._adapter.reset()

            for turn_index in range(request.strategy.max_turns):
                attack = await self._generator.generate(
                    AttackGenerationRequest(
                        strategy=request.strategy,
                        policy=self._policy,
                        actor=request.actor,
                        turn_index=turn_index,
                        prior_turns=turns,
                        seed=derive_seed(seeds.generator_seed, "turn", turn_index),
                    )
                )
                conversation.append(Message(role=Role.USER, content=attack.content))

                output = await self._adapter.send(
                    AdapterInput(
                        messages=list(conversation),
                        actor=request.actor,
                        metadata=_adapter_metadata(request, seeds, turn_index),
                    )
                )
                turns.append(
                    Turn(
                        index=turn_index,
                        attacker_message=attack.content,
                        output=output,
                    )
                )
                conversation.append(Message(role=Role.ASSISTANT, content=output.assistant_message))

                scoring = self._scorer.score(
                    turns,
                    run_id=request.run_id,
                    attempt_id=attempt_id,
                    actor=request.actor,
                    strategy_id=request.strategy.id,
                )
                if scoring.has_attempt_success:
                    stop_reason = AttemptStopReason.ATTEMPT_SUCCESS
                    break
        except Exception as exc:
            raise AttemptExecutionError(
                attempt_id=attempt_id,
                strategy_id=request.strategy.id,
                partial_turns=turns,
                cause=exc,
            ) from exc

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
        "attempt_index": request.attempt_index,
        "strategy_id": request.strategy.id,
        "turn_index": turn_index,
        "attempt_seed": seeds.attempt_seed,
        "target_seed": derive_seed(seeds.target_seed, "turn", turn_index),
    }


def _cost_of(turns: list[Turn]) -> CostRecord:
    return CostRecord(
        prompt_tokens=sum(t.output.trace_metadata.prompt_tokens for t in turns),
        completion_tokens=sum(t.output.trace_metadata.completion_tokens for t in turns),
        usd=sum(t.output.trace_metadata.cost_usd for t in turns),
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
            "generator": generator_name,
        },
    )
