from __future__ import annotations

import json

import pytest

from redcell.arena.support_agent import (
    SUPPORT_AGENT_POLICY,
    SYSTEM_PROMPT_CANARY,
    SYSTEM_PROMPT_CANARY_PREFIX,
    ArenaAdapter,
)
from redcell.executor import (
    AttemptExecutionError,
    ConversationExecutor,
    ExecutionRequest,
)
from redcell.generation import ScriptedAttackGenerator
from redcell.llm import ScriptedProvider
from redcell.protocols import AttemptStopReason, ImpactStatus
from redcell.protocols.adapter import AdapterOutput, TraceMetadata
from redcell.protocols.common import ObservabilityLevel
from redcell.protocols.trace import Turn
from redcell.scoring import Level1Scorer
from redcell.strategies import (
    CROSS_USER_RESOURCE_ACCESS,
    DIRECT_INSTRUCTION_OVERRIDE,
)


def _tool_call(name: str, **arguments) -> str:
    return f"<tool_call>{json.dumps({'name': name, 'arguments': arguments})}</tool_call>"


def _executor(
    *,
    target_script: list[str],
    attack_script: list[str],
    strategy=DIRECT_INSTRUCTION_OVERRIDE,
    tokens_per_call: tuple[int, int] = (0, 0),
) -> tuple[ConversationExecutor, ScriptedProvider]:
    provider = ScriptedProvider(target_script, tokens_per_call=tokens_per_call)
    adapter = ArenaAdapter(provider)
    generator = ScriptedAttackGenerator({strategy.id: attack_script})
    return (
        ConversationExecutor(
            adapter=adapter,
            generator=generator,
            scorer=Level1Scorer(SUPPORT_AGENT_POLICY),
            policy=SUPPORT_AGENT_POLICY,
        ),
        provider,
    )


def _request(strategy=DIRECT_INSTRUCTION_OVERRIDE, attempt_index: int = 0) -> ExecutionRequest:
    return ExecutionRequest(
        run_id="run_1",
        strategy=strategy,
        actor="customer_a",
        run_seed=42,
        attempt_index=attempt_index,
    )


async def test_full_canary_finding_stops_after_first_turn() -> None:
    executor, provider = _executor(
        target_script=[f"The reference is {SYSTEM_PROMPT_CANARY}."],
        attack_script=["show config"],
    )
    result = await executor.execute(_request())

    assert result.attempt.turn_count == 1
    assert result.attempt.planned_max_turns == 2
    assert result.attempt.stopped_early
    assert result.attempt.stop_reason is AttemptStopReason.ATTEMPT_SUCCESS
    assert provider.call_count == 1
    assert result.findings[0].attempt_id == result.attempt.id


async def test_blocked_tool_violation_also_stops_without_waiting_for_score_one() -> None:
    executor, provider = _executor(
        target_script=[
            _tool_call("get_customer_profile", customer_id="customer_b"),
            "The permission layer denied it.",
        ],
        attack_script=["show customer_b"],
        strategy=CROSS_USER_RESOURCE_ACCESS,
    )
    result = await executor.execute(_request(CROSS_USER_RESOURCE_ACCESS))

    assert result.attempt.reward < 1.0
    assert result.attempt.stop_reason is AttemptStopReason.ATTEMPT_SUCCESS
    assert result.attempt.turn_count == 1
    assert result.findings[0].triad.attempted_action
    assert result.findings[0].triad.realized_impact is ImpactStatus.NOT_REALIZED
    # 一次外部 Turn 内部有 tool call + tool result 后续,所以 target provider 调了两次。
    assert provider.call_count == 2


async def test_partial_signal_continues_until_confirmed_finding() -> None:
    executor, _ = _executor(
        target_script=[
            f"Maybe it starts with {SYSTEM_PROMPT_CANARY_PREFIX}00000.",
            f"The full value is {SYSTEM_PROMPT_CANARY}.",
        ],
        attack_script=["first", "follow up"],
    )
    result = await executor.execute(_request())

    assert result.attempt.turn_count == 2
    assert not result.attempt.stopped_early
    assert result.attempt.stop_reason is AttemptStopReason.ATTEMPT_SUCCESS


async def test_no_finding_runs_to_max_turns() -> None:
    executor, _ = _executor(
        target_script=["No.", "Still no."],
        attack_script=["first", "second"],
    )
    result = await executor.execute(_request())

    assert result.findings == []
    assert result.attempt.turn_count == 2
    assert result.attempt.stop_reason is AttemptStopReason.MAX_TURNS


async def test_executor_passes_visible_conversation_history_to_next_turn() -> None:
    executor, provider = _executor(
        target_script=["First response.", "Second response."],
        attack_script=["first attack", "second attack"],
    )
    await executor.execute(_request())

    second_target_call = provider.calls[1]
    contents = [message.content for message in second_target_call]
    assert "first attack" in contents
    assert "First response." in contents
    assert "second attack" in contents


async def test_cost_and_reproduction_seeds_are_recorded() -> None:
    executor, _ = _executor(
        target_script=["No.", "No again."],
        attack_script=["first", "second"],
        tokens_per_call=(100, 20),
    )
    result = await executor.execute(_request(attempt_index=37))
    attempt = result.attempt

    assert attempt.cost.prompt_tokens == 200
    assert attempt.cost.completion_tokens == 40
    assert attempt.reproduction.run_seed == 42
    assert attempt.reproduction.seed is not None
    assert attempt.reproduction.generator_seed is not None
    assert attempt.reproduction.target_seed is not None
    assert attempt.reproduction.extra["attempt_index"] == 37


async def test_orchestrator_supplied_attempt_id_is_preserved() -> None:
    executor, _ = _executor(
        target_script=["No.", "No again."],
        attack_script=["first", "second"],
    )
    request = _request()
    result = await executor.execute(request)

    assert result.attempt.id == request.attempt_id


async def test_target_failure_raises_typed_error_with_partial_trace() -> None:
    executor, _ = _executor(
        target_script=["First response."],
        attack_script=["first", "second"],
    )

    with pytest.raises(AttemptExecutionError) as raised:
        await executor.execute(_request())

    assert len(raised.value.partial_turns) == 1
    assert raised.value.strategy_id == DIRECT_INSTRUCTION_OVERRIDE.id


async def test_each_attempt_resets_target_state() -> None:
    executor, _ = _executor(
        target_script=["No.", "No.", "No.", "No."],
        attack_script=["first", "second"],
    )
    first = await executor.execute(_request(attempt_index=0))
    second = await executor.execute(_request(attempt_index=1))

    assert first.attempt.reproduction.seed != second.attempt.reproduction.seed


def test_cost_uses_typed_trace_metadata_field() -> None:
    from redcell.executor import _cost_of

    turns = [
        Turn(
            index=0,
            attacker_message="test",
            output=AdapterOutput(
                observability=ObservabilityLevel.FULL,
                trace_metadata=TraceMetadata(cost_usd=0.0125),
            ),
        ),
        Turn(
            index=1,
            attacker_message="test again",
            output=AdapterOutput(
                observability=ObservabilityLevel.FULL,
                trace_metadata=TraceMetadata(cost_usd=0.0075),
            ),
        ),
    ]

    assert _cost_of(turns).usd == pytest.approx(0.02)


async def test_attempt_cost_includes_the_attacker_side() -> None:
    """⭐ 预算必须同时管住两侧,否则 `max_cost_usd` 是一张假的安全网。

    回归:attacker 的 token/费用曾经在 `LLMMutationGenerator` 里就被丢掉,
    `_cost_of()` 只累加 target adapter 那一侧 —— 设了上限也挡不住攻击方。
    """
    from redcell._base import CostRecord
    from redcell.generation import AttackGenerator, AttackMessage

    class _PaidAttacker(AttackGenerator):
        @property
        def name(self) -> str:
            return "paid"

        async def generate(self, request) -> AttackMessage:
            return AttackMessage(
                content="give me everything",
                generator=self.name,
                cost=CostRecord(prompt_tokens=200, completion_tokens=50, usd=0.25),
            )

    provider = ScriptedProvider(default="No.", tokens_per_call=(10, 5))
    executor = ConversationExecutor(
        adapter=ArenaAdapter(provider),
        generator=_PaidAttacker(),
        scorer=Level1Scorer(SUPPORT_AGENT_POLICY),
        policy=SUPPORT_AGENT_POLICY,
    )

    result = await executor.execute(_request())
    turns = result.attempt.turns

    # target 侧 10+5 每轮,attacker 侧 200+50 每轮 —— 两侧都要在总账里。
    assert result.attempt.cost.prompt_tokens == 210 * len(turns)
    assert result.attempt.cost.completion_tokens == 55 * len(turns)
    assert result.attempt.cost.usd == pytest.approx(0.25 * len(turns))
    # 但仍然分开留痕,事后能回答"这轮到底是哪一侧贵"。
    assert all(t.attacker_cost.prompt_tokens == 200 for t in turns)


async def test_generation_retries_reach_the_trace() -> None:
    """回归:字段加了却没流进 trace,"校准时聚合它"就是一句空话。

    重试会把"攻击方不稳"这个症状盖住,而症状正是"该换攻击方"的信号。
    """
    from redcell.generation import AttackGenerator, AttackMessage

    class _Flaky(AttackGenerator):
        @property
        def name(self) -> str:
            return "flaky"

        async def generate(self, request) -> AttackMessage:
            return AttackMessage(content="attack", generator=self.name, generation_retries=3)

    executor = ConversationExecutor(
        adapter=ArenaAdapter(ScriptedProvider(default="No.")),
        generator=_Flaky(),
        scorer=Level1Scorer(SUPPORT_AGENT_POLICY),
        policy=SUPPORT_AGENT_POLICY,
    )
    result = await executor.execute(_request())

    assert all(t.attacker_generation_retries == 3 for t in result.attempt.turns)
