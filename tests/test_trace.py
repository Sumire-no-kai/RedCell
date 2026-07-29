from __future__ import annotations

import pytest
from pydantic import ValidationError

from redcell.protocols import (
    REDCELL_PROTOCOL_VERSION,
    AdapterOutput,
    Attempt,
    AttemptStopReason,
    ObservabilityLevel,
    ReproductionContext,
    SignalChannel,
    SignalScore,
    Turn,
    build_attempt,
    compute_reward,
)


def _signal(channel: SignalChannel, score: float) -> SignalScore:
    return SignalScore(channel=channel, score=score, tier="t", evidence="e")


def test_compute_reward_takes_max() -> None:
    signals = [
        _signal(SignalChannel.CANARY, 0.6),
        _signal(SignalChannel.TOOL, 1.0),
    ]
    assert compute_reward(signals) == 1.0


def test_compute_reward_empty_is_zero() -> None:
    """没有任何正向证据自然是 0 —— 不需要专门去识别"模型拒绝了"。

    判断拒绝需要语义理解,那会把 LLM judge 拖进 Phase 0 的核心实验。
    """
    assert compute_reward([]) == 0.0


def test_signals_are_retained_in_full(reproduction: ReproductionContext) -> None:
    """reward 取 max,但证据链绝不能有损:两条线都要留在记录里。"""
    attempt = build_attempt(
        run_id="run_1",
        strategy_id="cross_user_resource_access",
        actor="customer_a",
        attack_prompt="...",
        reproduction=reproduction,
        signals=[
            _signal(SignalChannel.CANARY, 0.6),
            _signal(SignalChannel.TOOL, 1.0),
        ],
    )

    assert attempt.reward == 1.0
    assert len(attempt.signals) == 2
    assert attempt.signal(SignalChannel.CANARY).score == 0.6
    # 两条线同时非零 = 两类风险同时存在,应各自生成一条 Finding。
    assert set(attempt.triggered_channels()) == {SignalChannel.CANARY, SignalChannel.TOOL}


def test_attempt_rejects_hand_written_reward(reproduction: ReproductionContext) -> None:
    """reward 必须由 signals 推导。手工赋值会让 bandit 学到假信号。"""
    with pytest.raises(ValidationError, match="不一致"):
        Attempt(
            run_id="run_1",
            strategy_id="s",
            actor="customer_a",
            attack_prompt="...",
            reproduction=reproduction,
            signals=[_signal(SignalChannel.TOOL, 0.5)],
            reward=1.0,
        )


def test_attempt_spans_multiple_turns(reproduction: ReproductionContext) -> None:
    """一次 attempt = 一场完整会话(可能多轮),不是一轮。"""
    turns = [
        Turn(
            index=i,
            attacker_message=f"turn {i}",
            output=AdapterOutput(observability=ObservabilityLevel.FULL),
        )
        for i in range(3)
    ]
    attempt = build_attempt(
        run_id="run_1",
        strategy_id="multi_turn_trust_building",
        actor="customer_a",
        attack_prompt="...",
        reproduction=reproduction,
        turns=turns,
    )
    assert attempt.turn_count == 3
    assert attempt.reward == 0.0


def test_attempt_records_semantic_stop_reason(reproduction: ReproductionContext) -> None:
    attempt = build_attempt(
        attempt_id="attempt_fixed",
        run_id="run_1",
        strategy_id="s",
        actor="customer_a",
        attack_prompt="...",
        reproduction=reproduction,
        planned_max_turns=2,
        stop_reason=AttemptStopReason.CONFIRMED_FINDING,
        turns=[
            Turn(
                index=0,
                attacker_message="...",
                output=AdapterOutput(observability=ObservabilityLevel.FULL),
            )
        ],
    )

    assert attempt.id == "attempt_fixed"
    assert attempt.stopped_early
    assert attempt.stop_reason is AttemptStopReason.CONFIRMED_FINDING


def test_reproduction_context_records_replay_inputs() -> None:
    ctx = ReproductionContext(
        policy_version="v1",
        target_name="support-agent",
        adapter_type="arena",
        strategy_id="direct_instruction_override",
        seed=42,
        target_model="test-model",
        target_temperature=0.0,
    )
    assert ctx.seed == 42
    assert ctx.protocol_version == REDCELL_PROTOCOL_VERSION == "0.2.0"
    assert ctx.recorded_at.tzinfo is not None


def test_signal_score_bounds() -> None:
    with pytest.raises(ValidationError):
        _signal(SignalChannel.TOOL, 1.5)
