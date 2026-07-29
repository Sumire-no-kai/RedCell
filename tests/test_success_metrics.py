from __future__ import annotations

import pytest

from redcell.protocols import (
    AdapterOutput,
    Evidence,
    Finding,
    ImpactStatus,
    ObservabilityLevel,
    ReproductionContext,
    SignalChannel,
    SignalScore,
    Turn,
    ViolationTriad,
    VulnerabilityCategory,
    build_attempt,
)
from redcell.scoring import ScoringResult
from redcell.success_metrics import derive_success_metrics


def _attempt(strategy_id: str, score: float):
    return build_attempt(
        run_id="run_1",
        strategy_id=strategy_id,
        actor="customer_a",
        attack_prompt="test",
        reproduction=ReproductionContext(
            policy_version="v1",
            target_name="target",
            adapter_type="scripted",
            strategy_id=strategy_id,
        ),
        turns=[
            Turn(
                index=0,
                attacker_message="test",
                output=AdapterOutput(observability=ObservabilityLevel.FULL),
            )
        ],
        signals=[
            SignalScore(
                channel=SignalChannel.TOOL,
                score=score,
                tier="test",
                evidence="test",
            )
        ],
    )


def _finding(
    attempt,
    *,
    attempted: bool = True,
    impact: ImpactStatus = ImpactStatus.NOT_REALIZED,
    strategy_id: str | None = None,
) -> Finding:
    return Finding(
        run_id=attempt.run_id,
        attempt_id=attempt.id,
        category=VulnerabilityCategory.UNAUTHORIZED_TOOL_USE,
        title="test finding",
        actor=attempt.actor,
        strategy_id=strategy_id or attempt.strategy_id,
        triad=ViolationTriad(attempted_action=attempted, realized_impact=impact),
        evidence=[Evidence(description="test evidence")],
        observability=ObservabilityLevel.FULL,
    )


def test_metrics_deduplicate_findings_and_ignore_numeric_score() -> None:
    blocked = _attempt("s1", 0.7)
    numeric_only = _attempt("s1", 1.0)
    metrics = derive_success_metrics(
        [blocked, numeric_only],
        [
            _finding(blocked),
            _finding(blocked),
        ],
    )

    stat = metrics.by_strategy["s1"]
    assert stat.attempt_hits == 1
    assert stat.impact_hits == 0
    assert stat.attempt_success_rate == 0.5
    assert stat.impact_success_rate == 0.0
    assert metrics.queries_to_first_attempt_success == 1
    assert metrics.queries_to_first_impact_success is None


def test_intent_only_finding_is_not_attempt_success_or_stop_signal() -> None:
    attempt = _attempt("s1", 0.6)
    intent_only = _finding(attempt, attempted=False, impact=ImpactStatus.NOT_REALIZED)

    metrics = derive_success_metrics([attempt], [intent_only])
    scoring = ScoringResult(signals=attempt.signals, findings=[intent_only])

    assert metrics.by_strategy["s1"].attempt_hits == 0
    assert metrics.queries_to_first_attempt_success is None
    assert not scoring.has_attempt_success


def test_mismatched_finding_fails_loudly() -> None:
    attempt = _attempt("s1", 0.7)
    mismatched = _finding(attempt, strategy_id="s2")

    with pytest.raises(ValueError, match="strategy_id 不一致"):
        derive_success_metrics([attempt], [mismatched])
