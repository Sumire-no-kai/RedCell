from __future__ import annotations

import pytest

from redcell.gate_analysis import GateCondition, SeedPlan, TokenPrefix, analyse_phase_0_5


def test_gate_analysis_requires_complete_paired_blocks_and_uses_path_identity() -> None:
    prefixes = []
    for seed in range(12):
        for condition in GateCondition:
            count = 1 if condition is not GateCondition.LLM_MEMORY else 4
            prefixes.append(
                TokenPrefix(
                    seed=seed,
                    condition=condition,
                    checkpoint_tokens=160000,
                    attack_path_signatures={f"{condition.value}-{index}" for index in range(count)},
                )
            )
    prefixes.append(
        TokenPrefix(
            seed=99,
            condition=GateCondition.STATIC_OFF,
            checkpoint_tokens=160000,
            attack_path_signatures=set(),
        )
    )

    analysis = analyse_phase_0_5(prefixes, bootstrap_samples=100)

    assert analysis.valid_seeds == list(range(12))
    assert analysis.invalid_seeds == [99]
    assert len(analysis.comparisons) == 3
    assert all(item.mean_difference == 3 for item in analysis.comparisons)
    assert analysis.passed


def test_gate_analysis_keeps_later_complete_blocks_as_reserves() -> None:
    prefixes = [
        TokenPrefix(
            seed=seed,
            condition=condition,
            checkpoint_tokens=160000,
            attack_path_signatures={condition.value},
        )
        for seed in range(13)
        for condition in GateCondition
    ]

    analysis = analyse_phase_0_5(prefixes, bootstrap_samples=10)

    assert analysis.valid_seeds == list(range(12))
    assert analysis.reserve_seeds == [12]


def test_gate_analysis_uses_the_registered_seed_order_not_result_order() -> None:
    plan = SeedPlan(primary=[20, *range(1, 12)], reserve=[12, 13, 14, 15])
    prefixes = [
        TokenPrefix(seed=seed, condition=condition, checkpoint_tokens=160000)
        for seed in [1, 20]
        for condition in GateCondition
    ]

    analysis = analyse_phase_0_5(prefixes, seed_plan=plan)

    assert analysis.valid_seeds == [20, 1]
    assert analysis.missing_planned_seeds == [2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]


def test_seed_plan_rejects_pilot_seed_and_wrong_cardinality() -> None:
    with pytest.raises(ValueError, match="12 primary"):
        SeedPlan(primary=[1], reserve=[2])
    with pytest.raises(ValueError, match="pilot seeds"):
        SeedPlan(primary=[5000, *range(1, 12)], reserve=[12, 13, 14, 15])


def test_gate_analysis_rejects_duplicate_seed_condition_cells() -> None:
    prefixes = [
        TokenPrefix(seed=seed, condition=condition, checkpoint_tokens=160000)
        for seed in range(12)
        for condition in GateCondition
    ]
    prefixes.append(
        TokenPrefix(
            run_id="duplicate",
            seed=0,
            condition=GateCondition.STATIC_OFF,
            checkpoint_tokens=160000,
        )
    )

    analysis = analyse_phase_0_5(prefixes, bootstrap_samples=10)

    assert analysis.duplicate_cells == ["0:static-off"]
    assert analysis.invalid_seeds == [0]
    assert analysis.valid_seeds == list(range(1, 12))
    assert not analysis.passed


def test_gate_analysis_rejects_a_prefix_that_did_not_reach_checkpoint() -> None:
    prefixes = [
        TokenPrefix(
            seed=seed,
            condition=condition,
            checkpoint_tokens=160000,
            checkpoint_reached=not (seed == 0 and condition is GateCondition.LLM_MEMORY),
        )
        for seed in range(12)
        for condition in GateCondition
    ]

    analysis = analyse_phase_0_5(prefixes, bootstrap_samples=10)

    assert analysis.invalid_seeds == [0]
    assert analysis.valid_seeds == list(range(1, 12))
    assert not analysis.passed
