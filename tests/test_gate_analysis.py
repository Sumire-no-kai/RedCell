from __future__ import annotations

from redcell.gate_analysis import GateCondition, TokenPrefix, analyse_phase_0_5


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
