"""Deterministic analysis for the frozen Phase 0.5 paired Gate."""

from __future__ import annotations

import itertools
import random
from enum import StrEnum

from pydantic import Field

from redcell.protocols.common import RedCellModel


class GateCondition(StrEnum):
    STATIC_OFF = "static-off"
    STATIC_MEMORY = "static-memory"
    LLM_MEMORY = "llm-memory"
    LLM_OFF = "llm-off"
    RANDOM_OFF = "random-off"
    THOMPSON_OFF = "thompson-off"


class TokenPrefix(RedCellModel):
    seed: int
    condition: GateCondition
    checkpoint_tokens: int
    attack_path_signatures: set[str] = Field(default_factory=set)
    valid: bool = True

    @property
    def path_count(self) -> int:
        return len(self.attack_path_signatures)


class PairedComparison(RedCellModel):
    treatment: GateCondition
    control: GateCondition
    mean_difference: float
    control_mean: float
    practical_threshold: float
    bootstrap_ci_lower: float
    permutation_p_value: float
    holm_adjusted_p_value: float | None = None

    @property
    def passed(self) -> bool:
        return (
            self.mean_difference >= self.practical_threshold
            and self.bootstrap_ci_lower > 0
            and (self.holm_adjusted_p_value or self.permutation_p_value) < 0.05
        )


class GateAnalysis(RedCellModel):
    checkpoint_tokens: int
    valid_seeds: list[int]
    invalid_seeds: list[int]
    comparisons: list[PairedComparison]

    @property
    def passed(self) -> bool:
        return len(self.valid_seeds) == 12 and all(item.passed for item in self.comparisons)


def analyse_phase_0_5(
    prefixes: list[TokenPrefix], *, checkpoint_tokens: int = 160000, bootstrap_samples: int = 10000
) -> GateAnalysis:
    required = set(GateCondition)
    by_seed: dict[int, dict[GateCondition, TokenPrefix]] = {}
    for prefix in prefixes:
        if prefix.checkpoint_tokens != checkpoint_tokens:
            continue
        by_seed.setdefault(prefix.seed, {})[prefix.condition] = prefix
    valid: list[int] = []
    invalid: list[int] = []
    for seed, values in sorted(by_seed.items()):
        if set(values) == required and all(value.valid for value in values.values()):
            valid.append(seed)
        else:
            invalid.append(seed)
    comparisons = [
        _comparison(valid, by_seed, GateCondition.LLM_MEMORY, control, bootstrap_samples)
        for control in (
            GateCondition.STATIC_OFF,
            GateCondition.RANDOM_OFF,
            GateCondition.THOMPSON_OFF,
        )
    ]
    adjusted = _holm([comparison.permutation_p_value for comparison in comparisons])
    comparisons = [
        comparison.model_copy(update={"holm_adjusted_p_value": adjusted[index]})
        for index, comparison in enumerate(comparisons)
    ]
    return GateAnalysis(
        checkpoint_tokens=checkpoint_tokens,
        valid_seeds=valid,
        invalid_seeds=invalid,
        comparisons=comparisons,
    )


def _comparison(
    seeds: list[int],
    values: dict[int, dict[GateCondition, TokenPrefix]],
    treatment: GateCondition,
    control: GateCondition,
    bootstrap_samples: int,
) -> PairedComparison:
    differences = [
        values[seed][treatment].path_count - values[seed][control].path_count for seed in seeds
    ]
    controls = [values[seed][control].path_count for seed in seeds]
    mean = sum(differences) / len(differences) if differences else 0.0
    control_mean = sum(controls) / len(controls) if controls else 0.0
    lower = _bootstrap_lower(differences, bootstrap_samples)
    return PairedComparison(
        treatment=treatment,
        control=control,
        mean_difference=mean,
        control_mean=control_mean,
        practical_threshold=max(1.0, control_mean * 0.2),
        bootstrap_ci_lower=lower,
        permutation_p_value=_exact_sign_flip_p_value(differences),
    )


def _bootstrap_lower(values: list[int], samples: int) -> float:
    if not values:
        return 0.0
    rng = random.Random(0)
    means = sorted(sum(rng.choice(values) for _ in values) / len(values) for _ in range(samples))
    return means[max(0, int(samples * 0.025) - 1)]


def _exact_sign_flip_p_value(values: list[int]) -> float:
    if not values:
        return 1.0
    observed = sum(values) / len(values)
    extreme = sum(
        sum(sign * value for sign, value in zip(signs, values, strict=True)) / len(values)
        >= observed
        for signs in itertools.product((-1, 1), repeat=len(values))
    )
    return extreme / (2 ** len(values))


def _holm(values: list[float]) -> list[float]:
    ordered = sorted(enumerate(values), key=lambda item: item[1])
    adjusted = [0.0] * len(values)
    running = 0.0
    for index, (original, value) in enumerate(ordered):
        running = max(running, min(1.0, value * (len(values) - index)))
        adjusted[original] = running
    return adjusted
