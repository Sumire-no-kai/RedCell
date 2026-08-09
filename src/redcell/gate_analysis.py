"""Deterministic analysis for the frozen Phase 0.5 paired Gate."""

from __future__ import annotations

import itertools
import random
from enum import StrEnum

from pydantic import Field, model_validator

from redcell.finding_identity import attack_path_signature
from redcell.protocols.common import RedCellModel
from redcell.protocols.finding import Finding
from redcell.protocols.run import Run, RunEvent, RunEventType


class GateCondition(StrEnum):
    STATIC_OFF = "static-off"
    STATIC_MEMORY = "static-memory"
    LLM_MEMORY = "llm-memory"
    LLM_OFF = "llm-off"
    RANDOM_OFF = "random-off"
    THOMPSON_OFF = "thompson-off"


class SeedPlan(RedCellModel):
    """The ordered, pre-registered Phase 0.5 seed allocation.

    This intentionally carries no generated defaults.  A generated sequence would
    only look pre-registered after the results were already available.
    """

    primary: list[int]
    reserve: list[int]

    @model_validator(mode="after")
    def validate_frozen_allocation(self) -> SeedPlan:
        if len(self.primary) != 12 or len(self.reserve) != 4:
            raise ValueError("Phase 0.5 seed plan requires exactly 12 primary and 4 reserve seeds")
        all_seeds = [*self.primary, *self.reserve]
        if len(set(all_seeds)) != len(all_seeds):
            raise ValueError("Phase 0.5 seed plan must not repeat a seed")
        if set(all_seeds) & {5000, 5001, 5002}:
            raise ValueError("Phase 0 pilot seeds 5000-5002 are not eligible for Phase 0.5")
        return self

    @property
    def ordered(self) -> list[int]:
        return [*self.primary, *self.reserve]


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
    reserve_seeds: list[int] = Field(default_factory=list)
    missing_planned_seeds: list[int] = Field(default_factory=list)
    unregistered_seeds: list[int] = Field(default_factory=list)
    comparisons: list[PairedComparison]

    @property
    def passed(self) -> bool:
        return (
            len(self.valid_seeds) == 12
            and not self.unregistered_seeds
            and all(item.passed for item in self.comparisons)
        )


def analyse_phase_0_5(
    prefixes: list[TokenPrefix],
    *,
    checkpoint_tokens: int = 160000,
    bootstrap_samples: int = 10000,
    seed_plan: SeedPlan | None = None,
) -> GateAnalysis:
    required = set(GateCondition)
    by_seed: dict[int, dict[GateCondition, TokenPrefix]] = {}
    for prefix in prefixes:
        if prefix.checkpoint_tokens != checkpoint_tokens:
            continue
        by_seed.setdefault(prefix.seed, {})[prefix.condition] = prefix
    eligible: list[int] = []
    invalid: list[int] = []
    for seed, values in sorted(by_seed.items()):
        if set(values) == required and all(value.valid for value in values.values()):
            eligible.append(seed)
        else:
            invalid.append(seed)
    ordered = seed_plan.ordered if seed_plan is not None else sorted(by_seed)
    valid = [seed for seed in ordered if seed in eligible][:12]
    missing_planned = [seed for seed in ordered if seed not in by_seed]
    unregistered = sorted(set(by_seed) - set(ordered)) if seed_plan is not None else []
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
        reserve_seeds=[seed for seed in ordered if seed in eligible and seed not in valid],
        missing_planned_seeds=missing_planned,
        unregistered_seeds=unregistered,
        comparisons=comparisons,
    )


def token_prefixes_from_events(
    *,
    run: Run,
    events: list[RunEvent],
    findings: list[Finding],
    checkpoints: tuple[int, ...] = (64000, 160000, 320000),
) -> list[TokenPrefix]:
    """Project immutable committed-event prefixes; later findings never backfill."""
    if run.experiment_conditions is None or run.experiment_conditions.search is None:
        raise ValueError("Gate prefix requires frozen Phase 0.5 conditions")
    mode = run.experiment_conditions.generation_memory
    if mode is None:
        raise ValueError("Gate prefix requires frozen generation memory condition")
    condition = _condition_for(run.experiment_conditions.search.selector.value, mode.mode.value)
    by_id = {finding.id: finding for finding in findings}
    output: list[TokenPrefix] = []
    for checkpoint in checkpoints:
        paths: set[str] = set()
        for event in sorted(events, key=lambda item: item.sequence):
            if event.event_type is not RunEventType.ATTEMPT_COMMITTED:
                continue
            usage = event.payload.get("usage", {})
            if (
                int(usage.get("prompt_tokens", 0)) + int(usage.get("completion_tokens", 0))
                > checkpoint
            ):
                break
            for finding_id in event.payload.get("finding_ids", []):
                finding = by_id.get(finding_id)
                if finding is not None:
                    paths.add(attack_path_signature(finding))
        output.append(
            TokenPrefix(
                seed=run.seed or 0,
                condition=condition,
                checkpoint_tokens=checkpoint,
                attack_path_signatures=paths,
                valid=run.is_conclusive,
            )
        )
    return output


def _condition_for(selector: str, memory: str) -> GateCondition:
    lookup = {
        ("static", "off"): GateCondition.STATIC_OFF,
        ("static", "bounded-relevant-v1"): GateCondition.STATIC_MEMORY,
        ("llm", "bounded-relevant-v1"): GateCondition.LLM_MEMORY,
        ("llm", "off"): GateCondition.LLM_OFF,
        ("random", "off"): GateCondition.RANDOM_OFF,
        ("thompson", "off"): GateCondition.THOMPSON_OFF,
    }
    try:
        return lookup[(selector, memory)]
    except KeyError as exc:
        raise ValueError("condition is outside the frozen Phase 0.5 Gate matrix") from exc


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
