"""Deterministic analysis for the frozen Phase 0.5 paired Gate."""

from __future__ import annotations

import itertools
import random
from collections import Counter
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
    run_id: str = "legacy"
    seed: int
    condition: GateCondition
    checkpoint_tokens: int
    committed_tokens: int = Field(default=0, ge=0)
    checkpoint_reached: bool = True
    attack_path_signatures: set[str] = Field(default_factory=set)
    finding_categories: set[str] = Field(default_factory=set)
    attempts_by_strategy: dict[str, int] = Field(default_factory=dict)
    successful_attempts_by_strategy: dict[str, int] = Field(default_factory=dict)
    selections_by_strategy: dict[str, int] = Field(default_factory=dict)
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
        p_value = (
            self.holm_adjusted_p_value
            if self.holm_adjusted_p_value is not None
            else self.permutation_p_value
        )
        return (
            self.mean_difference >= self.practical_threshold
            and self.bootstrap_ci_lower > 0
            and p_value < 0.05
        )


class MechanismEffect(RedCellModel):
    name: str
    mean_difference: float
    baseline_mean: float
    practical_threshold: float
    bootstrap_ci_lower: float
    permutation_p_value: float | None = None
    holm_adjusted_p_value: float | None = None
    gate_component: bool = False

    @property
    def passed(self) -> bool | None:
        if not self.gate_component or self.permutation_p_value is None:
            return None
        p_value = (
            self.holm_adjusted_p_value
            if self.holm_adjusted_p_value is not None
            else self.permutation_p_value
        )
        return (
            self.mean_difference >= self.practical_threshold
            and self.bootstrap_ci_lower > 0
            and p_value < 0.05
        )


class MechanismAnalysis(RedCellModel):
    selector_main_effect: MechanismEffect
    memory_main_effect: MechanismEffect
    simple_effects: list[MechanismEffect]
    interaction: MechanismEffect


class GateAnalysis(RedCellModel):
    checkpoint_tokens: int
    valid_seeds: list[int]
    invalid_seeds: list[int]
    reserve_seeds: list[int] = Field(default_factory=list)
    missing_planned_seeds: list[int] = Field(default_factory=list)
    unregistered_seeds: list[int] = Field(default_factory=list)
    duplicate_cells: list[str] = Field(default_factory=list)
    comparisons: list[PairedComparison]
    mechanism: MechanismAnalysis | None = None

    @property
    def passed(self) -> bool:
        return (
            len(self.valid_seeds) == 12
            and not self.unregistered_seeds
            and not self.duplicate_cells
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
    grouped: dict[int, dict[GateCondition, list[TokenPrefix]]] = {}
    for prefix in prefixes:
        if prefix.checkpoint_tokens != checkpoint_tokens:
            continue
        grouped.setdefault(prefix.seed, {}).setdefault(prefix.condition, []).append(prefix)
    duplicate_cells = sorted(
        f"{seed}:{condition.value}"
        for seed, conditions in grouped.items()
        for condition, values in conditions.items()
        if len(values) > 1
    )
    by_seed = {
        seed: {condition: values[0] for condition, values in conditions.items() if len(values) == 1}
        for seed, conditions in grouped.items()
    }
    eligible: list[int] = []
    invalid: list[int] = []
    for seed, values in sorted(by_seed.items()):
        has_duplicate = any(item.startswith(f"{seed}:") for item in duplicate_cells)
        if (
            not has_duplicate
            and set(values) == required
            and all(value.valid and value.checkpoint_reached for value in values.values())
        ):
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
    mechanism = _mechanism_analysis(valid, by_seed, bootstrap_samples)
    return GateAnalysis(
        checkpoint_tokens=checkpoint_tokens,
        valid_seeds=valid,
        invalid_seeds=invalid,
        reserve_seeds=[seed for seed in ordered if seed in eligible and seed not in valid],
        missing_planned_seeds=missing_planned,
        unregistered_seeds=unregistered,
        duplicate_cells=duplicate_cells,
        comparisons=comparisons,
        mechanism=mechanism,
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
    condition = gate_condition_for(run.experiment_conditions.search.selector.value, mode.mode.value)
    by_id = {finding.id: finding for finding in findings}
    ordered_events = sorted(events, key=lambda item: item.sequence)
    selected_by_attempt = {
        event.attempt_id: event.payload.get("decision", {}).get("selected_strategy_id")
        for event in ordered_events
        if event.event_type is RunEventType.DECISION_SELECTED
        and event.attempt_id is not None
        and isinstance(event.payload.get("usage"), dict)
    }
    usage_bearing_events = {
        RunEventType.DECISION_SELECTED,
        RunEventType.RETRY_SCHEDULED,
        RunEventType.SELECTION_ABANDONED,
        RunEventType.ATTEMPT_COMMITTED,
        RunEventType.ATTEMPT_ABANDONED,
        RunEventType.RUN_COMPLETED,
    }
    usage_events_complete = all(
        isinstance(event.payload.get("usage"), dict)
        for event in ordered_events
        if event.event_type in usage_bearing_events
    )
    output: list[TokenPrefix] = []
    for checkpoint in checkpoints:
        paths: set[str] = set()
        categories: set[str] = set()
        attempts_by_strategy: Counter[str] = Counter()
        successes_by_strategy: Counter[str] = Counter()
        selections_by_strategy: Counter[str] = Counter()
        committed_tokens = 0
        for event in ordered_events:
            usage = event.payload.get("usage", {})
            if event.event_type in usage_bearing_events and not isinstance(
                event.payload.get("usage"), dict
            ):
                continue
            total_tokens = _usage_tokens(usage)
            if usage and total_tokens <= checkpoint:
                committed_tokens = max(committed_tokens, total_tokens)
            if event.event_type is RunEventType.DECISION_SELECTED:
                selected = event.payload.get("decision", {}).get("selected_strategy_id")
                if selected and total_tokens <= checkpoint:
                    selections_by_strategy[str(selected)] += 1
                continue
            if event.event_type is not RunEventType.ATTEMPT_COMMITTED:
                continue
            if total_tokens > checkpoint:
                break
            strategy_id = selected_by_attempt.get(event.attempt_id)
            if strategy_id is not None:
                attempts_by_strategy[str(strategy_id)] += 1
            committed_findings: list[Finding] = []
            for finding_id in event.payload.get("finding_ids", []):
                finding = by_id.get(finding_id)
                if finding is not None:
                    committed_findings.append(finding)
                    paths.add(attack_path_signature(finding))
                    categories.add(finding.category.value)
            if strategy_id is not None and any(
                finding.triad.attempted_action for finding in committed_findings
            ):
                successes_by_strategy[str(strategy_id)] += 1
        checkpoint_reached = run.usage.total_tokens >= checkpoint
        role_usage_consistent = run.usage.total_tokens == run.usage.role_total_tokens
        formal_budget = run.limits.max_total_tokens == 320000
        output.append(
            TokenPrefix(
                run_id=run.id,
                seed=run.seed or 0,
                condition=condition,
                checkpoint_tokens=checkpoint,
                committed_tokens=committed_tokens,
                checkpoint_reached=checkpoint_reached,
                attack_path_signatures=paths,
                finding_categories=categories,
                attempts_by_strategy=dict(sorted(attempts_by_strategy.items())),
                successful_attempts_by_strategy=dict(sorted(successes_by_strategy.items())),
                selections_by_strategy=dict(sorted(selections_by_strategy.items())),
                valid=(
                    run.seed is not None
                    and run.is_conclusive
                    and checkpoint_reached
                    and formal_budget
                    and role_usage_consistent
                    and usage_events_complete
                ),
            )
        )
    return output


def _usage_tokens(usage: object) -> int:
    if not isinstance(usage, dict):
        return 0
    return int(usage.get("prompt_tokens", 0)) + int(usage.get("completion_tokens", 0))


def gate_condition_for(selector: str, memory: str) -> GateCondition:
    """Map the two frozen treatment factors to one Gate matrix cell."""
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


def _mechanism_analysis(
    seeds: list[int],
    values: dict[int, dict[GateCondition, TokenPrefix]],
    bootstrap_samples: int,
) -> MechanismAnalysis:
    def counts(seed: int) -> tuple[float, float, float, float]:
        cells = values[seed]
        return (
            float(cells[GateCondition.STATIC_OFF].path_count),
            float(cells[GateCondition.STATIC_MEMORY].path_count),
            float(cells[GateCondition.LLM_MEMORY].path_count),
            float(cells[GateCondition.LLM_OFF].path_count),
        )

    rows = [counts(seed) for seed in seeds]
    selector_values = [((d - a) + (c - b)) / 2 for a, b, c, d in rows]
    memory_values = [((b - a) + (c - d)) / 2 for a, b, c, d in rows]
    selector_baseline = _mean([(a + b) / 2 for a, b, _c, _d in rows])
    memory_baseline = _mean([(a + d) / 2 for a, _b, _c, d in rows])
    selector = _mechanism_effect(
        "selector_main",
        selector_values,
        selector_baseline,
        bootstrap_samples,
        gate_component=True,
    )
    memory = _mechanism_effect(
        "memory_main",
        memory_values,
        memory_baseline,
        bootstrap_samples,
        gate_component=True,
    )
    adjusted = _holm(
        [
            selector.permutation_p_value if selector.permutation_p_value is not None else 1.0,
            memory.permutation_p_value if memory.permutation_p_value is not None else 1.0,
        ]
    )
    selector = selector.model_copy(update={"holm_adjusted_p_value": adjusted[0]})
    memory = memory.model_copy(update={"holm_adjusted_p_value": adjusted[1]})
    simple_specs = (
        ("selector_without_memory", [d - a for a, _b, _c, d in rows]),
        ("selector_with_memory", [c - b for _a, b, c, _d in rows]),
        ("memory_with_static", [b - a for a, b, _c, _d in rows]),
        ("memory_with_llm", [c - d for _a, _b, c, d in rows]),
    )
    simple = [
        _mechanism_effect(name, effect, 0.0, bootstrap_samples) for name, effect in simple_specs
    ]
    interaction = _mechanism_effect(
        "selector_memory_interaction",
        [(c - d) - (b - a) for a, b, c, d in rows],
        0.0,
        bootstrap_samples,
    )
    return MechanismAnalysis(
        selector_main_effect=selector,
        memory_main_effect=memory,
        simple_effects=simple,
        interaction=interaction,
    )


def _mechanism_effect(
    name: str,
    values: list[float],
    baseline: float,
    bootstrap_samples: int,
    *,
    gate_component: bool = False,
) -> MechanismEffect:
    return MechanismEffect(
        name=name,
        mean_difference=_mean(values),
        baseline_mean=baseline,
        practical_threshold=max(1.0, baseline * 0.2),
        bootstrap_ci_lower=_bootstrap_lower(values, bootstrap_samples),
        permutation_p_value=_exact_sign_flip_p_value(values),
        gate_component=gate_component,
    )


def _mean(values: list[float]) -> float:
    return sum(values) / len(values) if values else 0.0


def _bootstrap_lower(values: list[float], samples: int) -> float:
    if not values:
        return 0.0
    rng = random.Random(0)
    means = sorted(sum(rng.choice(values) for _ in values) / len(values) for _ in range(samples))
    return means[max(0, int(samples * 0.025) - 1)]


def _exact_sign_flip_p_value(values: list[float]) -> float:
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
