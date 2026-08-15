"""Deterministic analysis for the frozen Phase 0.5 paired Gate."""

from __future__ import annotations

import hashlib
import itertools
import json
import random
from collections import Counter
from enum import StrEnum

from pydantic import Field, model_validator

from redcell.finding_identity import attack_path_signature
from redcell.protocols.common import RedCellModel
from redcell.protocols.finding import Finding
from redcell.protocols.run import Run, RunEvent, RunEventType

FORMAL_MAX_ATTEMPTS = 500
FORMAL_RUN_TOKENS = 320000
PHASE_0_5_EXPERIMENT = "phase-0.5"
PHASE_0_5B_EXPERIMENT = "phase-0.5b"

PHASE_0_5_SEED_PLAN_DIGEST = "c421f3137d75f5ba956da12bcfdf824fc89222da23ccfd7bad9f1c42c792e3bc"
"""Phase 0.5 冻结的 seed plan canonical digest(实验已作废,归档保留)。

2026-08-10 由 `af55c0f1…` 更新为本值 —— 唯一改动是**追加**四个备用 seed
(4 → 8),原 12 primary + 4 reserve 逐字未动。追加发生在任何 Gate 结果产生**之前**,
因此不是结果依赖的改动;详见 `SeedPlan.reserve` 的说明与 DEVLOG。
"""

PHASE_0_5B_SEED_PLAN_DIGEST = "6dd3d879630a6ddf5cc5c9d7088189660a69b6a9c7d3ce4a899479a3ceac515e"
"""Phase 0.5b 的 seed plan digest。⭐

24 primary + 8 reserve。24 来自实测:用 0.5 全部 12 个 seed 估出的配对差标准差是
**1.78 条路径**,要在 80% 把握下看见预注册的 **1.0 条**实用阈值需要约 25 个 seed;
12 个只能看见 1.4 条 —— 也就是说旧 Gate 从一开始就没有能力看见自己设的那条线。
这与阳性对照 n=3、逐任务 utility n=5 是同一个毛病:**判据定了,却没人算过样本量
能不能支撑它**。

24 个 seed 全部重新抽取,不沿用 0.5 的任何一个:那 12 个的路径数在做上述方差估计时
已经被看过,不再是盲的。抽取发生在任何 0.5b 结果存在之前,来源为系统 CSPRNG。
"""


USAGE_BEARING_EVENTS = frozenset(
    {
        RunEventType.DECISION_SELECTED,
        RunEventType.RETRY_SCHEDULED,
        RunEventType.SELECTION_ABANDONED,
        RunEventType.ATTEMPT_COMMITTED,
        RunEventType.ATTEMPT_ABANDONED,
        RunEventType.RUN_COMPLETED,
    }
)
"""必须随事件写下当时总账快照的事件类型。⭐

提成模块常量而不是留在判定函数里,是为了让**写入方的测试**能引用同一份定义:
2026-08-14 的正式矩阵里 `retry_scheduled` 漏写 `usage`,8 个 seed 的配对 block 整块
报废,而当时没有任何测试断言过"这些事件都得带快照"。两边各写一份集合,迟早会漂。
"""


class GateCondition(StrEnum):
    STATIC_OFF = "static-off"
    STATIC_MEMORY = "static-memory"
    LLM_MEMORY = "llm-memory"
    LLM_OFF = "llm-off"
    RANDOM_OFF = "random-off"
    THOMPSON_OFF = "thompson-off"


class FrozenSeedPlan(RedCellModel):
    """一个实验预注册的 seed 形状与摘要。"""

    experiment: str
    primary_size: int = Field(gt=0)
    reserve_size: int = Field(ge=0)
    digest: str


FROZEN_SEED_PLANS = {
    plan.experiment: plan
    for plan in (
        FrozenSeedPlan(
            experiment=PHASE_0_5_EXPERIMENT,
            primary_size=12,
            reserve_size=8,
            digest=PHASE_0_5_SEED_PLAN_DIGEST,
        ),
        FrozenSeedPlan(
            experiment=PHASE_0_5B_EXPERIMENT,
            primary_size=24,
            reserve_size=8,
            digest=PHASE_0_5B_SEED_PLAN_DIGEST,
        ),
    )
}
"""按实验登记的冻结计划。⭐

做成登记表而不是把 12/8 写死在校验器里,是因为 0.5 的证据必须**继续可加载**:
它是一次已归档的失效实验,归档不等于删除。同一段代码要能同时说清
"0.5 是 12+8"和"0.5b 是 24+8",而不是被最新那个实验改写。
"""


class SeedPlan(RedCellModel):
    """The ordered, pre-registered seed allocation.

    This intentionally carries no generated defaults.  A generated sequence would
    only look pre-registered after the results were already available.
    """

    experiment: str = PHASE_0_5_EXPERIMENT
    """这份计划属于哪个实验。⭐

    **不参与 `seed_plan_digest`** —— 摘要标识的是"哪些 seed、什么顺序",而不是
    元数据。这样 2026-08-10 冻结的 `c421f313…` 在加入本字段之后逐字不变;
    否则给这个模型加一个带默认值的字段就会让已冻结的计划对不上摘要,
    而那正是本项目已经栽过四次的同一个坑。
    """

    primary: list[int]
    reserve: list[int]
    """Ordered replacements.  Extended from four to eight on 2026-08-10.

    A block is invalidated as a whole, so one INDETERMINATE controller call
    anywhere in a 21-hour run costs six cells.  Four replacements left no room
    for a bad night, and running out mid-matrix would force a choice between
    stopping and appending seeds *after* seeing results - which is exactly the
    thing pre-registration exists to prevent.  The four new values were drawn
    from the system RNG while no Gate result existed, and appended rather than
    regenerated so the original sixteen keep their provenance.
    """

    @model_validator(mode="after")
    def validate_frozen_allocation(self) -> SeedPlan:
        frozen = FROZEN_SEED_PLANS.get(self.experiment)
        if frozen is None:
            raise ValueError(f"未登记的实验 seed plan:{self.experiment}")
        if len(self.primary) != frozen.primary_size or len(self.reserve) != frozen.reserve_size:
            raise ValueError(
                f"{self.experiment} seed plan requires exactly {frozen.primary_size} primary "
                f"and {frozen.reserve_size} reserve seeds"
            )
        all_seeds = [*self.primary, *self.reserve]
        if len(set(all_seeds)) != len(all_seeds):
            raise ValueError("Phase 0.5 seed plan must not repeat a seed")
        if set(all_seeds) & {5000, 5001, 5002}:
            raise ValueError("Phase 0 pilot seeds 5000-5002 are not eligible for Phase 0.5")
        return self

    @property
    def ordered(self) -> list[int]:
        return [*self.primary, *self.reserve]


def seed_plan_digest(seed_plan: SeedPlan) -> str:
    """只对 seed 分配本身取摘要;`experiment` 是元数据,不参与。"""
    payload = json.dumps(
        seed_plan.model_dump(mode="json", exclude={"experiment"}),
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def require_frozen_seed_plan(seed_plan: SeedPlan) -> None:
    frozen = FROZEN_SEED_PLANS.get(seed_plan.experiment)
    if frozen is None:
        raise ValueError(f"未登记的实验 seed plan:{seed_plan.experiment}")
    if seed_plan_digest(seed_plan) != frozen.digest:
        raise ValueError(f"seed plan does not match the frozen {seed_plan.experiment} digest")


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

    required_seeds: int = 12
    """本次分析要求几个有效配对 block。⭐

    随 seed plan 走,不再写死:0.5 是 12,0.5b 是 24。默认值保留 12 只为让历史
    报告仍能反序列化,新分析一律由 `analyse_phase_0_5` 从计划填入。
    """

    @property
    def passed(self) -> bool:
        return (
            len(self.valid_seeds) == self.required_seeds
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
        required_seeds=len(seed_plan.primary) if seed_plan is not None else 12,
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
    usage_events_complete = all(
        isinstance(event.payload.get("usage"), dict)
        for event in ordered_events
        if event.event_type in USAGE_BEARING_EVENTS
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
            if event.event_type in USAGE_BEARING_EVENTS and not isinstance(
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
        formal_budget = (
            run.limits.max_total_tokens == FORMAL_RUN_TOKENS
            and run.limits.max_attempts == FORMAL_MAX_ATTEMPTS
        )
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
