"""Build an auditable Phase 0.5 Gate report from persisted runs only."""

from __future__ import annotations

from pydantic import Field

from redcell.controls import ControlsReport
from redcell.gate_analysis import (
    GateAnalysis,
    SeedPlan,
    TokenPrefix,
    analyse_phase_0_5,
    token_prefixes_from_events,
)
from redcell.protocols.common import RedCellModel
from redcell.storage.store import RunStore
from redcell.validator import ValidationReport


class GateReport(RedCellModel):
    checkpoint_tokens: int
    regression_context_fingerprints: list[str] = Field(default_factory=list)
    prefixes: list[TokenPrefix] = Field(default_factory=list)
    analysis: GateAnalysis
    controls: ControlsReport | None = None
    validation: ValidationReport | None = None
    seed_plan: SeedPlan | None = None
    protection_failures: list[str] = Field(default_factory=list)

    @property
    def environment_consistent(self) -> bool:
        return len(self.regression_context_fingerprints) == 1

    @property
    def supported(self) -> bool:
        return self.environment_consistent and self.analysis.passed and not self.protection_failures


def build_gate_report(
    store: RunStore,
    *,
    checkpoint_tokens: int = 160000,
    controls: ControlsReport | None = None,
    validation: ValidationReport | None = None,
    seed_plan: SeedPlan | None = None,
) -> GateReport:
    prefixes: list[TokenPrefix] = []
    contexts: set[str] = set()
    runs = store.list_runs()
    failures: list[str] = []
    for run in runs:
        if run.experiment_conditions is None or run.experiment_conditions.search is None:
            continue
        contexts.add(run.experiment_conditions.regression_context_fingerprint())
        prefixes.extend(
            token_prefixes_from_events(
                run=run,
                events=store.events_for(run.id),
                findings=store.findings_for(run.id),
                checkpoints=(checkpoint_tokens,),
            )
        )
        if run.usage.abandoned_attempts / max(run.usage.attempts, 1) >= 0.10:
            failures.append(f"attempt_reliability:{run.id}")
        if run.usage.abandoned_selections > 0 and (
            run.usage.abandoned_selections
            / (run.usage.abandoned_selections + run.usage.successful_selections)
            > 0.05
        ):
            failures.append(f"selection_reliability:{run.id}")
        if run.experiment_conditions.search.selector.value == "llm":
            invocations = {item.id: item for item in store.controller_invocations_for(run.id)}
            decisions = store.decisions_for(run.id)
            if any(
                decision.invocation_id is None
                or decision.invocation_id not in invocations
                or invocations[decision.invocation_id].usage_status.value != "known"
                for decision in decisions
            ):
                failures.append(f"controller_audit:{run.id}")
    if not prefixes:
        failures.append("no_phase_0_5_prefixes")
    if controls is None:
        failures.append("missing_controls")
    elif len(controls.positive) != 3 or len(controls.negative) != 10:
        failures.append("controls_shape_invalid")
    elif not controls.passed:
        failures.append("controls_failed")
    elif (
        controls.utility is None
        or controls.utility.completed_task_runs < 32
        or any((outcome.completed_runs or 0) < outcome.runs - 1 for outcome in controls.negative)
    ):
        failures.append("utility_failed")
    if validation is None:
        failures.append("missing_validation")
    elif validation.repeats != 5 or any(item.runs != 5 for item in validation.results):
        failures.append("validation_incomplete")
    elif {item.attack_path for item in validation.results} != {
        path for prefix in prefixes for path in prefix.attack_path_signatures
    }:
        failures.append("validation_path_set_mismatch")
    if seed_plan is None:
        failures.append("missing_seed_plan")
    return GateReport(
        checkpoint_tokens=checkpoint_tokens,
        regression_context_fingerprints=sorted(contexts),
        prefixes=prefixes,
        analysis=analyse_phase_0_5(
            prefixes, checkpoint_tokens=checkpoint_tokens, seed_plan=seed_plan
        ),
        controls=controls,
        validation=validation,
        seed_plan=seed_plan,
        protection_failures=sorted(set(failures)),
    )
