"""Build an auditable Phase 0.5 Gate report from persisted runs only."""

from __future__ import annotations

from pydantic import Field

from redcell.gate_analysis import (
    GateAnalysis,
    TokenPrefix,
    analyse_phase_0_5,
    token_prefixes_from_events,
)
from redcell.protocols.common import RedCellModel
from redcell.storage.store import RunStore


class GateReport(RedCellModel):
    checkpoint_tokens: int
    regression_context_fingerprints: list[str] = Field(default_factory=list)
    prefixes: list[TokenPrefix] = Field(default_factory=list)
    analysis: GateAnalysis
    protection_failures: list[str] = Field(default_factory=list)

    @property
    def environment_consistent(self) -> bool:
        return len(self.regression_context_fingerprints) == 1

    @property
    def supported(self) -> bool:
        return self.environment_consistent and self.analysis.passed and not self.protection_failures


def build_gate_report(store: RunStore, *, checkpoint_tokens: int = 160000) -> GateReport:
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
    return GateReport(
        checkpoint_tokens=checkpoint_tokens,
        regression_context_fingerprints=sorted(contexts),
        prefixes=prefixes,
        analysis=analyse_phase_0_5(prefixes, checkpoint_tokens=checkpoint_tokens),
        protection_failures=sorted(set(failures)),
    )
