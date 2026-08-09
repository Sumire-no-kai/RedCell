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

    @property
    def environment_consistent(self) -> bool:
        return len(self.regression_context_fingerprints) == 1

    @property
    def supported(self) -> bool:
        return self.environment_consistent and self.analysis.passed


def build_gate_report(store: RunStore, *, checkpoint_tokens: int = 160000) -> GateReport:
    prefixes: list[TokenPrefix] = []
    contexts: set[str] = set()
    for run in store.list_runs():
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
    return GateReport(
        checkpoint_tokens=checkpoint_tokens,
        regression_context_fingerprints=sorted(contexts),
        prefixes=prefixes,
        analysis=analyse_phase_0_5(prefixes, checkpoint_tokens=checkpoint_tokens),
    )
