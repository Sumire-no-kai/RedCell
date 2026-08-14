"""Fail-closed selection of the exact formal paths that require replay."""

from __future__ import annotations

from dataclasses import dataclass

from redcell.finding_identity import attack_path_signature
from redcell.gate_analysis import (
    FORMAL_RUN_TOKENS,
    SeedPlan,
    TokenPrefix,
    analyse_phase_0_5,
    require_frozen_seed_plan,
    token_prefixes_from_events,
)
from redcell.protocols.finding import Finding
from redcell.protocols.run import Run
from redcell.protocols.trace import Attempt
from redcell.storage import RunStore

PRIMARY_CHECKPOINT = 160000


@dataclass(frozen=True)
class ValidationEvidence:
    runs: list[Run]
    attempts: list[Attempt]
    findings: list[Finding]


def select_validation_evidence(store: RunStore, seed_plan: SeedPlan) -> ValidationEvidence:
    """Select the 320k paths from the same twelve valid paired blocks as the Gate."""
    require_frozen_seed_plan(seed_plan)
    runs = [run for run in store.list_runs() if _is_phase_0_5_run(run)]
    prefixes: list[TokenPrefix] = []
    runs_by_id = {run.id: run for run in runs}
    for run in runs:
        prefixes.extend(
            token_prefixes_from_events(
                run=run,
                events=store.events_for(run.id),
                findings=store.findings_for(run.id),
                checkpoints=(PRIMARY_CHECKPOINT, FORMAL_RUN_TOKENS),
            )
        )
    analysis = analyse_phase_0_5(
        prefixes,
        checkpoint_tokens=PRIMARY_CHECKPOINT,
        seed_plan=seed_plan,
    )
    if len(analysis.valid_seeds) != 12:
        raise ValueError("replay validation requires exactly 12 valid paired seed blocks")
    if analysis.duplicate_cells:
        raise ValueError("replay validation refuses duplicate seed-condition cells")
    if analysis.unregistered_seeds:
        raise ValueError("replay validation refuses runs outside the frozen seed plan")

    selected = [
        prefix
        for prefix in prefixes
        if prefix.checkpoint_tokens == FORMAL_RUN_TOKENS
        and prefix.seed in set(analysis.valid_seeds)
        and prefix.valid
    ]
    if len(selected) != 12 * 6:
        raise ValueError("replay validation requires all 72 valid 320k cells")
    selected_keys = {(prefix.seed, prefix.condition) for prefix in selected}
    if len(selected_keys) != len(selected):
        raise ValueError("replay validation found duplicate 320k cells")

    selected_runs = [runs_by_id[prefix.run_id] for prefix in selected]
    if len({run.gate_context_fingerprint() for run in selected_runs}) != 1:
        raise ValueError("replay validation refuses mixed Gate contexts")

    attempts: list[Attempt] = []
    findings: list[Finding] = []
    for prefix in selected:
        run_findings = [
            finding
            for finding in store.findings_for(prefix.run_id)
            if attack_path_signature(finding) in prefix.attack_path_signatures
        ]
        finding_attempt_ids = {finding.attempt_id for finding in run_findings}
        attempts.extend(
            attempt
            for attempt in store.attempts_for(prefix.run_id)
            if attempt.id in finding_attempt_ids
        )
        findings.extend(run_findings)
    return ValidationEvidence(runs=selected_runs, attempts=attempts, findings=findings)


def _is_phase_0_5_run(run: Run) -> bool:
    """与 `gate_report` 同一条判据 —— 两处必须一致,否则报告和复核会看到不同的 Run 集。"""
    return run.has_verified_phase_0_5_conditions
