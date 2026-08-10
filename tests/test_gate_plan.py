from __future__ import annotations

from pathlib import Path

import pytest

from redcell.gate_analysis import (
    PHASE_0_5_SEED_PLAN_DIGEST,
    SeedPlan,
    seed_plan_digest,
)
from redcell.gate_plan import build_gate_plan

SEED_PLAN_PATH = Path(__file__).parents[1] / "docs" / "PHASE0_5_SEED_PLAN.json"


def test_versioned_seed_plan_matches_the_frozen_digest() -> None:
    seed_plan = SeedPlan.model_validate_json(SEED_PLAN_PATH.read_text(encoding="utf-8"))

    assert seed_plan_digest(seed_plan) == PHASE_0_5_SEED_PLAN_DIGEST
    assert not set(seed_plan.ordered) & {5000, 5001, 5002}


def test_gate_plan_freezes_500_attempts_and_disables_reserves() -> None:
    seed_plan = SeedPlan.model_validate_json(SEED_PLAN_PATH.read_text(encoding="utf-8"))

    plan = build_gate_plan(
        seed_plan,
        max_attempts=500,
        database_url="sqlite:///runs/phase-0-5.db",
        report_directory="runs/phase-0-5",
    )

    assert len(plan.cells) == 96
    assert all(cell.enabled_initially for cell in plan.cells[:72])
    assert not any(cell.enabled_initially for cell in plan.cells[72:])


def test_gate_plan_refuses_a_different_attempt_cap_or_seed_plan() -> None:
    seed_plan = SeedPlan.model_validate_json(SEED_PLAN_PATH.read_text(encoding="utf-8"))

    with pytest.raises(ValueError, match="max_attempts must be 500"):
        build_gate_plan(
            seed_plan,
            max_attempts=499,
            database_url="sqlite:///runs/phase-0-5.db",
            report_directory="runs/phase-0-5",
        )
    with pytest.raises(ValueError, match="canonical digest"):
        build_gate_plan(
            SeedPlan(primary=list(range(1, 13)), reserve=list(range(13, 17))),
            max_attempts=500,
            database_url="sqlite:///runs/phase-0-5.db",
            report_directory="runs/phase-0-5",
        )
