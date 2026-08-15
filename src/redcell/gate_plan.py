"""Declarative, non-executing plan for the frozen Phase 0.5 matrix."""

from __future__ import annotations

from enum import StrEnum
from typing import Literal

from pydantic import Field, model_validator

from redcell.gate_analysis import (
    FORMAL_MAX_ATTEMPTS,
    FORMAL_RUN_TOKENS,
    FROZEN_SEED_PLANS,
    GateCondition,
    SeedPlan,
    require_frozen_seed_plan,
    seed_plan_digest,
)
from redcell.protocols.common import RedCellModel
from redcell.protocols.run import GenerationMemoryMode, SearchSelector

GATE_PLAN_VERSION = "phase-0.5-gate-plan-v1"


class SeedRole(StrEnum):
    PRIMARY = "primary"
    RESERVE = "reserve"


_TREATMENTS: tuple[tuple[GateCondition, SearchSelector, GenerationMemoryMode], ...] = (
    (GateCondition.STATIC_OFF, SearchSelector.STATIC, GenerationMemoryMode.OFF),
    (
        GateCondition.STATIC_MEMORY,
        SearchSelector.STATIC,
        GenerationMemoryMode.BOUNDED_RELEVANT_V1,
    ),
    (
        GateCondition.LLM_MEMORY,
        SearchSelector.LLM,
        GenerationMemoryMode.BOUNDED_RELEVANT_V1,
    ),
    (GateCondition.LLM_OFF, SearchSelector.LLM, GenerationMemoryMode.OFF),
    (GateCondition.RANDOM_OFF, SearchSelector.RANDOM, GenerationMemoryMode.OFF),
    (GateCondition.THOMPSON_OFF, SearchSelector.THOMPSON, GenerationMemoryMode.OFF),
)


class GatePlanCell(RedCellModel):
    seed: int
    seed_role: SeedRole
    enabled_initially: bool
    condition: GateCondition
    search: SearchSelector
    cross_attempt_memory: GenerationMemoryMode
    max_attempts: int = Field(ge=1)
    max_total_tokens: int = FORMAL_RUN_TOKENS
    argv: list[str]


class GatePlan(RedCellModel):
    plan_version: Literal["phase-0.5-gate-plan-v1"] = GATE_PLAN_VERSION
    seed_plan_digest: str
    database_url: str
    report_directory: str
    max_attempts: int = Field(ge=1)
    primary_cells: int
    reserve_cells: int
    cells: list[GatePlanCell]

    @model_validator(mode="after")
    def matches_registered_matrix(self) -> GatePlan:
        """Reject a drifted/tampered execution plan before any paid child can start."""
        if self.max_attempts != FORMAL_MAX_ATTEMPTS:
            raise ValueError(f"Phase 0.5 Gate max_attempts must be {FORMAL_MAX_ATTEMPTS}")
        if not self.database_url.startswith("sqlite:///"):
            raise ValueError("Phase 0.5 Gate plan requires an explicit SQLite database URL")
        if not self.report_directory.strip():
            raise ValueError("report_directory must not be empty")
        frozen = next(
            (item for item in FROZEN_SEED_PLANS.values() if item.digest == self.seed_plan_digest),
            None,
        )
        if frozen is None:
            raise ValueError("Gate plan seed digest is not registered")
        primary = list(
            dict.fromkeys(cell.seed for cell in self.cells if cell.seed_role is SeedRole.PRIMARY)
        )
        reserve = list(
            dict.fromkeys(cell.seed for cell in self.cells if cell.seed_role is SeedRole.RESERVE)
        )
        seed_plan = SeedPlan(experiment=frozen.experiment, primary=primary, reserve=reserve)
        require_frozen_seed_plan(seed_plan)
        expected = _build_cells(
            seed_plan,
            max_attempts=self.max_attempts,
            database_url=self.database_url,
            report_directory=self.report_directory,
        )
        if self.primary_cells != len(primary) * len(_TREATMENTS):
            raise ValueError("Gate plan primary_cells does not match its frozen allocation")
        if self.reserve_cells != len(reserve) * len(_TREATMENTS):
            raise ValueError("Gate plan reserve_cells does not match its frozen allocation")
        if self.cells != expected:
            raise ValueError("Gate plan cells/argv do not match the canonical frozen matrix")
        return self


def _build_cells(
    seed_plan: SeedPlan,
    *,
    max_attempts: int,
    database_url: str,
    report_directory: str,
) -> list[GatePlanCell]:
    cells: list[GatePlanCell] = []
    for role, seeds in (
        (SeedRole.PRIMARY, seed_plan.primary),
        (SeedRole.RESERVE, seed_plan.reserve),
    ):
        for seed in seeds:
            for condition, search, memory in _TREATMENTS:
                argv = [
                    "redcell",
                    "run",
                    "--online",
                    "--search",
                    search.value,
                    "--cross-attempt-memory",
                    memory.value,
                    "--budget",
                    str(max_attempts),
                    "--max-tokens",
                    str(FORMAL_RUN_TOKENS),
                    "--seed",
                    str(seed),
                    "--db",
                    database_url,
                    "--out",
                    report_directory,
                ]
                cells.append(
                    GatePlanCell(
                        seed=seed,
                        seed_role=role,
                        enabled_initially=role is SeedRole.PRIMARY,
                        condition=condition,
                        search=search,
                        cross_attempt_memory=memory,
                        max_attempts=max_attempts,
                        argv=argv,
                    )
                )
    return cells


def build_gate_plan(
    seed_plan: SeedPlan,
    *,
    max_attempts: int,
    database_url: str,
    report_directory: str,
) -> GatePlan:
    """Build commands without executing a Provider or touching the run database."""
    if max_attempts != FORMAL_MAX_ATTEMPTS:
        raise ValueError(f"Phase 0.5 Gate max_attempts must be {FORMAL_MAX_ATTEMPTS}")
    require_frozen_seed_plan(seed_plan)
    if not database_url.startswith("sqlite:///"):
        raise ValueError("Phase 0.5 Gate plan requires an explicit SQLite database URL")
    if not report_directory.strip():
        raise ValueError("report_directory must not be empty")
    cells = _build_cells(
        seed_plan,
        max_attempts=max_attempts,
        database_url=database_url,
        report_directory=report_directory,
    )
    return GatePlan(
        seed_plan_digest=seed_plan_digest(seed_plan),
        database_url=database_url,
        report_directory=report_directory,
        max_attempts=max_attempts,
        primary_cells=len(seed_plan.primary) * len(_TREATMENTS),
        reserve_cells=len(seed_plan.reserve) * len(_TREATMENTS),
        cells=cells,
    )
