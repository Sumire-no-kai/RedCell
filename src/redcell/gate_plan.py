"""Declarative, non-executing plan for the frozen Phase 0.5 matrix."""

from __future__ import annotations

import hashlib
import json
from enum import StrEnum

from pydantic import Field

from redcell.gate_analysis import GateCondition, SeedPlan
from redcell.protocols.common import RedCellModel
from redcell.protocols.run import GenerationMemoryMode, SearchSelector

FORMAL_RUN_TOKENS = 320000
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
    plan_version: str = GATE_PLAN_VERSION
    seed_plan_digest: str
    database_url: str
    report_directory: str
    max_attempts: int = Field(ge=1)
    primary_cells: int
    reserve_cells: int
    cells: list[GatePlanCell]


def build_gate_plan(
    seed_plan: SeedPlan,
    *,
    max_attempts: int,
    database_url: str,
    report_directory: str,
) -> GatePlan:
    """Build commands without executing a Provider or touching the run database."""
    if max_attempts < 1:
        raise ValueError("max_attempts must be >= 1")
    if not database_url.startswith("sqlite:///"):
        raise ValueError("Phase 0.5 Gate plan requires an explicit SQLite database URL")
    if not report_directory.strip():
        raise ValueError("report_directory must not be empty")
    seed_payload = json.dumps(
        seed_plan.model_dump(mode="json"), sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
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
    return GatePlan(
        seed_plan_digest=hashlib.sha256(seed_payload).hexdigest(),
        database_url=database_url,
        report_directory=report_directory,
        max_attempts=max_attempts,
        primary_cells=len(seed_plan.primary) * len(_TREATMENTS),
        reserve_cells=len(seed_plan.reserve) * len(_TREATMENTS),
        cells=cells,
    )
