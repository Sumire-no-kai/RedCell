from __future__ import annotations

from pathlib import Path

import pytest

from redcell.arena.support_agent import SUPPORT_AGENT_POLICY
from redcell.budget import BudgetLimits
from redcell.gate_analysis import GateCondition, SeedPlan, TokenPrefix, gate_condition_for
from redcell.gate_validation import select_validation_evidence
from redcell.protocols import (
    ArenaRunConfiguration,
    ControllerRunConfiguration,
    ExperimentConditions,
    GenerationMemoryConfiguration,
    GenerationMemoryLimits,
    GenerationMemoryMode,
    ProviderRunConfiguration,
    Run,
    RunStatus,
    SearchConfiguration,
    SearchSelector,
    StrategyCatalogue,
)
from redcell.strategies import PHASE_0_STRATEGIES
from redcell.versions import EXPERIMENT_CONDITIONS_SCHEMA_VERSION

FROZEN_PLAN = SeedPlan.model_validate_json(
    (Path(__file__).parents[1] / "docs" / "PHASE0_5_SEED_PLAN.json").read_text(encoding="utf-8")
)


def _provider(name: str) -> ProviderRunConfiguration:
    return ProviderRunConfiguration(
        provider=name,
        base_url=f"https://{name}.example.invalid/v1",
        model=f"{name}-model",
        temperature=0.7,
        max_tokens=512,
        rpm=60,
        max_concurrency=1,
        input_usd_per_mtok=0,
        output_usd_per_mtok=0,
    )


def _run(seed: int, condition: GateCondition) -> Run:
    selector, memory_mode = {
        GateCondition.STATIC_OFF: (SearchSelector.STATIC, GenerationMemoryMode.OFF),
        GateCondition.STATIC_MEMORY: (
            SearchSelector.STATIC,
            GenerationMemoryMode.BOUNDED_RELEVANT_V1,
        ),
        GateCondition.LLM_MEMORY: (
            SearchSelector.LLM,
            GenerationMemoryMode.BOUNDED_RELEVANT_V1,
        ),
        GateCondition.LLM_OFF: (SearchSelector.LLM, GenerationMemoryMode.OFF),
        GateCondition.RANDOM_OFF: (SearchSelector.RANDOM, GenerationMemoryMode.OFF),
        GateCondition.THOMPSON_OFF: (SearchSelector.THOMPSON, GenerationMemoryMode.OFF),
    }[condition]
    memory = (
        GenerationMemoryConfiguration(mode=GenerationMemoryMode.OFF)
        if memory_mode is GenerationMemoryMode.OFF
        else GenerationMemoryConfiguration(
            mode=memory_mode,
            policy_version="bounded-relevant-v1",
            limits=GenerationMemoryLimits(),
        )
    )
    controller = (
        ControllerRunConfiguration(
            provider=_provider("controller"),
            connection_id="controller:test",
            connection_fingerprint="https://controller.example.invalid/v1",
            prompt_version="controller-prompt-v1",
            evidence_policy_version="controller-evidence-v1",
            thinking_disabled=False,
        )
        if selector is SearchSelector.LLM
        else None
    )
    conditions = ExperimentConditions(
        online=True,
        actor="customer_a",
        target=_provider("target"),
        attacker=_provider("attacker"),
        arena=ArenaRunConfiguration(
            defense="standard",
            enforce_permissions=True,
            enforce_confirmation=True,
        ),
        strategy_catalogue=StrategyCatalogue(
            version="phase0.5-v1", strategies=list(PHASE_0_STRATEGIES)
        ).condition_summary(),
        search=SearchConfiguration(selector=selector),
        generation_memory=memory,
        controller=controller,
        # Gate 只采信摘要可重算证实的 Run;正式 Run 一律由 CLI 带上 schema 版本。
        conditions_schema_version=EXPERIMENT_CONDITIONS_SCHEMA_VERSION,
    )
    return Run(
        id=f"run-{seed}-{condition.value}",
        target_name=SUPPORT_AGENT_POLICY.target_name,
        policy_version=SUPPORT_AGENT_POLICY.version,
        adapter_type="arena/support-agent",
        algorithm=selector.value,
        limits=BudgetLimits(max_attempts=500, max_total_tokens=320000),
        seed=seed,
        status=RunStatus.COMPLETED,
        experiment_conditions=conditions,
    )


class _Store:
    def __init__(self, runs: list[Run]) -> None:
        self.runs = runs

    def list_runs(self) -> list[Run]:
        return self.runs

    def events_for(self, _run_id: str) -> list:
        return []

    def findings_for(self, _run_id: str) -> list:
        return []

    def attempts_for(self, _run_id: str) -> list:
        return []


def _prefixes(*, run: Run, events: list, findings: list, checkpoints: tuple[int, ...]):
    del events, findings
    assert run.experiment_conditions is not None
    assert run.experiment_conditions.search is not None
    assert run.experiment_conditions.generation_memory is not None
    condition = gate_condition_for(
        run.experiment_conditions.search.selector.value,
        run.experiment_conditions.generation_memory.mode.value,
    )
    return [
        TokenPrefix(
            run_id=run.id,
            seed=run.seed or 0,
            condition=condition,
            checkpoint_tokens=checkpoint,
            committed_tokens=checkpoint,
            checkpoint_reached=True,
            valid=True,
        )
        for checkpoint in checkpoints
    ]


def test_validation_selects_exactly_the_twelve_valid_paired_blocks(monkeypatch) -> None:
    runs = [_run(seed, condition) for seed in FROZEN_PLAN.primary for condition in GateCondition]
    monkeypatch.setattr("redcell.gate_validation.token_prefixes_from_events", _prefixes)

    evidence = select_validation_evidence(
        _Store(runs),  # type: ignore[arg-type]
        FROZEN_PLAN,
    )

    assert len(evidence.runs) == 72
    assert evidence.attempts == []
    assert evidence.findings == []


def test_validation_refuses_an_unregistered_seed(monkeypatch) -> None:
    runs = [_run(seed, condition) for seed in FROZEN_PLAN.primary for condition in GateCondition]
    runs.extend(_run(99, condition) for condition in GateCondition)
    monkeypatch.setattr("redcell.gate_validation.token_prefixes_from_events", _prefixes)

    with pytest.raises(ValueError, match="outside the frozen seed plan"):
        select_validation_evidence(
            _Store(runs),  # type: ignore[arg-type]
            FROZEN_PLAN,
        )
