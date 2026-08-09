from __future__ import annotations

import pytest

from redcell.budget import BudgetLimits
from redcell.protocols import (
    ArenaRunConfiguration,
    ControllerRunConfiguration,
    ExperimentConditions,
    GenerationMemoryConfiguration,
    GenerationMemoryLimits,
    GenerationMemoryMode,
    ProviderRunConfiguration,
    Run,
    SearchConfiguration,
    SearchSelector,
    StrategyCatalogue,
)
from redcell.strategies.library import PHASE_0_STRATEGIES


def _provider() -> ProviderRunConfiguration:
    return ProviderRunConfiguration(
        provider="scripted",
        base_url="https://example.invalid/v1",
        model="test-model",
        temperature=0.0,
        max_tokens=512,
        rpm=1,
        max_concurrency=1,
        input_usd_per_mtok=0,
        output_usd_per_mtok=0,
    )


def _conditions(**updates: object) -> ExperimentConditions:
    payload: dict[str, object] = {
        "online": False,
        "actor": "customer_a",
        "target": _provider(),
        "attacker": _provider(),
        "arena": ArenaRunConfiguration(
            defense="baseline", enforce_permissions=True, enforce_confirmation=False
        ),
        "search": SearchConfiguration(selector=SearchSelector.STATIC),
        "generation_memory": GenerationMemoryConfiguration(mode=GenerationMemoryMode.OFF),
    }
    payload.update(updates)
    return ExperimentConditions.model_validate(payload)


def _catalogue():
    return StrategyCatalogue(
        version="phase0.5-v1", strategies=list(PHASE_0_STRATEGIES)
    ).condition_summary()


def test_phase_0_5_requires_new_treatment_fields_and_catalogue() -> None:
    conditions = _conditions()
    with pytest.raises(ValueError, match="strategy_catalogue"):
        conditions.require_phase_0_5()


def test_llm_search_requires_controller_but_static_forbids_it() -> None:
    controller = ControllerRunConfiguration(
        provider=_provider(),
        connection_id="controller-test",
        connection_fingerprint="sha256:abc",
        prompt_version="controller-prompt-v1",
        evidence_policy_version="controller-evidence-v1",
        thinking_disabled=True,
    )
    static = _conditions(controller=controller, strategy_catalogue=_catalogue())
    with pytest.raises(ValueError, match="非 LLM"):
        static.require_phase_0_5()

    llm = _conditions(
        search=SearchConfiguration(selector=SearchSelector.LLM), strategy_catalogue=_catalogue()
    )
    with pytest.raises(ValueError, match="Controller"):
        llm.require_phase_0_5()


def test_memory_configuration_binds_limits_to_enabled_mode() -> None:
    with pytest.raises(ValueError, match="memory=off"):
        GenerationMemoryConfiguration(
            mode=GenerationMemoryMode.OFF,
            policy_version="bounded-relevant-v1",
        )
    with pytest.raises(ValueError, match="必须记录"):
        GenerationMemoryConfiguration(mode=GenerationMemoryMode.BOUNDED_RELEVANT_V1)

    enabled = GenerationMemoryConfiguration(
        mode=GenerationMemoryMode.BOUNDED_RELEVANT_V1,
        policy_version="bounded-relevant-v1",
        limits=GenerationMemoryLimits(),
    )
    assert enabled.limits.max_history_chars == 12000


def test_regression_context_ignores_treatment_but_complete_fingerprint_does_not() -> None:
    static = _conditions()
    llm = _conditions(
        search=SearchConfiguration(selector=SearchSelector.LLM),
        generation_memory=GenerationMemoryConfiguration(
            mode=GenerationMemoryMode.BOUNDED_RELEVANT_V1,
            policy_version="bounded-relevant-v1",
            limits=GenerationMemoryLimits(),
        ),
        controller=ControllerRunConfiguration(
            provider=_provider(),
            connection_id="controller-test",
            connection_fingerprint="sha256:abc",
            prompt_version="controller-prompt-v1",
            evidence_policy_version="controller-evidence-v1",
            thinking_disabled=True,
        ),
    )
    assert static.fingerprint() != llm.fingerprint()
    assert static.regression_context_fingerprint() == llm.regression_context_fingerprint()


def test_experiment_fingerprint_binds_scorer_and_identity_versions() -> None:
    baseline = _conditions()

    assert (
        baseline.fingerprint()
        != baseline.model_copy(update={"scorer_version": "level1-v-next"}).fingerprint()
    )
    assert (
        baseline.fingerprint()
        != baseline.model_copy(
            update={"finding_signature_version": "finding-signature-v-next"}
        ).fingerprint()
    )
    assert (
        baseline.fingerprint()
        != baseline.model_copy(
            update={"attack_path_signature_version": "attack-path-signature-v-next"}
        ).fingerprint()
    )


def test_gate_context_fingerprint_binds_budget_contract() -> None:
    run = Run(
        target_name="target",
        policy_version="policy-v1",
        adapter_type="arena",
        algorithm="static",
        limits=BudgetLimits(max_total_tokens=320000),
        experiment_conditions=_conditions(),
    )

    assert (
        run.gate_context_fingerprint()
        != run.model_copy(
            update={"limits": BudgetLimits(max_total_tokens=160000)}
        ).gate_context_fingerprint()
    )
