import hashlib

import pytest
from pydantic import ValidationError

from redcell.protocols import (
    ArenaRunConfiguration,
    ExperimentConditions,
    MutationOperator,
    PredictedStrength,
    ProviderRunConfiguration,
    Strategy,
    StrategyCatalogue,
    VulnerabilityCategory,
)


def _strategy(*, template: str = "Request the restricted tool.", max_turns: int = 3) -> Strategy:
    return Strategy(
        id="restricted_tool_request",
        name="Restricted tool request",
        description="Generic strategy-catalogue test fixture.",
        categories=[VulnerabilityCategory.UNAUTHORIZED_TOOL_USE],
        seed_template=template,
        mutation_operators=[MutationOperator.PARAPHRASE],
        max_turns=max_turns,
        predicted_rank=1,
        predicted_strength=PredictedStrength.MEDIUM,
    )


def _conditions(catalogue: StrategyCatalogue | None = None) -> ExperimentConditions:
    provider = ProviderRunConfiguration(
        provider="test",
        base_url="https://example.invalid/v1",
        model="test-model",
        temperature=0.7,
        max_tokens=128,
        rpm=0.0,
        max_concurrency=1,
        input_usd_per_mtok=0.0,
        output_usd_per_mtok=0.0,
    )
    return ExperimentConditions(
        online=False,
        actor="customer_a",
        target=provider,
        attacker=provider,
        arena=ArenaRunConfiguration(
            defense="standard", enforce_permissions=True, enforce_confirmation=True
        ),
        strategy_catalogue=catalogue.condition_summary() if catalogue else None,
    )


def test_catalogue_summary_uses_template_digest_and_keeps_order() -> None:
    strategy = _strategy()
    summary = StrategyCatalogue(version="phase0.5-v1", strategies=[strategy]).condition_summary()

    assert summary.version == "phase0.5-v1"
    assert summary.strategies[0].id == strategy.id
    assert (
        summary.strategies[0].template_sha256
        == hashlib.sha256(strategy.seed_template.encode("utf-8")).hexdigest()
    )
    assert "restricted tool" not in summary.model_dump_json()


def test_catalogue_semantic_changes_change_experiment_fingerprint() -> None:
    original = StrategyCatalogue(version="phase0.5-v1", strategies=[_strategy()])
    changed = StrategyCatalogue(version="phase0.5-v1", strategies=[_strategy(max_turns=2)])

    assert _conditions(original).fingerprint() != _conditions(changed).fingerprint()


def test_phase_zero_conditions_keep_legacy_payload_shape() -> None:
    conditions = _conditions()

    assert "strategy_catalogue" not in conditions.model_dump(mode="json", exclude_none=True)


def test_catalogue_rejects_duplicate_strategy_ids() -> None:
    with pytest.raises(ValidationError, match="重复 id"):
        StrategyCatalogue(version="phase0.5-v1", strategies=[_strategy(), _strategy()])
