from __future__ import annotations

import hashlib
import json

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
    UsageAccountingMode,
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
        usage_accounting_mode=UsageAccountingMode.PROMPT_COMPLETION_V1,
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


def test_phase_0_5_requires_explicit_usage_accounting_modes() -> None:
    conditions = _conditions(strategy_catalogue=_catalogue())
    incomplete = conditions.model_copy(
        update={"attacker": conditions.attacker.model_copy(update={"usage_accounting_mode": None})}
    )

    with pytest.raises(ValueError, match="usage_accounting_mode"):
        incomplete.require_phase_0_5()


def test_online_phase_0_5_requires_billed_token_coverage_before_execution() -> None:
    conditions = _conditions(online=True, strategy_catalogue=_catalogue())

    with pytest.raises(ValueError, match="usage 覆盖全部计费 Token"):
        conditions.require_phase_0_5()

    covered = conditions.model_copy(
        update={
            "target": conditions.target.model_copy(update={"usage_covers_billed_tokens": True}),
            "attacker": conditions.attacker.model_copy(update={"usage_covers_billed_tokens": True}),
        }
    )

    covered.require_phase_0_5()

    uncovered_controller = ControllerRunConfiguration(
        provider=_provider(),
        connection_id="controller-test",
        connection_fingerprint="sha256:abc",
        prompt_version="controller-prompt-v1",
        evidence_policy_version="controller-evidence-v1",
        thinking_disabled=False,
    )
    llm = covered.model_copy(
        update={
            "search": SearchConfiguration(selector=SearchSelector.LLM),
            "controller": uncovered_controller,
        }
    )
    with pytest.raises(ValueError, match="usage 覆盖全部计费 Token"):
        llm.require_phase_0_5()

    llm.model_copy(
        update={
            "controller": uncovered_controller.model_copy(
                update={
                    "provider": uncovered_controller.provider.model_copy(
                        update={"usage_covers_billed_tokens": True}
                    )
                }
            )
        }
    ).require_phase_0_5()


def test_llm_search_requires_controller_but_static_forbids_it() -> None:
    controller = ControllerRunConfiguration(
        provider=_provider(),
        connection_id="controller-test",
        connection_fingerprint="sha256:abc",
        prompt_version="controller-prompt-v1",
        evidence_policy_version="controller-evidence-v1",
        thinking_disabled=False,
    )
    static = _conditions(controller=controller, strategy_catalogue=_catalogue())
    with pytest.raises(ValueError, match="非 LLM"):
        static.require_phase_0_5()

    llm = _conditions(
        search=SearchConfiguration(selector=SearchSelector.LLM), strategy_catalogue=_catalogue()
    )
    with pytest.raises(ValueError, match="Controller"):
        llm.require_phase_0_5()


def test_controller_thinking_snapshot_must_match_provider_payload() -> None:
    with pytest.raises(ValueError, match="thinking_disabled"):
        ControllerRunConfiguration(
            provider=_provider(),
            connection_id="controller-test",
            connection_fingerprint="sha256:abc",
            prompt_version="controller-prompt-v1",
            evidence_policy_version="controller-evidence-v1",
            thinking_disabled=True,
        )


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
            provider=_provider().model_copy(
                update={"usage_accounting_mode": UsageAccountingMode.TOTAL_MINUS_PROMPT_V1}
            ),
            connection_id="controller-test",
            connection_fingerprint="sha256:abc",
            prompt_version="controller-prompt-v1",
            evidence_policy_version="controller-evidence-v1",
            thinking_disabled=False,
        ),
    )
    assert static.fingerprint() != llm.fingerprint()
    assert static.regression_context_fingerprint() == llm.regression_context_fingerprint()


def test_regression_context_omits_optional_legacy_provider_fields() -> None:
    legacy_provider = _provider().model_copy(update={"usage_accounting_mode": None})
    conditions = _conditions(target=legacy_provider, attacker=legacy_provider)
    payload = {
        "version": "regression-context-v1",
        "online": conditions.online,
        "actor": conditions.actor,
        "target": conditions.target.model_dump(mode="json", exclude_none=True),
        "attacker": conditions.attacker.model_dump(mode="json", exclude_none=True),
        "arena": conditions.arena.model_dump(mode="json"),
        "strategy_catalogue": None,
        "scorer_version": conditions.scorer_version,
        "finding_signature_version": conditions.finding_signature_version,
        "attack_path_signature_version": conditions.attack_path_signature_version,
    }
    expected = hashlib.sha256(
        json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode(
            "utf-8"
        )
    ).hexdigest()

    assert conditions.regression_context_fingerprint() == expected


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
        limits=BudgetLimits(max_attempts=500, max_total_tokens=320000),
        experiment_conditions=_conditions(),
    )

    assert (
        run.gate_context_fingerprint()
        != run.model_copy(
            update={"limits": BudgetLimits(max_total_tokens=160000)}
        ).gate_context_fingerprint()
    )


# ── Phase 0 冻结基线的历史形状 ────────────────────────────────────────────

PHASE_0_BASELINE_FINGERPRINT = "a0f8d19098c605b1a373b5e95557252f2cb6a6210f6fc1d59629626c9828b924"
"""`docs/PHASE0_BASELINE.md` 记录的 2026-08-06 消融矩阵指纹（18 个 run 全部一致）。"""

PHASE_0_BASELINE_CONDITIONS: dict[str, object] = {
    "online": True,
    "actor": "customer_a",
    "target": {
        "provider": "glm",
        "base_url": "https://api.z.ai/api/paas/v4",
        "model": "glm-4.7-flashx",
        "temperature": 0.7,
        "max_tokens": 512,
        "rpm": 0.0,
        "max_concurrency": 3,
        "input_usd_per_mtok": 0.07,
        "output_usd_per_mtok": 0.4,
        "extra_body": {"thinking": {"type": "disabled"}},
    },
    "attacker": {
        "provider": "gemini",
        "base_url": "https://generativelanguage.googleapis.com/v1beta/openai",
        "model": "gemini-3.1-flash-lite",
        "temperature": 1.0,
        "max_tokens": 512,
        "rpm": 0.0,
        "max_concurrency": 0,
        "input_usd_per_mtok": 0.25,
        "output_usd_per_mtok": 1.5,
        "extra_body": {},
    },
    "arena": {"defense": "standard", "enforce_permissions": True, "enforce_confirmation": True},
}
"""取自本机 `redcell.db` 中该批 run 的原始快照；不含任何凭据。"""

PHASE_0_DECLARED_ADDITIONS = {
    ("scorer_version",),
    ("finding_signature_version",),
    ("attack_path_signature_version",),
}
"""Phase 0.5 之后**恒定出现**、因而让历史哈希无法由当前代码复算的字段。

刻意用完整路径而不是顶层字段名；未来新增嵌套字段时，只比顶层 key 会让它溜过去。
新增任何一个恒定字段都必须显式登记到这里，登记本身就是“我知道我改变了历史条件
形状”这句话。价格未知现在保持 `None` 并被 `exclude_none` 省略，不再属于恒定新增字段。
"""


def _added_paths(
    current: dict, historical: dict, prefix: tuple[str, ...] = ()
) -> set[tuple[str, ...]]:
    additions: set[tuple[str, ...]] = set()
    for key, value in current.items():
        path = (*prefix, key)
        if key not in historical:
            additions.add(path)
        elif isinstance(value, dict) and isinstance(historical[key], dict):
            additions.update(_added_paths(value, historical[key], path))
    return additions


def _strip_declared(payload: dict, prefix: tuple[str, ...] = ()) -> dict:
    stripped = {}
    for key, value in payload.items():
        path = (*prefix, key)
        if path in PHASE_0_DECLARED_ADDITIONS:
            continue
        stripped[key] = _strip_declared(value, path) if isinstance(value, dict) else value
    return stripped


def _fingerprint_of(payload: dict) -> str:
    """复用 `ExperimentConditions.fingerprint()` 的序列化口径。"""
    encoded = json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )
    return hashlib.sha256(encoded).hexdigest()


def test_phase_zero_snapshot_gains_only_declared_fields() -> None:
    """冻结快照在当前 schema 下**只**多出已登记的字段,一个都不能多。

    这是给 `docs/PHASE0_BASELINE.md` 那批数字上的机器锁。失败时先看 diff:
    多出来的那个字段就是让历史条件形状改变的元凶。
    """
    conditions = ExperimentConditions.model_validate(PHASE_0_BASELINE_CONDITIONS)
    dumped = conditions.model_dump(mode="json", exclude_none=True)

    assert _added_paths(dumped, PHASE_0_BASELINE_CONDITIONS) == PHASE_0_DECLARED_ADDITIONS
    assert _strip_declared(dumped) == PHASE_0_BASELINE_CONDITIONS


def test_phase_zero_historical_shape_is_still_byte_identical() -> None:
    """去掉已登记字段后,历史载荷必须仍然精确哈希回 `a0f8d19…`。

    ⚠️ 这条**不是**要求当前代码复算出历史指纹 —— 它做不到,也不该做:
    scorer 或 signature 语义一变就该换指纹,那是 fail-closed 的正确行为
    (理由见 `docs/PHASE0_BASELINE.md`)。这条锁住的是另一件事:
    **除了已登记的那几个字段,历史条件的其余部分一个字节都没有漂移。**
    变红时不要改这里的期望值,先去查是哪个字段动了。
    """
    conditions = ExperimentConditions.model_validate(PHASE_0_BASELINE_CONDITIONS)
    dumped = conditions.model_dump(mode="json", exclude_none=True)

    assert _fingerprint_of(_strip_declared(dumped)) == PHASE_0_BASELINE_FINGERPRINT
