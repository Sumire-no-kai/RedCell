"""把指纹的**取值**钉死,让 schema 漂移当场变红。⭐

2026-08-09 给 `ExperimentConditions` 加了三个带默认值的字段,没有升 schema 版本。
后果是 `redcell.db` 里 23 条 Run 有 19 条读不出来 —— 反序列化时补上今天的默认值,
摘要随之改变,校验器判定"与 conditions 不一致"。这个缺陷存在了五天没人发现,
因为**没有任何测试断言过摘要等于什么**:所有测试都在拿今天的代码算两遍再比较,
那种断言在 schema 漂移时会一起漂,永远是绿的。

所以这里钉的是字面量。它失败时该做的不是改数字,是问:
这次改动有没有升 `EXPERIMENT_CONDITIONS_SCHEMA_VERSION`?
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from redcell.arena.support_agent.codec import TOOL_CALL_CODEC_VERSION
from redcell.feedback_attacker import feedback_strategy_digest
from redcell.protocols.run import ExperimentConditions, Run
from redcell.protocols.strategy import StrategyCatalogue
from redcell.storage import RunStore
from redcell.strategies.library import PHASE_0_STRATEGIES
from redcell.versions import (
    EXPERIMENT_CONDITIONS_SCHEMA_VERSION,
    FEEDBACK_EXPERIMENT_CONDITIONS_SCHEMA_VERSION,
    HOST_BOUND_EXPERIMENT_CONDITIONS_SCHEMA_VERSION,
)

# 一份定死的条件。字段值刻意用非默认值,免得改默认值时测试察觉不到。
_PINNED_PAYLOAD = {
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
        "cached_input_usd_per_mtok": 0.01,
    },
    "attacker": {
        "provider": "gemini",
        "base_url": "https://generativelanguage.googleapis.com/v1beta/openai",
        "model": "gemini-2.5-flash",
        "temperature": 1.0,
        "max_tokens": 1024,
        "rpm": 0.0,
        "max_concurrency": 3,
        "input_usd_per_mtok": 0.3,
        "output_usd_per_mtok": 2.5,
        "cached_input_usd_per_mtok": 0.075,
    },
    "arena": {"defense": "standard", "enforce_permissions": True, "enforce_confirmation": True},
}

PINNED_FINGERPRINT = "5f912888e1c020f01e4a06b9616ed17a670aacc80bf34b9f53d4d98aa9c1c4a9"
PINNED_REGRESSION_CONTEXT = "cae963ba87dfbf00f5eaba679eeb52383d98eaaa2aa9b2abb03dabb629d281c1"
PINNED_V4_FINGERPRINT = "51d295e820ed2b9c04154917794f00760b1b2cc343cbba27b50fcabedb80559c"


def _pinned() -> ExperimentConditions:
    return ExperimentConditions.model_validate(json.loads(json.dumps(_PINNED_PAYLOAD)))


def _current() -> ExperimentConditions:
    """A genuine current-schema record: v4 must carry the tool-call protocol."""
    payload = json.loads(json.dumps(_PINNED_PAYLOAD))
    payload["arena"]["tool_call_protocol_version"] = TOOL_CALL_CODEC_VERSION
    payload["conditions_schema_version"] = EXPERIMENT_CONDITIONS_SCHEMA_VERSION
    return ExperimentConditions.model_validate(payload)


def _feedback() -> ExperimentConditions:
    payload = json.loads(json.dumps(_PINNED_PAYLOAD))
    payload["arena"]["tool_call_protocol_version"] = "native-function-calling-v1"
    payload["conditions_schema_version"] = FEEDBACK_EXPERIMENT_CONDITIONS_SCHEMA_VERSION
    payload["feedback"] = {
        "driver_name": "llm-feedback",
        "strategy_views_sha256": feedback_strategy_digest([PHASE_0_STRATEGIES[0]]),
        "observation_visibility": "tool-status",
        "prompt_version": "feedback-attacker-prompt-v2",
        "schema_version": "feedback-attacker-choice-v2",
        "observation_policy_version": "attacker-observation-v2",
        "max_decision_steps": 8,
        "max_turns_per_attempt": 3,
        "stop_policy_version": "feedback-stop-v1",
    }
    payload["strategy_catalogue"] = (
        StrategyCatalogue(version="feedback-test", strategies=[PHASE_0_STRATEGIES[0]])
        .condition_summary()
        .model_dump(mode="json")
    )
    for role in ("target", "attacker"):
        payload[role]["usage_accounting_mode"] = "prompt-completion-v1"
        payload[role]["usage_covers_billed_tokens"] = True
    return ExperimentConditions.model_validate(payload)


def test_experiment_fingerprint_is_pinned_to_a_literal() -> None:
    """摘要漂了就该在这里失败,而不是等历史证据读不出来才发现。

    修法不是把下面的字面量改成新值就完事 —— 先确认
    `EXPERIMENT_CONDITIONS_SCHEMA_VERSION` 是否也升了一版。
    """
    assert _pinned().fingerprint() == PINNED_FINGERPRINT


def test_regression_context_fingerprint_is_pinned_to_a_literal() -> None:
    assert _pinned().regression_context_fingerprint() == PINNED_REGRESSION_CONTEXT


def test_the_schema_version_stays_out_of_the_digest() -> None:
    """版本描述的是摘要的出处,不是被摘要的条件 —— 进了摘要就自我指涉了。"""
    versioned = _pinned().model_copy(
        update={"conditions_schema_version": HOST_BOUND_EXPERIMENT_CONDITIONS_SCHEMA_VERSION}
    )

    assert versioned.fingerprint() == PINNED_FINGERPRINT
    assert versioned.regression_context_fingerprint() == PINNED_REGRESSION_CONTEXT


def test_a_record_from_an_older_schema_stays_readable() -> None:
    """旧记录只能保留、不能重算校验;它读得出来,但不算"验过"。"""
    run = Run(
        target_name="support-agent",
        policy_version="v1",
        adapter_type="arena",
        algorithm="static",
        limits={"max_attempts": 1},
        experiment_conditions=_pinned(),
        experiment_fingerprint="0" * 64,
    )

    assert run.experiment_fingerprint == "0" * 64
    assert run.has_auditable_conditions
    assert not run.conditions_fingerprint_verified


def test_a_current_schema_record_still_rejects_a_forged_fingerprint() -> None:
    """版本对得上时校验必须照常生效,否则这个机制就成了绕过校验的后门。"""
    conditions = _current()

    try:
        Run(
            target_name="support-agent",
            policy_version="v1",
            adapter_type="arena",
            algorithm="static",
            limits={"max_attempts": 1},
            experiment_conditions=conditions,
            experiment_fingerprint="0" * 64,
        )
    except ValueError as exc:
        assert "experiment_fingerprint" in str(exc)
    else:  # pragma: no cover - 只有回归时才会走到
        raise AssertionError("伪造的 fingerprint 必须被拒绝")


def test_current_and_legacy_runs_in_a_fresh_database_round_trip_together(tmp_path: Path) -> None:
    """加字段导致历史记录读不出来的那个缺陷,在这里直接可复现。

    只用本测试自己写入的库,不碰仓库里的 `redcell.db` —— 测试不该依赖开发机上
    碰巧存在的数据。
    """
    url = f"sqlite:///{(tmp_path / 'runs.db').as_posix()}"
    conditions = _current()
    current_run = Run(
        target_name="support-agent",
        policy_version="v1",
        adapter_type="arena",
        algorithm="static",
        limits={"max_attempts": 1},
        experiment_conditions=conditions,
    )
    legacy_run = Run(
        target_name="support-agent",
        policy_version="v1",
        adapter_type="arena",
        algorithm="static",
        limits={"max_attempts": 1},
        experiment_conditions=_pinned(),
        experiment_fingerprint="0" * 64,
    )
    with RunStore(url) as store:
        store.save_run(current_run)
        store.save_run(legacy_run)
        loaded = store.list_runs()

    assert len(loaded) == 2
    assert [run.conditions_fingerprint_verified for run in loaded] == [True, False]


def test_current_schema_requires_the_tool_call_protocol() -> None:
    """Without the protocol a v4 digest is identical whichever codec actually ran."""
    payload = json.loads(json.dumps(_PINNED_PAYLOAD))
    payload["conditions_schema_version"] = EXPERIMENT_CONDITIONS_SCHEMA_VERSION

    with pytest.raises(ValueError, match="工具调用协议"):
        ExperimentConditions.model_validate(payload)


def test_an_older_schema_cannot_claim_a_tool_call_protocol() -> None:
    payload = json.loads(json.dumps(_PINNED_PAYLOAD))
    payload["arena"]["tool_call_protocol_version"] = TOOL_CALL_CODEC_VERSION
    payload["conditions_schema_version"] = HOST_BOUND_EXPERIMENT_CONDITIONS_SCHEMA_VERSION

    with pytest.raises(ValueError, match="工具调用协议"):
        ExperimentConditions.model_validate(payload)


def test_the_tool_call_protocol_enters_the_current_digest() -> None:
    assert _current().fingerprint() != PINNED_FINGERPRINT


def test_v4_fingerprint_and_serialization_stay_unchanged_without_feedback() -> None:
    conditions = _current()

    assert conditions.fingerprint() == PINNED_V4_FINGERPRINT
    assert "feedback" not in conditions.model_dump(mode="json")
    assert "feedback" not in json.loads(conditions.model_dump_json())
    run = Run(
        target_name="support-agent",
        policy_version="v1",
        adapter_type="arena",
        algorithm="static",
        limits={"max_attempts": 1},
        experiment_conditions=conditions,
    )
    assert "feedback_stop_reason" not in run.model_dump(mode="json")


def test_feedback_conditions_bind_driver_and_visibility_into_v5_fingerprint() -> None:
    conditions = _feedback()
    conditions.require_feedback()
    payload = conditions.model_dump(mode="json")

    assert payload["conditions_schema_version"] == FEEDBACK_EXPERIMENT_CONDITIONS_SCHEMA_VERSION
    assert payload["feedback"]["driver_name"] == "llm-feedback"
    assert conditions.fingerprint() != _current().fingerprint()
    payload["feedback"]["observation_visibility"] = "response-only"
    changed = ExperimentConditions.model_validate(payload)
    assert changed.fingerprint() != conditions.fingerprint()


def test_v5_accepts_scripted_feedback_and_explicit_text_protocol() -> None:
    payload = _feedback().model_dump(mode="json")
    payload["online"] = False
    payload["feedback"]["driver_name"] = "scripted-feedback"
    payload["arena"]["tool_call_protocol_version"] = TOOL_CALL_CODEC_VERSION

    ExperimentConditions.model_validate(payload).require_feedback()


@pytest.mark.parametrize(
    "schema",
    [HOST_BOUND_EXPERIMENT_CONDITIONS_SCHEMA_VERSION, EXPERIMENT_CONDITIONS_SCHEMA_VERSION],
)
def test_legacy_conditions_reject_feedback_configuration(schema: str) -> None:
    payload = _feedback().model_dump(mode="json")
    payload["conditions_schema_version"] = schema
    if schema == HOST_BOUND_EXPERIMENT_CONDITIONS_SCHEMA_VERSION:
        payload["arena"].pop("tool_call_protocol_version")

    with pytest.raises(ValueError, match="feedback 配置"):
        ExperimentConditions.model_validate(payload)


def test_v5_requires_feedback_configuration_and_known_tool_protocol() -> None:
    payload = _feedback().model_dump(mode="json")
    payload.pop("feedback")
    with pytest.raises(ValueError, match="feedback 配置"):
        ExperimentConditions.model_validate(payload)

    payload = _feedback().model_dump(mode="json")
    payload["arena"]["tool_call_protocol_version"] = "unknown-protocol"
    with pytest.raises(ValueError, match="工具调用协议"):
        ExperimentConditions.model_validate(payload)

    payload["arena"].pop("tool_call_protocol_version")
    with pytest.raises(ValueError, match="工具调用协议"):
        ExperimentConditions.model_validate(payload)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("search", {"selector": "static"}),
        ("generation_memory", {"mode": "off"}),
        (
            "controller",
            {
                "provider": _PINNED_PAYLOAD["attacker"],
                "connection_id": "controller:test",
                "connection_fingerprint": "test",
                "prompt_version": "controller-prompt-v1",
                "evidence_policy_version": "controller-evidence-v1",
                "thinking_disabled": False,
            },
        ),
    ],
)
def test_v5_rejects_legacy_treatment_factors(field: str, value: dict) -> None:
    payload = _feedback().model_dump(mode="json")
    payload[field] = value

    with pytest.raises(ValueError, match="旧 search / generation_memory / controller"):
        ExperimentConditions.model_validate(payload)


def test_feedback_run_requires_attempt_and_token_limits_and_stays_out_of_old_gate() -> None:
    conditions = _feedback()
    run = Run(
        target_name="support-agent",
        policy_version="v1",
        adapter_type="arena",
        algorithm="llm-feedback",
        limits={"max_attempts": 2, "max_total_tokens": 1000},
        experiment_conditions=conditions,
    )

    run.require_feedback()
    loaded = Run.model_validate_json(run.model_dump_json())
    assert loaded.conditions_fingerprint_verified
    assert not loaded.has_verified_phase_0_5_conditions
    for limits in ({"max_attempts": 2}, {"max_total_tokens": 1000}):
        with pytest.raises(ValueError, match="max_attempts 与 max_total_tokens"):
            run.model_copy(update={"limits": run.limits.model_validate(limits)}).require_feedback()


def test_feedback_requires_usage_identity_for_both_participating_providers() -> None:
    payload = _feedback().model_dump(mode="json")
    payload["attacker"].pop("usage_accounting_mode")
    with pytest.raises(ValueError, match="usage_accounting_mode"):
        ExperimentConditions.model_validate(payload).require_feedback()

    payload = _feedback().model_dump(mode="json")
    payload["target"]["usage_covers_billed_tokens"] = False
    with pytest.raises(ValueError, match="usage 覆盖全部计费 Token"):
        ExperimentConditions.model_validate(payload).require_feedback()
