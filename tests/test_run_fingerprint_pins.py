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

from redcell.protocols.run import ExperimentConditions, Run
from redcell.storage import RunStore
from redcell.versions import EXPERIMENT_CONDITIONS_SCHEMA_VERSION

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


def _pinned() -> ExperimentConditions:
    return ExperimentConditions.model_validate(json.loads(json.dumps(_PINNED_PAYLOAD)))


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
        update={"conditions_schema_version": EXPERIMENT_CONDITIONS_SCHEMA_VERSION}
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
    conditions = _pinned().model_copy(
        update={"conditions_schema_version": EXPERIMENT_CONDITIONS_SCHEMA_VERSION}
    )

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
    conditions = _pinned().model_copy(
        update={"conditions_schema_version": EXPERIMENT_CONDITIONS_SCHEMA_VERSION}
    )
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
