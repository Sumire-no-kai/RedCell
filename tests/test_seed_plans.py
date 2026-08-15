"""两份冻结 seed plan 的钉子。

0.5 是一次已归档的**失效**实验,0.5b 是替代它的重跑。归档不等于删除:同一段代码
必须能同时说清"0.5 是 12+8"和"0.5b 是 24+8",而不是被最新那个实验改写。
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from redcell.gate_analysis import (
    FROZEN_SEED_PLANS,
    PHASE_0_5_EXPERIMENT,
    PHASE_0_5_SEED_PLAN_DIGEST,
    PHASE_0_5B_EXPERIMENT,
    PHASE_0_5B_SEED_PLAN_DIGEST,
    SeedPlan,
    require_frozen_seed_plan,
    seed_plan_digest,
)

_DOCS = Path(__file__).parents[1] / "docs"


def _load(name: str) -> SeedPlan:
    return SeedPlan.model_validate_json((_DOCS / name).read_text(encoding="utf-8"))


def test_the_archived_phase_0_5_plan_still_loads_and_matches_its_digest() -> None:
    """加 `experiment` 字段之后,2026-08-10 冻结的摘要必须逐字不变。⭐

    这正是本项目已经栽过四次的坑:给一个被摘要的模型加带默认值的字段,历史产物
    当场对不上。这里把它钉死 —— `experiment` 是元数据,不进摘要。
    """
    plan = _load("PHASE0_5_SEED_PLAN.json")

    assert plan.experiment == PHASE_0_5_EXPERIMENT
    assert (len(plan.primary), len(plan.reserve)) == (12, 8)
    assert seed_plan_digest(plan) == PHASE_0_5_SEED_PLAN_DIGEST
    require_frozen_seed_plan(plan)


def test_the_phase_0_5b_plan_is_frozen_at_twenty_four_primary_seeds() -> None:
    """24 来自实测:配对差标准差 1.78,要看见预注册的 1.0 阈值需要约 25 个 seed。

    12 个只够看见 1.4 条 —— 旧 Gate 从一开始就没有能力看见自己设的那条线。
    """
    plan = _load("PHASE0_5B_SEED_PLAN.json")

    assert plan.experiment == PHASE_0_5B_EXPERIMENT
    assert (len(plan.primary), len(plan.reserve)) == (24, 8)
    assert seed_plan_digest(plan) == PHASE_0_5B_SEED_PLAN_DIGEST
    require_frozen_seed_plan(plan)


def test_phase_0_5b_reuses_no_seed_from_the_invalidated_run() -> None:
    """0.5 的 12 个 seed 已经被看过路径数,不再是盲的,不得进入新实验。⭐

    重用等于让一半样本带着已知结果进入预注册 —— 这个污染是我们自己造成的
    (估方差时看了全部 12 个),所以必须在这里挡住,而不是靠记性。
    """
    old = _load("PHASE0_5_SEED_PLAN.json")
    new = _load("PHASE0_5B_SEED_PLAN.json")

    assert set(old.ordered) & set(new.ordered) == set()


def test_a_plan_whose_shape_disagrees_with_its_experiment_is_rejected() -> None:
    old = json.loads((_DOCS / "PHASE0_5_SEED_PLAN.json").read_text(encoding="utf-8"))

    with pytest.raises(ValueError, match="24 primary"):
        SeedPlan.model_validate({**old, "experiment": PHASE_0_5B_EXPERIMENT})


def test_an_unregistered_experiment_is_rejected() -> None:
    new = json.loads((_DOCS / "PHASE0_5B_SEED_PLAN.json").read_text(encoding="utf-8"))

    with pytest.raises(ValueError, match="未登记"):
        SeedPlan.model_validate({**new, "experiment": "phase-0.5c"})


def test_every_registered_plan_declares_its_own_shape() -> None:
    assert set(FROZEN_SEED_PLANS) == {PHASE_0_5_EXPERIMENT, PHASE_0_5B_EXPERIMENT}
    for experiment, frozen in FROZEN_SEED_PLANS.items():
        assert frozen.experiment == experiment
        assert len(frozen.digest) == 64
