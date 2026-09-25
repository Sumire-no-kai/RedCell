"""Gate 流水线的靶场绑定(2026-09-25)。

三条不变量:
1. 已登记的四个实验都在客服靶场上,它们的 Gate 计划与改前逐字节相同(无 `arena_id`、无 `--arena`);
2. 登记在别的靶场上的实验,靶场从登记推出并进入每格 argv,篡改会在执行前被拒绝;
3. preflight 与 gate-report 用实验所在靶场的考卷和答案,且 controls 必须来自同一个靶场。
"""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from redcell.arena.ops_console import OPS_CONSOLE_ARENA
from redcell.arena.registry import DEFAULT_ARENA_ID
from redcell.arena.support_agent import SUPPORT_AGENT_ARENA, DefenseLevel, ToolCallProtocol
from redcell.cli import _experiment_conditions
from redcell.controls import UTILITY_CONTEXT_VERSION, ControlsReport, controls_conditions
from redcell.gate_analysis import (
    FROZEN_SEED_PLANS,
    PHASE_0_5D_EXPERIMENT,
    SeedPlan,
    experiment_arena_id,
)
from redcell.gate_plan import GatePlan, build_gate_plan
from redcell.gate_preflight import run_preflight
from redcell.gate_report import _golden_failures
from redcell.golden import evaluate_golden
from redcell.utility_baseline import UtilityBaseline

from .test_gate_preflight import (
    GOLDEN_FIXTURES,
    PHASE_0_5D_SEED_PLAN,
    _billing_evidence,
    _check,
    _db,
    _roles,
)

OPS_GOLDEN_FIXTURES = Path("tests/fixtures/level1-golden-ops-console-v2.json").resolve()


def _seed_plan() -> SeedPlan:
    return SeedPlan.model_validate_json(PHASE_0_5D_SEED_PLAN.read_text(encoding="utf-8"))


def _plan() -> GatePlan:
    return build_gate_plan(
        _seed_plan(),
        max_attempts=500,
        database_url="sqlite:///runs/phase-0-5d.db",
        report_directory="runs/phase-0-5d",
        tool_call_protocol=ToolCallProtocol.NATIVE_V1,
    )


@pytest.fixture
def on_ops_console(monkeypatch):
    """假设 0.5d 当初登记在工单台上 —— 只为测试,真实登记表不变。"""
    frozen = FROZEN_SEED_PLANS[PHASE_0_5D_EXPERIMENT]
    monkeypatch.setitem(
        FROZEN_SEED_PLANS,
        PHASE_0_5D_EXPERIMENT,
        frozen.model_copy(update={"arena_id": "ops-console"}),
    )


# ── Gate 计划 ─────────────────────────────────────────────────────────────


def test_every_registered_experiment_is_on_the_support_arena() -> None:
    for experiment, frozen in FROZEN_SEED_PLANS.items():
        assert frozen.arena_id == DEFAULT_ARENA_ID, experiment
        assert experiment_arena_id(experiment) == DEFAULT_ARENA_ID


def test_default_arena_plan_carries_no_arena_anywhere() -> None:
    plan = _plan()
    assert plan.arena_id is None
    assert "arena_id" not in plan.model_dump(mode="json")
    assert not any("--arena" in cell.argv for cell in plan.cells)


def test_experiment_on_another_arena_puts_it_into_every_cell(on_ops_console) -> None:
    plan = _plan()
    assert plan.arena_id == "ops-console"
    assert all(cell.argv[-2:] == ["--arena", "ops-console"] for cell in plan.cells)
    assert GatePlan.model_validate_json(plan.model_dump_json()) == plan


def test_loaded_plan_rejects_an_arena_that_disagrees_with_the_registration(on_ops_console) -> None:
    payload = _plan().model_dump(mode="python")
    payload.pop("arena_id")
    with pytest.raises(ValidationError, match="预注册的靶场不一致"):
        GatePlan.model_validate(payload)


def test_plan_for_the_default_arena_rejects_a_smuggled_arena() -> None:
    payload = _plan().model_dump(mode="python")
    payload["arena_id"] = "ops-console"
    with pytest.raises(ValidationError, match="预注册的靶场不一致"):
        GatePlan.model_validate(payload)


def test_registration_on_an_unknown_arena_is_a_config_error(monkeypatch) -> None:
    frozen = FROZEN_SEED_PLANS[PHASE_0_5D_EXPERIMENT]
    monkeypatch.setitem(
        FROZEN_SEED_PLANS, PHASE_0_5D_EXPERIMENT, frozen.model_copy(update={"arena_id": "bogus"})
    )
    with pytest.raises(ValueError, match="登记的靶场不存在"):
        _plan()


# ── preflight ─────────────────────────────────────────────────────────────


def _preflight(tmp_path, *, controls_arena, golden_fixtures=None):
    roles = _roles()
    target = next(settings for name, settings in roles if name == "target")
    conditions = controls_conditions(
        target=target.run_configuration(),
        tool_call_protocol_version=ToolCallProtocol.NATIVE_V1.value,
        arena=controls_arena,
    )
    return run_preflight(
        seed_plan_json=PHASE_0_5D_SEED_PLAN,
        database_url=_db(tmp_path),
        golden_fixtures=golden_fixtures,
        roles=roles,
        shared_rate_limit_db=f"sqlite:///{tmp_path / 'shared-rate-limit.db'}",
        billing_evidence=_billing_evidence(roles),
        controls=ControlsReport(
            conditions=conditions,
            utility_context_fingerprint=conditions.utility_context_fingerprint(),
            utility_context_version=UTILITY_CONTEXT_VERSION,
        ),
        utility_baseline=UtilityBaseline(
            context_fingerprint=conditions.utility_context_fingerprint(),
            negative_repeats=20,
            per_task={"task": 20},
        ),
        gate_plan=_plan(),
    )


def test_preflight_defaults_to_the_experiment_arenas_golden(tmp_path) -> None:
    report = _preflight(tmp_path, controls_arena=SUPPORT_AGENT_ARENA)
    assert _check(report, "level1_golden").passed
    with pytest.raises(StopIteration):
        _check(report, "controls_arena_mismatch")


def test_preflight_rejects_controls_from_another_arena(tmp_path, on_ops_console) -> None:
    """同源的 controls 与 baseline 指纹一致,但都来自客服靶场 —— 只有显式的靶场核对拦得住。"""
    report = _preflight(tmp_path, controls_arena=SUPPORT_AGENT_ARENA)
    assert not report.passed
    assert not _check(report, "controls_arena_mismatch").passed
    assert _check(report, "level1_golden").passed  # 默认取工单台自己的考卷


def test_preflight_accepts_controls_from_the_registered_arena(tmp_path, on_ops_console) -> None:
    report = _preflight(tmp_path, controls_arena=OPS_CONSOLE_ARENA)
    with pytest.raises(StopIteration):
        _check(report, "controls_arena_mismatch")


def test_preflight_rejects_another_arenas_answer_key(tmp_path, on_ops_console) -> None:
    report = _preflight(tmp_path, controls_arena=OPS_CONSOLE_ARENA, golden_fixtures=GOLDEN_FIXTURES)
    assert not _check(report, "level1_golden").passed


# ── gate-report ───────────────────────────────────────────────────────────


def _reference(arena_id: str | None):
    return _experiment_conditions(
        online=False,
        providers=None,
        actor="agent_l1" if arena_id else "customer_a",
        defense=DefenseLevel.STANDARD,
        enforce_permissions=True,
        enforce_confirmation=True,
        tool_call_protocol_version=ToolCallProtocol.NATIVE_V1.value,
        arena_id=arena_id,
        arena_version=OPS_CONSOLE_ARENA.version if arena_id else None,
    )


def test_gate_report_checks_golden_against_the_runs_arena() -> None:
    ops_golden = evaluate_golden(OPS_GOLDEN_FIXTURES, arena=OPS_CONSOLE_ARENA)
    support_golden = evaluate_golden(GOLDEN_FIXTURES, arena=SUPPORT_AGENT_ARENA)
    ops_reference = _reference("ops-console")
    support_reference = _reference(None)

    assert _golden_failures(ops_golden, ops_reference) == []
    assert _golden_failures(support_golden, support_reference) == []
    assert {
        "level1_golden_fixture_digest_mismatch",
        "level1_golden_outcomes_shape_invalid",
    } <= set(_golden_failures(support_golden, ops_reference))
    assert "level1_golden_fixture_digest_mismatch" in _golden_failures(
        ops_golden, support_reference
    )
