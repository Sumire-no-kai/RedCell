from __future__ import annotations

from pathlib import Path

import pytest

from redcell.arena.support_agent import ToolCallProtocol
from redcell.gate_analysis import (
    PHASE_0_5_SEED_PLAN_DIGEST,
    SeedPlan,
    seed_plan_digest,
)
from redcell.gate_plan import GATE_PLAN_VERSION, GatePlan, build_gate_plan
from redcell.protocols.run import ExecutionHostProfile

SEED_PLAN_PATH = Path(__file__).parents[1] / "docs" / "PHASE0_5_SEED_PLAN.json"


def test_versioned_seed_plan_matches_the_frozen_digest() -> None:
    seed_plan = SeedPlan.model_validate_json(SEED_PLAN_PATH.read_text(encoding="utf-8"))

    assert seed_plan_digest(seed_plan) == PHASE_0_5_SEED_PLAN_DIGEST
    assert not set(seed_plan.ordered) & {5000, 5001, 5002}


def test_gate_plan_freezes_500_attempts_and_disables_reserves() -> None:
    seed_plan = SeedPlan.model_validate_json(SEED_PLAN_PATH.read_text(encoding="utf-8"))

    plan = build_gate_plan(
        seed_plan,
        max_attempts=500,
        database_url="sqlite:///runs/phase-0-5.db",
        report_directory="runs/phase-0-5",
    )

    assert len(plan.cells) == 120
    assert plan.plan_version == GATE_PLAN_VERSION
    assert plan.execution_host_profile is ExecutionHostProfile.WINDOWS_WAKELOCK_V1
    # 2026-09-23: new experiments default to native function calling.
    assert plan.tool_call_protocol_version == ToolCallProtocol.NATIVE_V1.value
    assert all("--execution-host-profile" in cell.argv for cell in plan.cells)
    assert all(
        cell.argv[cell.argv.index("--tool-call-protocol") + 1] == ToolCallProtocol.NATIVE_V1.value
        for cell in plan.cells
    )
    assert all(cell.enabled_initially for cell in plan.cells[:72])
    assert not any(cell.enabled_initially for cell in plan.cells[72:])


def test_v2_gate_plan_without_explicit_tool_protocol_still_loads() -> None:
    seed_plan = SeedPlan.model_validate_json(SEED_PLAN_PATH.read_text(encoding="utf-8"))
    payload = build_gate_plan(
        seed_plan,
        max_attempts=500,
        database_url="sqlite:///runs/phase-0-5.db",
        report_directory="runs/phase-0-5",
    ).model_dump(mode="python")
    payload["plan_version"] = "phase-0.5-gate-plan-v2"
    payload.pop("tool_call_protocol_version")
    for cell in payload["cells"]:
        flag = cell["argv"].index("--tool-call-protocol")
        del cell["argv"][flag : flag + 2]

    loaded = GatePlan.model_validate(payload)

    assert loaded.tool_call_protocol_version is None


def test_gate_plan_refuses_a_different_attempt_cap_or_seed_plan() -> None:
    seed_plan = SeedPlan.model_validate_json(SEED_PLAN_PATH.read_text(encoding="utf-8"))

    with pytest.raises(ValueError, match="max_attempts must be 500"):
        build_gate_plan(
            seed_plan,
            max_attempts=499,
            database_url="sqlite:///runs/phase-0-5.db",
            report_directory="runs/phase-0-5",
        )
    with pytest.raises(ValueError, match="does not match the frozen"):
        build_gate_plan(
            SeedPlan(primary=list(range(1, 13)), reserve=list(range(13, 21))),
            max_attempts=500,
            database_url="sqlite:///runs/phase-0-5.db",
            report_directory="runs/phase-0-5",
        )


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (
            lambda payload: payload["cells"][0].update(seed=123456789),
            "requires exactly 12 primary|frozen digest|canonical frozen matrix",
        ),
        (
            lambda payload: payload["cells"][0]["argv"].__setitem__(
                payload["cells"][0]["argv"].index("320000"), "160000"
            ),
            "canonical frozen matrix",
        ),
        (
            lambda payload: payload.update(primary_cells=71),
            "primary_cells",
        ),
    ],
)
def test_loaded_gate_plan_rejects_drift_before_execution(mutate, message) -> None:
    seed_plan = SeedPlan.model_validate_json(SEED_PLAN_PATH.read_text(encoding="utf-8"))
    plan = build_gate_plan(
        seed_plan,
        max_attempts=500,
        database_url="sqlite:///runs/phase-0-5.db",
        report_directory="runs/phase-0-5",
    )
    payload = plan.model_dump(mode="python")
    mutate(payload)

    with pytest.raises(ValueError, match=message):
        GatePlan.model_validate(payload)


def _plan(**kwargs) -> GatePlan:
    seed_plan = SeedPlan.model_validate_json(SEED_PLAN_PATH.read_text(encoding="utf-8"))
    return build_gate_plan(
        seed_plan,
        max_attempts=500,
        database_url="sqlite:///runs/phase-0-5.db",
        report_directory="runs/phase-0-5",
        **kwargs,
    )


def test_gate_plan_without_env_file_serialises_exactly_as_before() -> None:
    """不传 --env-file 时计划与 argv 必须和加入该字段之前逐字节相同。"""
    plan = _plan()

    assert "env_file" not in plan.model_dump(mode="json")
    assert '"env_file"' not in plan.model_dump_json()
    assert not any("--env-file" in cell.argv for cell in plan.cells)


def test_gate_plan_freezes_the_env_file_into_every_cell() -> None:
    plan = _plan(env_file=".env.gemini")

    assert plan.env_file == ".env.gemini"
    assert all(cell.argv[cell.argv.index("--env-file") + 1] == ".env.gemini" for cell in plan.cells)
    assert GatePlan.model_validate_json(plan.model_dump_json()) == plan


def test_loaded_gate_plan_rejects_a_cell_that_dropped_its_env_file() -> None:
    """计划与各格 argv 不一致时,付费子进程启动前就要拒绝。"""
    payload = _plan(env_file=".env.gemini").model_dump(mode="python")
    argv = payload["cells"][0]["argv"]
    flag = argv.index("--env-file")
    del argv[flag : flag + 2]

    with pytest.raises(ValueError, match="canonical frozen matrix"):
        GatePlan.model_validate(payload)


# ── 0.5e:工具协议随登记冻结(2026-09-25) ─────────────────────────────────

PHASE_0_5E_SEED_PLAN_PATH = Path(__file__).parents[1] / "docs" / "PHASE0_5E_SEED_PLAN.json"


def _phase_0_5e_plan(**kwargs) -> GatePlan:
    seed_plan = SeedPlan.model_validate_json(PHASE_0_5E_SEED_PLAN_PATH.read_text(encoding="utf-8"))
    return build_gate_plan(
        seed_plan,
        max_attempts=500,
        database_url="sqlite:///runs/phase-0-5e.db",
        report_directory="runs/phase-0-5e",
        **kwargs,
    )


def test_phase_0_5e_plan_takes_native_v2_from_its_registration() -> None:
    plan = _phase_0_5e_plan()
    assert plan.tool_call_protocol_version == ToolCallProtocol.NATIVE_V2.value
    assert (plan.primary_cells, plan.reserve_cells) == (144, 48)
    assert all(
        cell.argv[cell.argv.index("--tool-call-protocol") + 1] == ToolCallProtocol.NATIVE_V2.value
        for cell in plan.cells
    )
    assert _phase_0_5e_plan(tool_call_protocol=ToolCallProtocol.NATIVE_V2) == plan


@pytest.mark.parametrize("protocol", [ToolCallProtocol.NATIVE_V1, ToolCallProtocol.TEXT_V2])
def test_phase_0_5e_refuses_any_other_protocol(protocol: ToolCallProtocol) -> None:
    with pytest.raises(ValueError, match="预注册的工具协议"):
        _phase_0_5e_plan(tool_call_protocol=protocol)


def test_a_loaded_phase_0_5e_plan_with_another_protocol_is_rejected() -> None:
    payload = _phase_0_5e_plan().model_dump(mode="python")
    payload["tool_call_protocol_version"] = ToolCallProtocol.NATIVE_V1.value
    for cell in payload["cells"]:
        argv = cell["argv"]
        argv[argv.index("--tool-call-protocol") + 1] = ToolCallProtocol.NATIVE_V1.value
    with pytest.raises(ValueError, match="预注册的协议不一致"):
        GatePlan.model_validate(payload)


def test_unregistered_protocol_experiments_keep_the_new_experiment_default() -> None:
    """0.5d 没有冻结协议:不传参数时仍取新实验默认,与改动前相同。"""
    seed_plan = SeedPlan.model_validate_json(
        (Path(__file__).parents[1] / "docs" / "PHASE0_5D_SEED_PLAN.json").read_text(
            encoding="utf-8"
        )
    )
    plan = build_gate_plan(
        seed_plan,
        max_attempts=500,
        database_url="sqlite:///runs/phase-0-5d.db",
        report_directory="runs/phase-0-5d",
    )
    assert plan.tool_call_protocol_version == ToolCallProtocol.NATIVE_V1.value
