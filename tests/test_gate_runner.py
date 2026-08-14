from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest
from scripts.run_gate_matrix import _command_for, _exclusive_state_lock, _save

from redcell.gate_analysis import GateCondition, SeedPlan
from redcell.gate_plan import SeedRole, build_gate_plan
from redcell.gate_runner import (
    CellStatus,
    MatrixState,
    ReserveInvalidationReason,
    enable_reserve_block,
    initial_state,
    invalidate_unknown_delivery,
    pending_cells,
    progress_summary,
    record_dispatch,
    require_matching_state,
    verify_cell_run,
)
from redcell.gate_runner import (
    record_outcome as _persist_outcome,
)

FROZEN_PLAN = SeedPlan.model_validate_json(
    (Path(__file__).parents[1] / "docs" / "PHASE0_5_SEED_PLAN.json").read_text(encoding="utf-8")
)


def _plan(**updates):
    payload = {
        "max_attempts": 500,
        "database_url": "sqlite:///runs/phase-0-5.db",
        "report_directory": "runs/phase-0-5",
    }
    payload.update(updates)
    return build_gate_plan(FROZEN_PLAN, **payload)


def test_matrix_dry_run_survives_legacy_windows_output_encoding(tmp_path) -> None:
    plan_path = tmp_path / "plan.json"
    state_path = tmp_path / "state.json"
    plan_path.write_text(_plan().model_dump_json(indent=2), encoding="utf-8")
    environment = os.environ.copy()
    environment["PYTHONIOENCODING"] = "cp1252"

    completed = subprocess.run(
        [
            sys.executable,
            str(Path(__file__).parents[1] / "scripts" / "run_gate_matrix.py"),
            "--plan",
            str(plan_path),
            "--state",
            str(state_path),
            "--dry-run",
        ],
        cwd=Path(__file__).parents[1],
        env=environment,
        capture_output=True,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr.decode("utf-8", errors="replace")
    assert "待执行 72 格" in completed.stdout.decode("utf-8")


def record_outcome(state: MatrixState, **kwargs) -> MatrixState:
    """Tests model the mandatory dispatch write before a cell can complete."""
    state = record_dispatch(state, seed=kwargs["seed"], condition=kwargs["condition"])
    kwargs.setdefault(
        "run_id",
        next(
            cell.run_id for cell in state.cells if cell.key == (kwargs["seed"], kwargs["condition"])
        ),
    )
    return _persist_outcome(state, **kwargs)


def _complete_block(state: MatrixState, seed: int) -> MatrixState:
    for condition in GateCondition:
        state = record_outcome(state, seed=seed, condition=condition, exit_code=0)
    return state


def _fail_block(state: MatrixState, seed: int) -> MatrixState:
    return record_outcome(
        state,
        seed=seed,
        condition=GateCondition.STATIC_OFF,
        exit_code=3,
    )


def test_initial_state_covers_every_planned_cell() -> None:
    plan = _plan()
    state = initial_state(plan)

    assert len(state.cells) == len(plan.cells) == 120
    assert all(cell.status is CellStatus.PENDING for cell in state.cells)


def test_matrix_script_invokes_the_redcell_cli_module() -> None:
    """计划记录的是 console script，不得误转成不存在的 `python -m run`。"""
    cell = _plan().cells[0]

    argv = _command_for(cell)

    assert argv[1:4] == ["-m", "redcell.cli", "run"]
    assert argv[4:] == cell.argv[2:]


def test_only_primary_cells_are_dispatched_before_a_reserve_is_enabled() -> None:
    """备用 seed 不得自动上场 —— 补位与否是要人看过失效原因才能定的判断。"""
    plan = _plan()
    state = initial_state(plan)

    ready = pending_cells(plan, state, limit=96)

    assert len(ready) == 72
    assert {cell.seed_role for cell in ready} == {SeedRole.PRIMARY}


def test_disabled_reserve_cannot_be_dispatched_through_the_low_level_interface() -> None:
    plan = _plan()
    reserve = next(cell for cell in plan.cells if cell.seed_role is SeedRole.RESERVE)

    with pytest.raises(ValueError, match="当前未启用"):
        record_dispatch(initial_state(plan), seed=reserve.seed, condition=reserve.condition)


def test_cells_are_dispatched_in_frozen_plan_order() -> None:
    """同一 block 的六个条件挨着跑,外部条件才尽可能接近 —— 成对比较的前提。"""
    plan = _plan()
    state = initial_state(plan)

    ready = pending_cells(plan, state, limit=6)

    assert len({cell.seed for cell in ready}) == 1
    assert [cell.condition for cell in ready] == [cell.condition for cell in plan.cells[:6]]


def test_a_failed_cell_takes_its_whole_block_out(caplog) -> None:
    """⭐ 失效单位是 block 不是 cell。

    只重跑失败那一格,会让这个 block 各条件的运行时刻不再可配对,
    而 Gate 的统计量正是成对的。
    """
    plan = _plan()
    seed = plan.cells[0].seed
    state = initial_state(plan)
    state = record_outcome(state, seed=seed, condition=GateCondition.STATIC_OFF, exit_code=0)

    state = record_outcome(state, seed=seed, condition=GateCondition.LLM_MEMORY, exit_code=3)

    view = state.block(seed)
    assert view.invalid
    assert not view.usable
    assert view.failed == 1
    # 已完成的那一格保留原状,未跑的四格标为不再派发 —— 两者必须分得开。
    assert view.completed == 1
    assert view.skipped == 4
    assert not any(cell.seed == seed for cell in pending_cells(plan, state, limit=96))


def test_other_blocks_keep_running_after_one_fails() -> None:
    plan = _plan()
    failed_seed = plan.cells[0].seed
    state = record_outcome(
        initial_state(plan), seed=failed_seed, condition=GateCondition.STATIC_OFF, exit_code=3
    )

    ready = pending_cells(plan, state, limit=96)

    assert ready
    assert failed_seed not in {cell.seed for cell in ready}


def test_completed_cells_are_never_dispatched_again() -> None:
    """重跑会造出同一 seed×condition 的第二条记录,而 Gate 拒绝重复单元格。"""
    plan = _plan()
    seed = plan.cells[0].seed
    state = record_outcome(
        initial_state(plan), seed=seed, condition=GateCondition.STATIC_OFF, exit_code=0
    )

    ready = pending_cells(plan, state, limit=96)

    assert (seed, GateCondition.STATIC_OFF) not in {(c.seed, c.condition) for c in ready}


def test_crash_after_dispatch_invalidates_the_whole_block() -> None:
    """A child may have run, but without a durable outcome it must never be guessed or reused."""
    plan = _plan()
    cell = plan.cells[0]
    state = record_dispatch(
        initial_state(plan), seed=cell.seed, condition=cell.condition, run_id="preassigned-run"
    )

    recovered = invalidate_unknown_delivery(state)

    record = next(item for item in recovered.cells if item.key == (cell.seed, cell.condition))
    assert record.status is CellStatus.FAILED
    assert record.run_id == "preassigned-run"
    assert recovered.block(cell.seed).skipped == 5


def test_crash_recovery_resolves_every_dispatched_cell_in_the_batch() -> None:
    plan = _plan()
    batch = plan.cells[:3]
    state = initial_state(plan)
    for index, cell in enumerate(batch):
        state = record_dispatch(
            state,
            seed=cell.seed,
            condition=cell.condition,
            run_id=f"preassigned-run-{index}",
        )

    recovered = invalidate_unknown_delivery(state)

    assert not any(cell.status is CellStatus.DISPATCHED for cell in recovered.cells)
    assert recovered.block(batch[0].seed).failed == 3
    assert recovered.block(batch[0].seed).skipped == 3


def test_reserve_activation_records_reason_and_prior_state_digest() -> None:
    plan = _plan()
    primary_seed = next(cell.seed for cell in plan.cells if cell.seed_role is SeedRole.PRIMARY)
    state = _fail_block(initial_state(plan), primary_seed)
    reserve_seed = next(cell.seed for cell in plan.cells if cell.seed_role is SeedRole.RESERVE)
    before = state.state_digest()

    activated = enable_reserve_block(
        state,
        reserve_seed,
        reason=ReserveInvalidationReason.INFRASTRUCTURE,
        summary="provider outage reviewed",
    )

    assert activated.reserve_activations[0].reason is ReserveInvalidationReason.INFRASTRUCTURE
    assert activated.reserve_activations[0].summary == "provider outage reviewed"
    assert activated.reserve_activations[0].state_digest_before == before


def test_a_normal_run_with_findings_keeps_its_block_usable() -> None:
    """Finding 是实验结果，不是失败；CLI 用退出码 1 表示这种正常完成。"""
    plan = _plan()
    seed = plan.cells[0].seed

    state = record_outcome(
        initial_state(plan), seed=seed, condition=GateCondition.STATIC_OFF, exit_code=1
    )

    assert state.block(seed).completed == 1
    assert not state.block(seed).invalid
    assert any(cell.seed == seed for cell in pending_cells(plan, state, limit=96))


def test_a_cell_cannot_have_its_outcome_overwritten() -> None:
    plan = _plan()
    seed = plan.cells[0].seed
    state = record_outcome(
        initial_state(plan), seed=seed, condition=GateCondition.STATIC_OFF, exit_code=0
    )

    with pytest.raises(ValueError, match="已有状态"):
        record_outcome(state, seed=seed, condition=GateCondition.STATIC_OFF, exit_code=3)


def test_enabling_a_reserve_block_puts_exactly_that_block_in_play() -> None:
    plan = _plan()
    reserve_seed = next(c.seed for c in plan.cells if c.seed_role is SeedRole.RESERVE)
    primary_seed = next(c.seed for c in plan.cells if c.seed_role is SeedRole.PRIMARY)
    state = enable_reserve_block(
        _fail_block(initial_state(plan), primary_seed),
        reserve_seed,
        reason=ReserveInvalidationReason.INFRASTRUCTURE,
        summary="infrastructure failure",
    )

    ready = pending_cells(plan, state, limit=96)
    reserve_ready = {cell.seed for cell in ready if cell.seed_role is SeedRole.RESERVE}

    assert reserve_ready == {reserve_seed}
    assert len(ready) == 72


def test_reserve_cannot_be_enabled_without_an_uncompensated_invalid_block() -> None:
    plan = _plan()
    reserve_seed = next(c.seed for c in plan.cells if c.seed_role is SeedRole.RESERVE)

    with pytest.raises(ValueError, match="没有尚未补位"):
        enable_reserve_block(
            initial_state(plan),
            reserve_seed,
            reason=ReserveInvalidationReason.INFRASTRUCTURE,
            summary="infrastructure failure",
        )


def test_a_primary_seed_cannot_be_enabled_as_reserve() -> None:
    plan = _plan()
    primary_seed = plan.cells[0].seed

    with pytest.raises(ValueError, match="不是备用 seed"):
        enable_reserve_block(
            initial_state(plan),
            primary_seed,
            reason=ReserveInvalidationReason.INFRASTRUCTURE,
            summary="infrastructure failure",
        )


def test_reserve_blocks_must_be_enabled_in_the_frozen_order() -> None:
    plan = _plan()
    reserve_seeds = list(
        dict.fromkeys(cell.seed for cell in plan.cells if cell.seed_role is SeedRole.RESERVE)
    )
    primary_seeds = list(
        dict.fromkeys(cell.seed for cell in plan.cells if cell.seed_role is SeedRole.PRIMARY)
    )
    state = _fail_block(initial_state(plan), primary_seeds[0])
    state = _fail_block(state, primary_seeds[1])

    with pytest.raises(ValueError, match=f"备用 seed {reserve_seeds[0]}"):
        enable_reserve_block(
            state,
            reserve_seeds[1],
            reason=ReserveInvalidationReason.INFRASTRUCTURE,
            summary="infrastructure failure",
        )

    state = enable_reserve_block(
        state,
        reserve_seeds[0],
        reason=ReserveInvalidationReason.INFRASTRUCTURE,
        summary="infrastructure failure",
    )
    state = enable_reserve_block(
        state,
        reserve_seeds[1],
        reason=ReserveInvalidationReason.INFRASTRUCTURE,
        summary="infrastructure failure",
    )
    assert state.enabled_reserve_seeds == reserve_seeds[:2]


def test_matrix_state_rejects_reserve_without_activation_provenance() -> None:
    plan = _plan()
    primary_seed = next(c.seed for c in plan.cells if c.seed_role is SeedRole.PRIMARY)
    reserve_seed = next(c.seed for c in plan.cells if c.seed_role is SeedRole.RESERVE)
    state = _fail_block(initial_state(plan), primary_seed)
    payload = state.model_dump(mode="python")
    payload["enabled_reserve_seeds"] = [reserve_seed]

    with pytest.raises(ValueError, match="activation 证据"):
        MatrixState.model_validate(payload)


def test_matrix_state_save_round_trips(tmp_path) -> None:
    state = initial_state(_plan())
    path = tmp_path / "matrix-state.json"

    _save(path, state)

    assert MatrixState.model_validate_json(path.read_text(encoding="utf-8")) == state


def test_failed_atomic_replace_preserves_the_previous_state(tmp_path, monkeypatch) -> None:
    path = tmp_path / "matrix-state.json"
    path.write_text("previous complete state", encoding="utf-8")

    def fail_replace(_source, _destination) -> None:
        raise OSError("simulated replace failure")

    monkeypatch.setattr("scripts.run_gate_matrix.os.replace", fail_replace)

    with pytest.raises(OSError, match="simulated"):
        _save(path, initial_state(_plan()))

    assert path.read_text(encoding="utf-8") == "previous complete state"
    assert not list(tmp_path.glob("*.tmp"))


def test_only_one_matrix_runner_can_own_a_state_file(tmp_path) -> None:
    state_path = tmp_path / "matrix-state.json"

    with (
        _exclusive_state_lock(state_path),
        pytest.raises(RuntimeError, match="独占锁"),
        _exclusive_state_lock(state_path),
    ):
        pytest.fail("second runner unexpectedly acquired the same state")


def test_state_from_a_different_plan_is_refused() -> None:
    """续跑时把上一版计划的进度当成这一版,会得到一批混了两套条件的数据。"""
    plan = _plan()
    other = _plan(database_url="sqlite:///runs/other.db")
    state = initial_state(plan)

    require_matching_state(plan, state)
    with pytest.raises(ValueError, match="数据库不一致"):
        require_matching_state(other, state)


def test_state_with_tampered_seed_role_is_refused() -> None:
    plan = _plan()
    state = initial_state(plan)
    tampered = state.model_copy(
        update={
            "cells": [
                state.cells[0].model_copy(update={"seed_role": SeedRole.RESERVE}),
                *state.cells[1:],
            ]
        }
    )

    with pytest.raises(ValueError, match="primary/reserve"):
        require_matching_state(plan, tampered)


def test_duplicate_cells_are_rejected_by_the_schema() -> None:
    plan = _plan()
    state = initial_state(plan)

    with pytest.raises(ValueError, match="不得出现两条记录"):
        MatrixState(
            seed_plan_digest=state.seed_plan_digest,
            database_url=state.database_url,
            cells=[state.cells[0], state.cells[0]],
        )


def test_twelve_usable_blocks_are_reported_as_ready_for_replay() -> None:
    plan = _plan()
    state = initial_state(plan)
    for seed in FROZEN_PLAN.primary:
        state = _complete_block(state, seed)

    summary = progress_summary(plan, state)

    assert len(state.usable_blocks) == 12
    assert "可以进入 validate-paths" in summary
    assert "72/72 completed" in summary


# ── 逐格核验 ─────────────────────────────────────────────────────────────


def _finished_run(
    cell,
    *,
    conditions_schema_version=None,
    **updates,
):
    from redcell.budget import BudgetLimit, BudgetLimits, BudgetUsage
    from redcell.protocols.run import (
        ArenaRunConfiguration,
        ExperimentConditions,
        GenerationMemoryConfiguration,
        GenerationMemoryLimits,
        GenerationMemoryMode,
        ProviderRunConfiguration,
        Run,
        RunStatus,
        SearchConfiguration,
    )
    from redcell.protocols.strategy import StrategyCatalogue
    from redcell.strategies import PHASE_0_STRATEGIES
    from redcell.versions import EXPERIMENT_CONDITIONS_SCHEMA_VERSION

    if conditions_schema_version is None:
        conditions_schema_version = EXPERIMENT_CONDITIONS_SCHEMA_VERSION

    provider = ProviderRunConfiguration(
        provider="p",
        base_url="https://p.invalid/v1",
        model="m",
        temperature=0.0,
        max_tokens=512,
        rpm=0,
        max_concurrency=1,
    )
    payload = {
        "status": RunStatus.COMPLETED,
        "stopped_by": BudgetLimit.TOKENS,
        "usage": BudgetUsage(
            prompt_tokens=200000,
            completion_tokens=120000,
            generator_prompt_tokens=100000,
            generator_completion_tokens=60000,
            target_prompt_tokens=100000,
            target_completion_tokens=60000,
        ),
    }
    payload.update(updates)
    return Run(
        target_name="t",
        policy_version="v1",
        adapter_type="arena",
        algorithm=cell.search.value,
        limits=BudgetLimits(max_attempts=500, max_total_tokens=cell.max_total_tokens),
        seed=cell.seed,
        experiment_conditions=ExperimentConditions(
            online=True,
            actor="customer_a",
            target=provider,
            attacker=provider,
            arena=ArenaRunConfiguration(
                defense="standard", enforce_permissions=True, enforce_confirmation=True
            ),
            strategy_catalogue=StrategyCatalogue(
                version="phase0.5-v1", strategies=PHASE_0_STRATEGIES
            ).condition_summary(),
            search=SearchConfiguration(selector=cell.search),
            generation_memory=(
                GenerationMemoryConfiguration(
                    mode=cell.cross_attempt_memory,
                    policy_version="bounded-relevant-v1",
                    limits=GenerationMemoryLimits(),
                )
                if cell.cross_attempt_memory is GenerationMemoryMode.BOUNDED_RELEVANT_V1
                else GenerationMemoryConfiguration(mode=cell.cross_attempt_memory)
            ),
            conditions_schema_version=conditions_schema_version,
        ),
        **payload,
    )


def test_a_run_that_reached_the_token_prefix_verifies() -> None:
    cell = _plan().cells[0]

    assert verify_cell_run(_finished_run(cell), cell) is None


def test_a_run_with_an_unverifiable_conditions_fingerprint_is_refused_immediately() -> None:
    """不能等 72 格跑完后才由最终 report 发现 schema provenance 缺失。"""
    cell = _plan().cells[0]
    run = _finished_run(cell)
    assert run.experiment_conditions is not None
    legacy_conditions = run.experiment_conditions.model_copy(
        update={"conditions_schema_version": None}
    )
    legacy_run = run.model_copy(update={"experiment_conditions": legacy_conditions})

    reason = verify_cell_run(legacy_run, cell)

    assert reason is not None
    assert "可复验" in reason


def test_a_run_stopped_by_something_other_than_tokens_is_refused() -> None:
    """⭐ 退出码看不出"耗尽的是哪一项"。

    墙钟或 attempt 上限停下的 Run 同样 exit 0/1,却到不了 320k 前缀 ——
    不当场拦下,它会一路装成 usable 直到约 32 小时后的 gate-report。
    """
    from redcell.budget import BudgetLimit

    cell = _plan().cells[0]
    run = _finished_run(cell, stopped_by=BudgetLimit.WALL_CLOCK)

    reason = verify_cell_run(run, cell)

    assert reason is not None
    assert "不是 Token" in reason


def test_a_run_short_of_the_checkpoint_is_refused() -> None:
    from redcell.budget import BudgetUsage

    cell = _plan().cells[0]
    run = _finished_run(
        cell,
        usage=BudgetUsage(
            prompt_tokens=100,
            completion_tokens=100,
            generator_prompt_tokens=50,
            generator_completion_tokens=50,
            target_prompt_tokens=50,
            target_completion_tokens=50,
        ),
    )

    assert "未达 checkpoint" in (verify_cell_run(run, cell) or "")


def test_role_and_total_token_ledgers_must_agree() -> None:
    """总账与三角色账不守恒 ⇒ 等 Token 比较的分母本身不可信。"""
    from redcell.budget import BudgetUsage

    cell = _plan().cells[0]
    run = _finished_run(
        cell,
        usage=BudgetUsage(
            prompt_tokens=200000,
            completion_tokens=120000,
            generator_prompt_tokens=100000,
            generator_completion_tokens=60000,
            target_prompt_tokens=100000,
            target_completion_tokens=59999,
        ),
    )

    assert "不一致" in (verify_cell_run(run, cell) or "")


def test_an_incomplete_run_is_refused() -> None:
    from redcell.protocols.run import RunStatus

    cell = _plan().cells[0]

    assert "不是 completed" in (
        verify_cell_run(_finished_run(cell, status=RunStatus.FAILED), cell) or ""
    )


def test_a_missing_run_is_refused() -> None:
    cell = _plan().cells[0]

    assert "找不到" in (verify_cell_run(None, cell) or "")


def test_exact_run_id_is_required_instead_of_treatment_matching() -> None:
    """条件相同也不能替代派发前持久化的精确 Run ID。"""
    plan = _plan()
    static_off, static_memory = plan.cells[0], plan.cells[1]
    run = _finished_run(static_memory)

    assert "Run ID" in (verify_cell_run(run, static_off, expected_run_id="the-dispatched-id") or "")
