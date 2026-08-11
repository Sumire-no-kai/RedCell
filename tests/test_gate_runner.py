from __future__ import annotations

from pathlib import Path

import pytest
from scripts.run_gate_matrix import _command_for

from redcell.gate_analysis import GateCondition, SeedPlan
from redcell.gate_plan import SeedRole, build_gate_plan
from redcell.gate_runner import (
    CellStatus,
    MatrixState,
    enable_reserve_block,
    find_cell_run,
    initial_state,
    pending_cells,
    progress_summary,
    record_outcome,
    require_matching_state,
    verify_cell_run,
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


def _complete_block(state: MatrixState, seed: int) -> MatrixState:
    for condition in GateCondition:
        state = record_outcome(state, seed=seed, condition=condition, exit_code=0)
    return state


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
    state = enable_reserve_block(initial_state(plan), reserve_seed)

    ready = pending_cells(plan, state, limit=96)
    reserve_ready = {cell.seed for cell in ready if cell.seed_role is SeedRole.RESERVE}

    assert reserve_ready == {reserve_seed}
    assert len(ready) == 78


def test_a_primary_seed_cannot_be_enabled_as_reserve() -> None:
    plan = _plan()
    primary_seed = plan.cells[0].seed

    with pytest.raises(ValueError, match="不是备用 seed"):
        enable_reserve_block(initial_state(plan), primary_seed)


def test_reserve_blocks_must_be_enabled_in_the_frozen_order() -> None:
    plan = _plan()
    reserve_seeds = list(
        dict.fromkeys(cell.seed for cell in plan.cells if cell.seed_role is SeedRole.RESERVE)
    )
    state = initial_state(plan)

    with pytest.raises(ValueError, match=f"备用 seed {reserve_seeds[0]}"):
        enable_reserve_block(state, reserve_seeds[1])

    state = enable_reserve_block(state, reserve_seeds[0])
    state = enable_reserve_block(state, reserve_seeds[1])
    assert state.enabled_reserve_seeds == reserve_seeds[:2]


def test_state_from_a_different_plan_is_refused() -> None:
    """续跑时把上一版计划的进度当成这一版,会得到一批混了两套条件的数据。"""
    plan = _plan()
    other = _plan(database_url="sqlite:///runs/other.db")
    state = initial_state(plan)

    require_matching_state(plan, state)
    with pytest.raises(ValueError, match="数据库不一致"):
        require_matching_state(other, state)


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


def _finished_run(cell, **updates):
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
        ),
        **payload,
    )


def test_a_run_that_reached_the_token_prefix_verifies() -> None:
    cell = _plan().cells[0]

    assert verify_cell_run(_finished_run(cell), cell) is None


def test_a_run_stopped_by_something_other_than_tokens_is_refused() -> None:
    """⭐ 退出码看不出"耗尽的是哪一项"。

    墙钟或 attempt 上限停下的 Run 同样 exit 0/1,却到不了 320k 前缀 ——
    不当场拦下,它会一路装成 usable 直到 21 小时后的 gate-report。
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


def test_the_run_is_matched_by_treatment_not_by_recency() -> None:
    """同一 seed 有六个条件,取错会让核验通过而数据错位。"""
    plan = _plan()
    static_off, static_memory = plan.cells[0], plan.cells[1]
    runs = [_finished_run(static_memory), _finished_run(static_off)]

    found = find_cell_run(runs, static_off)

    assert found is not None
    assert found.experiment_conditions.search.selector is static_off.search
    assert found.experiment_conditions.generation_memory.mode is static_off.cross_attempt_memory
