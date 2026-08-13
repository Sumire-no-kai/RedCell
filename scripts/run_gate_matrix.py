"""执行 Phase 0.5 的 72-cell 矩阵 —— 薄执行壳,调度规则在 `redcell.gate_runner`。

    python scripts/run_gate_matrix.py --plan runs/gate-plan.json --state runs/gate-matrix-state.json
    python scripts/run_gate_matrix.py ... --dry-run          # 只打印将要执行什么
    python scripts/run_gate_matrix.py ... --enable-reserve <seed>

约 72 个长 Run、21 小时以上,所以**必须可中断续跑**:每格结束立即落 state,
重启后已完成的格子不再派发。

⚠️ **本脚本不做判断,只做执行。** 一个 cell 失败之后要不要启用备用 block、
那次失效是不是"允许补位"的类型(基础设施 / 未知 Token / 可靠性 / 完整性),
都由人看过再用 `--enable-reserve` 点名 —— 见 `gate_runner` 模块 docstring 规则 2。
"""

from __future__ import annotations

import argparse
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from redcell.gate_plan import GatePlan
from redcell.gate_runner import (
    NORMAL_RUN_EXIT_CODES,
    MatrixState,
    ReserveInvalidationReason,
    enable_reserve_block,
    initial_state,
    invalidate_unknown_delivery,
    pending_cells,
    progress_summary,
    record_dispatch,
    record_outcome,
    require_matching_state,
    verify_cell_run,
)
from redcell.storage import RunStore

# Target 并发上限为 3(GLM 实测:并发 3 零 429,并发 5 因排队反而更慢)。
DEFAULT_CONCURRENCY = 3

EXIT_VERIFICATION_FAILED = 90
"""逐格核验未通过时记入 state 的合成退出码。

刻意不复用 CLI 的任何退出码:进程本身是正常结束的,失败发生在**我们的核验**这一层。
两者混用会让事后分不清"CLI 报了错"和"CLI 说好了但产出不合格"。
"""


def _load_state(path: Path, plan: GatePlan) -> MatrixState:
    if not path.exists():
        return initial_state(plan)
    state = MatrixState.model_validate_json(path.read_text(encoding="utf-8"))
    require_matching_state(plan, state)
    return state


def _save(path: Path, state: MatrixState) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(state.model_dump_json(indent=2), encoding="utf-8")


def _command_for(cell, run_id: str | None = None) -> list[str]:
    """把计划中的 console-script argv 映射为当前解释器可执行的模块命令。

    `GatePlan` 故意记录用户可复制的 `redcell run …`；脚本执行时不能简单替换成
    `python -m run …`，后者会寻找名为 `run` 的顶层模块并立即退出。必须显式指定
    `redcell.cli`，否则 Python 的 exit 1 会伪装成 CLI 的正常 `FINDINGS=1`。
    """
    argv = (
        [sys.executable, "-m", "redcell.cli", *cell.argv[1:]]
        if cell.argv[0] == "redcell"
        else list(cell.argv)
    )
    if run_id is not None:
        argv.extend(["--run-id", run_id])
    return argv


def _run_cell(cell, log_dir: Path, run_id: str) -> tuple[int, str]:
    """执行一格,返回 (exit_code, 日志路径)。argv 原样取自 plan,不再拼接。"""
    log_dir.mkdir(parents=True, exist_ok=True)
    log_path = log_dir / f"{cell.condition.value}-seed{cell.seed}.log"
    argv = _command_for(cell, run_id)
    started = time.time()
    with log_path.open("w", encoding="utf-8") as handle:
        completed = subprocess.run(
            argv,
            stdout=handle,
            stderr=subprocess.STDOUT,
            check=False,
            env={"PYTHONUTF8": "1", "PYTHONIOENCODING": "utf-8", **_inherited_env()},
        )
    minutes = (time.time() - started) / 60
    print(
        f"    {cell.condition.value:<14} seed {cell.seed:<12} "
        f"exit={completed.returncode} {minutes:.1f}min"
    )
    return completed.returncode, str(log_path)


def _inherited_env() -> dict[str, str]:
    import os

    return dict(os.environ)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--state", type=Path, default=Path("runs/gate-matrix-state.json"))
    parser.add_argument("--log-dir", type=Path, default=Path("runs/phase-0-5/logs"))
    parser.add_argument("--concurrency", type=int, default=DEFAULT_CONCURRENCY)
    parser.add_argument("--dry-run", action="store_true", help="只打印将要执行的格子")
    parser.add_argument(
        "--enable-reserve",
        type=int,
        action="append",
        default=[],
        help="显式启用一个备用 seed 的整块;需人工确认失效属于允许补位的类型",
    )
    parser.add_argument(
        "--reserve-reason",
        choices=[reason.value for reason in ReserveInvalidationReason],
        help="启用备用 block 的预注册失效类别",
    )
    parser.add_argument(
        "--reserve-summary",
        default="",
        help="启用备用 block 的人工复核摘要；不得以 Finding 结果作为理由",
    )
    args = parser.parse_args()

    if args.concurrency < 1:
        print("并发数必须至少为 1", file=sys.stderr)
        return 2

    try:
        plan = GatePlan.model_validate_json(args.plan.read_text(encoding="utf-8"))
        state = _load_state(args.state, plan)
        if args.enable_reserve and (
            args.reserve_reason is None or not args.reserve_summary.strip()
        ):
            raise ValueError("--enable-reserve 必须同时提供 --reserve-reason 与 --reserve-summary")
        for seed in args.enable_reserve:
            state = enable_reserve_block(
                state,
                seed,
                reason=ReserveInvalidationReason(args.reserve_reason),
                summary=args.reserve_summary,
            )
            print(f"已启用备用 block: seed {seed}")
    except (OSError, ValueError) as exc:
        # 调度前的配置错误不该以 traceback 出现:操作者要的是"哪里不对",
        # 而不是栈。真正的执行故障仍按各自语义落进 state。
        print(f"计划或 state 被拒绝:{exc}", file=sys.stderr)
        return 2
    recovered = invalidate_unknown_delivery(state)
    if recovered != state:
        state = recovered
        print("检测到中断前已派发但未确认的 cell；该 seed block 已按未知交付失效。")
    _save(args.state, state)

    if args.dry_run:
        ready = pending_cells(plan, state, limit=len(plan.cells))
        print(f"待执行 {len(ready)} 格(不会执行任何调用):")
        for cell in ready[: args.concurrency * 2]:
            print(f"    {cell.condition.value:<14} seed {cell.seed}")
        if len(ready) > args.concurrency * 2:
            print(f"    … 其余 {len(ready) - args.concurrency * 2} 格")
        print()
        print(progress_summary(plan, state))
        return 0

    while True:
        batch = pending_cells(plan, state, limit=args.concurrency)
        if not batch:
            break
        for cell in batch:
            state = record_dispatch(state, seed=cell.seed, condition=cell.condition)
        # 这次写入发生在 ThreadPool 创建之前。崩溃会保守地作废整个 block，绝不把
        # "也许跑过"的进程结果拼回正式矩阵。
        _save(args.state, state)
        dispatched_ids = {
            (cell.seed, cell.condition): cell.run_id
            for cell in state.cells
            if cell.run_id is not None
        }
        print(f"=== 本批 {len(batch)} 格 ===")
        with ThreadPoolExecutor(max_workers=args.concurrency) as pool:
            results = list(
                pool.map(
                    lambda cell, run_ids=dispatched_ids: _run_cell(
                        cell,
                        args.log_dir,
                        run_ids[(cell.seed, cell.condition)],
                    ),
                    batch,
                )
            )
        # 逐格核验 runbook §5 的硬条件。退出码只说明进程正常结束,说明不了
        # "耗尽的是 Token 而不是墙钟/attempt 上限",而后者产出的 Run 到不了 320k 前缀。
        with RunStore(plan.database_url) as store:
            for cell, (exit_code, log_path) in zip(batch, results, strict=True):
                record = next(
                    record for record in state.cells if record.key == (cell.seed, cell.condition)
                )
                run = None
                reason = None
                if exit_code in NORMAL_RUN_EXIT_CODES:
                    run = store.get_run(record.run_id or "")
                    reason = verify_cell_run(
                        run,
                        cell,
                        expected_run_id=record.run_id,
                        expected_gate_context_fingerprint=state.gate_context_fingerprint,
                    )
                    if reason is not None:
                        print(f"    ✗ {cell.condition.value} seed {cell.seed}: {reason}")
                state = record_outcome(
                    state,
                    seed=cell.seed,
                    condition=cell.condition,
                    # 核验不过即按失败落账 —— 让整块当场退出,而不是等到 gate-report。
                    exit_code=exit_code if reason is None else EXIT_VERIFICATION_FAILED,
                    run_id=record.run_id,
                    detail=f"{log_path}" if reason is None else f"{log_path} — {reason}",
                    gate_context_fingerprint=(
                        run.gate_context_fingerprint()
                        if reason is None and run is not None
                        else None
                    ),
                )
        # 每批结束立刻落盘:崩溃时最多丢一批的进度,而不是整轮。
        _save(args.state, state)
        print(progress_summary(plan, state))
        print()

    print(progress_summary(plan, state))
    invalid = [view for view in state.blocks() if view.invalid]
    if invalid:
        print()
        print("⚠️ 有 block 失效。先看日志判断失效类型,再决定是否 --enable-reserve;")
        print("   不得因为 Finding 结果不好看而换 seed。")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
