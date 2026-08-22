#!/usr/bin/env bash
# Phase 0 消融矩阵：3 算法 × 2 预算点 × 3 seed = 18 个独立 run。
#
# 为什么是多进程分片而不是 orchestrator 内部并发：SearchController.select() 是单槽
# 状态机（上一次决策未 update()/abandon() 收尾就不准再选），并发选臂在统计上是
# batched bandit——另一种算法，不是加个锁。分片让每个进程各跑一个独立 Controller、
# 进程内部严格串行，拿到完全相同的加速而不动接口。见 DEVLOG 2026-08-06。
#
# 并发上限 3 由 GLM-4.7-FlashX 决定（实测：并发 3 零 429，并发 5 反而更慢因为排队）。
# 每批同时起 3 个、wait 到齐再起下一批，保证任意时刻在途 target 请求数 == 3。
set -euo pipefail

cd "$(dirname "$0")/.."

PY="./.venv/Scripts/python.exe"
OUT="runs/ablation"
LOG_DIR="runs/ablation/logs"
mkdir -p "$LOG_DIR"

# seed 必须与任何一次校准/彩排用过的不重叠（CONCEPTS §16.8 的隔离规则）。
# 权威来源是 redcell.db 的 runs 表，不是文本日志（后者的数字容易是行号误匹配）：
#   select distinct seed from runs;  →  截至 2026-08-06 为 11 / 21 / 9001。
SEEDS=(5000 5001 5002)

for budget in 20 100; do
  for algo in static random thompson; do
    echo "=== budget=$budget algo=$algo  (3 seeds in parallel) ==="
    pids=()
    for seed in "${SEEDS[@]}"; do
      PYTHONUTF8=1 "$PY" -m redcell.cli run \
        --online --algorithm "$algo" --budget "$budget" --seed "$seed" \
        --out "$OUT" \
        >"$LOG_DIR/${algo}-b${budget}-s${seed}.log" 2>&1 &
      pids+=("$!")
    done
    failed=0
    for pid in "${pids[@]}"; do
      wait "$pid" || failed=1
    done
    if (( failed != 0 )); then
      echo "    failed: budget=$budget algo=$algo; inspect $LOG_DIR" >&2
      exit 1
    fi
    echo "    done: budget=$budget algo=$algo"
  done
done

echo "=== 全部 18 个 run 完成 ==="
