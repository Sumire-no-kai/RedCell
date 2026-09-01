# Phase 0.5d 运行手册：GLM-4.7 Target

> 状态：**修复代码与全新 seed 已登记；尚未获准发送新的 Provider 请求。**
> Phase 0.5c 的 24 个 primary seed 已被观察且整批失效。本手册不续跑、不复制 0.5c 的 runs、SQLite、
> trace、state 或 `.env`；它定义一个独立的 Phase 0.5d 实验。

## 已冻结的实验决策

- Target：`glm-4.7`，`temperature=0.7`、`max_tokens=512`、`thinking.type=disabled`。
- 六个 treatment 都在条件快照中声明同一 Controller HTTP timeout（当前配置默认 60 秒）。静态 treatment
  不会创建或调用 Controller；这是同一把 Gate 比较尺子，不是新增模型调用。
- shared SQLite limiter 保留 Target `max_concurrency=1`，并在任一子进程收到 429 后向全部子进程发布
  cooldown：优先采用 `Retry-After`，缺失时为 5/10/20/40/60 秒封顶。它是可靠性保护，不改变 treatment。
- `REDCELL_TARGET_RPM`：**OPEN，禁止保留为 0 或猜一个值。** 必须先在独立、获授权、有上限的 calibration
  中确定稳定值，再把该值与账户/时间证据冻结进 billing/preflight artifacts。
- Seed plan：`docs/PHASE0_5D_SEED_PLAN.json`，24 primary + 8 reserve，digest
  `0b8304d8a968c8982d632e11e135abc7f84989cadc17117283b9d33707567c66`。
- 运行根目录：`runs/phase-0-5d/`；正式数据库：`sqlite:///runs/phase-0-5d.db`；shared limiter 使用另一份
  新的 SQLite 文件，绝不复用 0.5c 的 limiter DB。

## 新主机准备和零成本门

从已合并的 `master` 获取代码；不要复制旧运行产物。建立环境并先通过四道零成本门：

```powershell
py -3.11 -m venv .venv
.venv\Scripts\python.exe -m pip install -e ".[dev]"
Copy-Item .env.example .env
.venv\Scripts\python.exe -m pytest -p no:cacheprovider
.venv\Scripts\python.exe -m ruff check .
.venv\Scripts\python.exe -m ruff format --check .
.venv\Scripts\python.exe -m black --check src tests
```

在 `.env` 经受信任渠道填入三角色凭据后，至少显式设置：

```text
REDCELL_TARGET_MODEL=glm-4.7
REDCELL_TARGET_MAX_CONCURRENCY=1
REDCELL_TARGET_RPM=<only-after-authorized-calibration>
REDCELL_TARGET_INPUT_USD_PER_MTOK=0.60
REDCELL_TARGET_CACHED_INPUT_USD_PER_MTOK=0.11
REDCELL_TARGET_OUTPUT_USD_PER_MTOK=2.20
REDCELL_TARGET_USAGE_COVERS_BILLED_TOKENS=true
REDCELL_SHARED_RATE_LIMIT_DB=sqlite:///runs/phase-0-5d-rate-limit.db
```

不要在 RPM 为 `0`、未校准、未有新的 Provider-call 授权时继续。RPM calibration、fresh controls、billing
evidence、preflight 和正式 matrix 是五道不同的门，任何一道通过都不自动替代下一道。

## 获得后续授权后的顺序

先在该主机、独立于正式 matrix seed 的范围内完成经授权的 RPM calibration，并记录模型、账户证据时间、
试验上限、429 与成功数；只有作者确认一个保守 RPM 后才写入 `.env`。然后重新跑 Provider controls：

```powershell
.venv\Scripts\python.exe -m redcell.cli controller-controls --out runs/phase-0-5d/controller-controls.json
.venv\Scripts\python.exe -m redcell.cli controls --out runs/phase-0-5d/controls
.venv\Scripts\python.exe -m redcell.cli attacker-control --samples 5 --seed 0 --out runs/phase-0-5d
.venv\Scripts\python.exe -m redcell.cli golden --out runs/phase-0-5d/golden.json
.venv\Scripts\python.exe -m redcell.cli controls-adjudication-template `
  --controls-json runs/phase-0-5d/controls/controls.json `
  --out runs/phase-0-5d/controls/adjudication.json
.venv\Scripts\python.exe -m redcell.cli billing-evidence-template `
  --out runs/phase-0-5d/billing-evidence.json
```

若 controls 有 raw Finding，必须先裁决每条 occurrence；任何 `unresolved` 或 detector false positive
阻止 matrix。随后生成 plan 与 preflight（两者不调用 Provider）：

```powershell
.venv\Scripts\python.exe -m redcell.cli gate-plan `
  --seed-plan-json docs/PHASE0_5D_SEED_PLAN.json `
  --max-attempts 500 `
  --db sqlite:///runs/phase-0-5d.db `
  --run-out runs/phase-0-5d `
  --out runs/phase-0-5d/gate-plan.json

.venv\Scripts\python.exe -m redcell.cli gate-preflight `
  --seed-plan-json docs/PHASE0_5D_SEED_PLAN.json `
  --db sqlite:///runs/phase-0-5d.db `
  --billing-evidence-json runs/phase-0-5d/billing-evidence.json `
  --out runs/phase-0-5d/preflight.json
```

只有 controls、billing、plan、preflight 都通过且作者给出新的 matrix 调用授权，才执行：

```powershell
# 只检查 plan/state，不调用 Provider
.venv\Scripts\python.exe scripts/run_gate_matrix.py `
  --plan runs/phase-0-5d/gate-plan.json `
  --state runs/phase-0-5d/gate-matrix-state.json `
  --dry-run

# 正式运行；中断后重复完全相同的命令，已完成 cell 不会重跑
.venv\Scripts\python.exe scripts/run_gate_matrix.py `
  --plan runs/phase-0-5d/gate-plan.json `
  --state runs/phase-0-5d/gate-matrix-state.json
```

禁止手工循环、禁止单 cell 重跑、禁止自动启用 reserve。一个 block 失效时先记录原因；只有审查确认的
可补位类别，才用 runner 的显式 `--enable-reserve <seed>` 启用完整 reserve block。144 个 primary cell
完成后再做 replay 与 `gate-report`，且只能以其 fail-closed verdict 声称研究结果。
