# Phase 0.5c 运行手册：GLM-4.7 Target（失效归档）

> 状态：**EXPERIMENT_INVALID（2026-09-01）**。复制的 matrix 运行出现 treatment 间 Gate context
> fingerprint 不一致（静态条件未声明 Controller timeout）及未被 shared limiter 协调的持续 429；24 个
> primary block 全部失效。不得运行、续跑、复制或分析下方命令生成的 0.5c 数据；原文保留仅用于审计。
> 请使用 `docs/PHASE0_5D_TEST_RUNBOOK.md` 的全新实验身份和全新 seed。

## 已冻结的决策

- Target：`glm-4.7`，`temperature=0.7`、`max_tokens=512`、`thinking.type=disabled`。
- Target 本地并发：**1**；尚无 GLM-4.7 账户并发额度的独立证据，禁止沿用 FlashX 的 2。
- Token 单价（USD / 1M）：input 0.60、cached input 0.11、output 2.20。
- Seed plan：`docs/PHASE0_5C_SEED_PLAN.json`，24 primary + 8 reserve，digest
  `264d3e0b5c035ab056d235506f2db0dee749268ad2e1d4b119887c1c0fb5dfad`。
- 运行根目录：`runs/phase-0-5c/`；正式数据库：`sqlite:///runs/phase-0-5c.db`。

## 在另一台 Windows 电脑准备

从合并后的 `master` 获取代码；不要复制旧 `runs/`、旧 SQLite、trace 或 `.env`。在新主机重新建立虚拟环境，
并仅通过受信任的渠道填写自己的 API key：

```powershell
py -3.11 -m venv .venv
.venv\Scripts\python.exe -m pip install -e ".[dev]"
Copy-Item .env.example .env
```

在 `.env` 填入三角色凭据，并将 Target 设置为：

```text
REDCELL_TARGET_MODEL=glm-4.7
REDCELL_TARGET_MAX_CONCURRENCY=1
REDCELL_TARGET_INPUT_USD_PER_MTOK=0.60
REDCELL_TARGET_CACHED_INPUT_USD_PER_MTOK=0.11
REDCELL_TARGET_OUTPUT_USD_PER_MTOK=2.20
REDCELL_TARGET_USAGE_COVERS_BILLED_TOKENS=true
```

同时配置一个**独立于正式 matrix DB** 的 `REDCELL_SHARED_RATE_LIMIT_DB`。矩阵前保持电脑接电、网络稳定，
并让 runner 保持前台；执行器会自行持有 Windows wake lock。

## 每台新主机的开跑顺序

先跑零成本门：

```powershell
.venv\Scripts\python.exe -m pytest -p no:cacheprovider
.venv\Scripts\python.exe -m ruff check .
.venv\Scripts\python.exe -m ruff format --check .
.venv\Scripts\python.exe -m black --check src tests
```

随后在**该主机**重新运行 Provider controls；它们会付费，但不使用正式 Gate seed：

```powershell
.venv\Scripts\python.exe -m redcell.cli controller-controls --out runs/phase-0-5c/controller-controls.json
.venv\Scripts\python.exe -m redcell.cli controls --out runs/phase-0-5c/controls
.venv\Scripts\python.exe -m redcell.cli attacker-control --samples 5 --seed 0 --out runs/phase-0-5c
.venv\Scripts\python.exe -m redcell.cli golden --out runs/phase-0-5c/golden.json
.venv\Scripts\python.exe -m redcell.cli controls-adjudication-template `
  --controls-json runs/phase-0-5c/controls/controls.json `
  --out runs/phase-0-5c/controls/adjudication.json
```

若 controls 出现 raw Finding，必须先对每条 occurrence 做独立裁决；未决或 detector false positive 都阻止矩阵。

从当前 `.env` 生成 billing evidence 模板，并按官方资料/账户证据填写后再继续。模板包含 no secret 的模型、
pricing、thinking 与 runtime cap，但不自动证明 coverage：

```powershell
.venv\Scripts\python.exe -m redcell.cli billing-evidence-template `
  --out runs/phase-0-5c/billing-evidence.json
```

生成计划和 preflight（均不调用 Provider）：

```powershell
.venv\Scripts\python.exe -m redcell.cli gate-plan `
  --seed-plan-json docs/PHASE0_5C_SEED_PLAN.json `
  --max-attempts 500 `
  --db sqlite:///runs/phase-0-5c.db `
  --run-out runs/phase-0-5c `
  --out runs/phase-0-5c/gate-plan.json

.venv\Scripts\python.exe -m redcell.cli gate-preflight `
  --seed-plan-json docs/PHASE0_5C_SEED_PLAN.json `
  --db sqlite:///runs/phase-0-5c.db `
  --billing-evidence-json runs/phase-0-5c/billing-evidence.json `
  --out runs/phase-0-5c/preflight.json
```

所有门通过且作者再次明确授权后，才启动 matrix：

```powershell
# 零成本检查计划和 state
.venv\Scripts\python.exe scripts/run_gate_matrix.py `
  --plan runs/phase-0-5c/gate-plan.json `
  --state runs/phase-0-5c/gate-matrix-state.json `
  --dry-run

# 正式执行；中断后以完全相同命令继续，已完成 cell 不会重跑
.venv\Scripts\python.exe scripts/run_gate_matrix.py `
  --plan runs/phase-0-5c/gate-plan.json `
  --state runs/phase-0-5c/gate-matrix-state.json
```

禁止手工循环、禁止只重跑单个失败 cell、禁止自动启用 reserve。整块失效后，先记录原因，再按既有
reserve 规则显式启用下一整个 seed block。完成 144 个 primary cell 后，再执行 replay 与 `gate-report`；
只能以其 fail-closed verdict 声称研究结果。
