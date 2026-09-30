# Phase 0.5e 正式矩阵运行手册:glm-4-32b Target,原生 FC v2

> 状态(2026-09-30):Mac 上限速探测、controls、Gate 计划、preflight 与 dry-run 均已通过(DEVLOG 2026-09-30)。
> Windows 按 §2 准备、§3 跑本机 controls 与 preflight,全部通过后等作者确认再按 §4 开跑。
>
> 本手册只定义**操作**。Gate 判定合同沿用 0.5d(PRD Phase 0.5e 一节),结果只以 `gate-report` 的 verdict 为准。

## 1. 已冻结的条件

| 项 | 取值 |
|---|---|
| 代码 | 校准 tag `phase-0.5e-arena-calibrated-2026-09-29`(`f68b2d5`)。master 在它之后只改了文档;开跑前按 §2.1 核对 |
| 登记 | `docs/PHASE0_5E_SEED_PLAN.json`,24 primary + 8 reserve,digest `d5c43f6f…`;6 个条件 × 24 = 144 个主单元 |
| 每格 | `max_attempts=500`,`max_total_tokens=320000`(三个角色合计),标准防御,`native-function-calling-v2` |
| Target | `glm-4-32b-0414-128k`,temperature 0.7,max_tokens 512,**并发 3、RPM 0**(2026-09-30 作者决定,见 DEVLOG) |
| Attacker | `gpt-6-luna`,temperature 1.0,`reasoning_effort=none`,并发 3 |
| Controller | `deepseek-flash`,thinking disabled,并发 3 |
| utility 基线 | `docs/PHASE0_5E_UTILITY_BASELINE.json`(163/200,下限 143,context `c204b86f…`) |
| 计费证据 | 三个角色均已对账;Target 批准并发 3、RPM 0 |

## 2. Windows 准备(零成本)

### 2.1 代码

```powershell
git switch master
git pull --ff-only
git fetch --tags
git diff --stat phase-0.5e-arena-calibrated-2026-09-29 HEAD -- . ':!docs'   # 必须为空
git rev-parse HEAD   # 记进 DEVLOG
```

### 2.2 私有仓库文件

从 `RedCell_Private_Data` 拉最新,核对 `MANIFEST.sha256` 后复制:

| 私有仓库 | 复制到公开仓库 |
|---|---|
| `docs/PHASE0_5E_UTILITY_BASELINE.json` | `docs/PHASE0_5E_UTILITY_BASELINE.json` |
| `docs/PHASE0_5E_BILLING_EVIDENCE.json` | `runs/phase-0-5e/billing-evidence.json` |

两个目标路径都被 `.gitignore` 覆盖,不要提交。

### 2.3 `.env`

`.env` 不在 git 里。与校准时相比,**必须改的只有一项**:

```text
REDCELL_TARGET_MAX_CONCURRENCY=3
```

此外核对下列键与 Mac 一致(不要打印 key 的值);preflight 会逐项比对,但先人工核对省一次来回:

```text
REDCELL_TARGET_RPM=0 / USAGE_COVERS_BILLED_TOKENS=true
REDCELL_ATTACKER_MAX_CONCURRENCY=3 / USAGE_COVERS_BILLED_TOKENS=true
REDCELL_CONTROLLER_PROVIDER / BASE_URL / MODEL=deepseek-flash / EXTRA_BODY(thinking disabled)
REDCELL_CONTROLLER_MAX_CONCURRENCY=3 / USAGE_ACCOUNTING_MODE=total-minus-prompt-v1 / USAGE_COVERS_BILLED_TOKENS=true
REDCELL_CONTROLLER_*_USD_PER_MTOK(0.30 / 1.20 / 0.006)
REDCELL_SHARED_RATE_LIMIT_DB
```

`REDCELL_ATTACKER_API_KEY` 若写成 `${OPENAI_API_KEY}` 引用,被引用的变量必须在同一文件更前面定义;直接写字面值更稳。

### 2.4 电源

长时间运行前把电源计划设为不休眠、不关闭硬盘。matrix runner 自带唤醒锁,但不能防止手动睡眠或重启。

## 3. Windows 本机 controls 与 preflight

controls 产物含模型回复,不能经私有仓库传输,所以 Windows 本机跑一轮(约 16 分钟、约 $0.1)。
**这一轮就是 Windows preflight 使用的那份;无论结果如何都不为挑选而重跑。** 不过下限或逐任务检查时,
矩阵暂停,交作者决定。

```powershell
.venv\Scripts\python.exe -m redcell.cli controls `
  --tool-call-protocol native-function-calling-v2 `
  --out runs/phase-0-5e/controls-prematrix-windows

.venv\Scripts\python.exe -m redcell.cli gate-plan `
  --seed-plan-json docs/PHASE0_5E_SEED_PLAN.json `
  --max-attempts 500 `
  --db sqlite:///runs/phase-0-5e.db `
  --out runs/phase-0-5e/gate-plan.json

.venv\Scripts\python.exe -m redcell.cli gate-preflight `
  --seed-plan-json docs/PHASE0_5E_SEED_PLAN.json `
  --db sqlite:///runs/phase-0-5e.db `
  --billing-evidence-json runs/phase-0-5e/billing-evidence.json `
  --controls-json runs/phase-0-5e/controls-prematrix-windows/controls.json `
  --utility-baseline-json docs/PHASE0_5E_UTILITY_BASELINE.json `
  --gate-plan-json runs/phase-0-5e/gate-plan.json `
  --out runs/phase-0-5e/preflight.json

.venv\Scripts\python.exe scripts/run_gate_matrix.py `
  --plan runs/phase-0-5e/gate-plan.json `
  --state runs/phase-0-5e/gate-matrix-state.json `
  --dry-run
```

- controls 若出现阴性 raw Finding,先用 `controls-adjudication-template` 生成裁决模板并逐条裁决;
  任何 `unresolved` 或检测器误报都阻止矩阵。
- preflight 需 16 项全 PASS;dry-run 应显示 `cells 0/144 completed`、`24 primary`。
- 生成的 `gate-plan.json` 应为 144 primary + 48 reserve(disabled),`seed_plan_digest` 以 `d5c43f6f` 开头。

## 4. 正式矩阵(作者确认后)

```powershell
.venv\Scripts\python.exe scripts/run_gate_matrix.py `
  --plan runs/phase-0-5e/gate-plan.json `
  --state runs/phase-0-5e/gate-matrix-state.json
```

- 中断后**重复完全相同的命令**,已完成的格子不会重跑。
- 禁止手工循环、禁止单格重跑、禁止自动启用 reserve。某个 block 失效时先记录原因;只有复核确认属于
  infrastructure / unknown_token / reliability / integrity 四类之一,才用 `--enable-reserve <seed>
  --reserve-reason <类别> --reserve-summary "<人工摘要>"` 启用整块 reserve,理由不得引用 Finding 结果。
- 默认 3 个 worker;不要调大(Target 批准并发就是 3)。

## 5. 预计耗时与费用(粗估,开跑后以实测为准)

- **上限(硬):** 144 × 320k = 4,608 万 token(三角色合计)。
- **费用:** 校准的 Target + Attacker 混合单价约 $0.107/百万 token,折算约 $5;LLM 条件里 Controller 的 token
  单价更高,估计总计 $5–8。即使全部按 Controller 输入价计,也不超过约 $14。
- **耗时:** 校准单进程约 503 token/秒;3 个 worker、Target 并发 3,约 9–13 小时。这是外推值
  (DEVLOG 2026-08-06 记过外推的坑),前 6–12 格跑完后用实测速度重估并记进 DEVLOG。

## 6. 跑完之后

- 在 DEVLOG 记:代码 commit、开始/结束时间、完成格数、失效 block 及原因、是否启用 reserve、429 与重试计数、
  报告的 token 与估算费用。原始数据库、trace、日志留在 Windows,不提交、不放私有仓库。
- 144 个主单元完成后再做 replay(`validate-paths`)与 `gate-report`;这两步的命令与判读另行确定。
