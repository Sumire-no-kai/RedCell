# Phase 0.5e 正式矩阵运行手册:glm-4-32b Target,原生 FC v2

> 状态(2026-10-01 夜):矩阵已在 Windows 完成(144/144,24/24 block 有效,DEVLOG 2026-10-01,#93)。
> **下一步只做 §6:** 本机补齐 gate-report 需要的三份对照、replay,再出 `gate-report`。
>
> 旧状态(2026-09-30):Mac 上限速探测、controls、Gate 计划、preflight 与 dry-run 均已通过;Windows 按 §2–§4 执行。
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

- **名义预算:** 144 × 320k = 4,608 万 token(三角色合计)。这**不是硬上限**:用量在调用完成后才结算,
  每格最后一次调用会越过预算线。实际矩阵报告 4,654 万 token,超出约 1.00%(DEVLOG 2026-10-01 Step 23)。
- **费用:** 校准的 Target + Attacker 混合单价约 $0.107/百万 token,折算约 $5;LLM 条件里 Controller 的 token
  单价更高,估计总计 $5–8。即使全部按 Controller 输入价计,也不超过约 $14。
- **耗时:** 校准单进程约 503 token/秒;3 个 worker、Target 并发 3,约 9–13 小时。这是外推值
  (DEVLOG 2026-08-06 记过外推的坑),前 6–12 格跑完后用实测速度重估并记进 DEVLOG。

- **实际(2026-10-01):** 8 小时 39 分,报告 4,654 万 token,按冻结单价估算 $5.96;重试、放弃、429 均为 0。

## 6. 跑完之后:对照补齐、replay、gate-report

在 Windows 执行,正式数据库 `runs/phase-0-5e.db` 就在这台机器上。代码保持 §2.1 的 tag 版本,**不要在这一节结束前拉取会改代码的提交**。
`.env` 保持矩阵时的样子。每条命令都只跑一次;任何一步失败就停下来报告,不重跑、不改配置。

### 6.1 为什么要在矩阵之后补跑两份对照

`gate-report` 要求攻击方对照和 Controller 对照的运行配置与矩阵中**逐字段一致**,不一致就判为 environment mismatch。
- 攻击方对照上次是 2026-09-23 在 Mac 上跑的,之后 Attacker 的计费覆盖声明改过,对不上。
- Controller 对照(2026-09-28)的产物在 Mac 上,含模型输出,按私有仓库边界不能传输。

所以两份都在 Windows 本机按矩阵配置各跑一次。它们检验的是两个角色的契约是否成立,与矩阵结果无关。
结果不合格时 `gate-report` 会如实报出对应失败,**不为让它合格而重跑**。golden 不调用模型,本机重新生成。
controls 用 §3 那份(`controls-prematrix-windows`);阴性 raw Finding 为 0,所以不需要裁决文件。

### 6.2 命令

```powershell
# 零成本:Level-1 golden
.venv\Scripts\python.exe -m redcell.cli golden --out runs/phase-0-5e/golden.json

# 付费(DeepSeek,12 个固定 case,约几美分):Controller 契约对照,prompt 与矩阵默认一致
.venv\Scripts\python.exe -m redcell.cli controller-controls `
  --controller-prompt-version controller-prompt-v1 `
  --out runs/phase-0-5e/controller-controls.json

# 付费(OpenAI,7 条策略 × 5 条 = 35 次,约几美分):攻击方对照,样本数与 seed 用 gate-report 要求的默认值
.venv\Scripts\python.exe -m redcell.cli attacker-control `
  --samples 5 --seed 0 `
  --out runs/phase-0-5e/attacker-control
# 产物:runs/phase-0-5e/attacker-control/attacker-control-seed0.json

# 付费(只调 Target):对 320k 前缀里的每条不同攻击路径原样重放 5 次;中断后用同一条命令续跑
.venv\Scripts\python.exe -m redcell.cli validate-paths `
  --seed-plan-json docs/PHASE0_5E_SEED_PLAN.json `
  --db sqlite:///runs/phase-0-5e.db `
  --repeats 5 `
  --checkpoint runs/phase-0-5e/validation-checkpoint.json `
  --out runs/phase-0-5e/validation.json

# 零成本:最终 Gate 分析
.venv\Scripts\python.exe -m redcell.cli gate-report `
  --db sqlite:///runs/phase-0-5e.db `
  --seed-plan-json docs/PHASE0_5E_SEED_PLAN.json `
  --matrix-state-json runs/phase-0-5e/gate-matrix-state.json `
  --validation-json runs/phase-0-5e/validation.json `
  --controls-json runs/phase-0-5e/controls-prematrix-windows/controls.json `
  --utility-baseline-json docs/PHASE0_5E_UTILITY_BASELINE.json `
  --billing-evidence-json runs/phase-0-5e/billing-evidence.json `
  --golden-json runs/phase-0-5e/golden.json `
  --attacker-control-json runs/phase-0-5e/attacker-control/attacker-control-seed0.json `
  --controller-controls-json runs/phase-0-5e/controller-controls.json `
  --out runs/phase-0-5e/gate-report.json
```

- `validate-paths` 的费用取决于攻击路径条数:每条重放 5 次,按矩阵里每次尝试约 3,100 个 Target token 粗估,
  每 100 条路径约 155 万 token,约 $0.16。它只重放已记录的攻击对话,不调用 Attacker 或 Controller,
  用量单独报告,不计入矩阵的 320k。
- `gate-report` 不必传 `--utility-confirmation-*`(那是 Phase 0.5b 专用)和 `--controls-adjudication-json`(无 Finding)。
- verdict 只有 `SUPPORTED` / `NOT_SUPPORTED` / `INCOMPLETE` / `EXPERIMENT_INVALID` 四种。`INCOMPLETE` 表示缺证据或证据不匹配,
  报告里的 failure 列表会写明是哪一项;先按名字核对文件路径是否传对,**不得为改变 verdict 而重跑对照或替换输入**。

### 6.4 修正报告(gate-report 原生协议 bug 修复后,零成本)

原报告把合格的原生协议 controls 误判为 `controls_environment_mismatch`(DEVLOG 2026-10-02 Step 50)。修复合并后,
拉取最新 master,在**完全相同的输入**上重新生成一份修正报告,写到新文件,**原 `gate-report.json` 不覆盖、不删除**:

```powershell
.venv\Scripts\python.exe -m redcell.cli gate-report `
  --db sqlite:///runs/phase-0-5e.db `
  --seed-plan-json docs/PHASE0_5E_SEED_PLAN.json `
  --matrix-state-json runs/phase-0-5e/gate-matrix-state.json `
  --validation-json runs/phase-0-5e/validation.json `
  --controls-json runs/phase-0-5e/controls-prematrix-windows/controls.json `
  --utility-baseline-json docs/PHASE0_5E_UTILITY_BASELINE.json `
  --billing-evidence-json runs/phase-0-5e/billing-evidence.json `
  --golden-json runs/phase-0-5e/golden.json `
  --attacker-control-json runs/phase-0-5e/attacker-control/attacker-control-seed0.json `
  --controller-controls-json runs/phase-0-5e/controller-controls.json `
  --out runs/phase-0-5e/gate-report-corrected.json
```

- 不调用任何 Provider,也不重跑 controls、对照、replay 或矩阵;`.env` 保持原样。
- DEVLOG 记录:代码 commit、退出码、修正报告的 verdict 与 failure 列表原文、SHA-256,以及和原报告的逐项差异。
  `analysis.comparisons` 与 `analysis.mechanism` 应与原报告逐字段相同(修复不涉及它们),如有不同要单独写明。
- 预期只少 `controls_environment_mismatch` 一项;如果还有其他差异,停下来报告。

### 6.3 记录

DEVLOG 记:代码 commit;每条命令的起止时间与退出码;golden 结果;两份对照是否合格;replay 的路径条数、
复现率与用量;`gate-report` 的 verdict 与 failure 列表原文。原始数据库、trace、对照明细、validation 与 gate-report JSON
都留 Windows 忽略路径,公开仓库只放安全摘要。报告的研究解读另行进行。
