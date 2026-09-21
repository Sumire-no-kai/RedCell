# RedCell 双设备交接快照（2026-09-21）

本文是 Windows 实验机与 macOS 开发机之间的判断交接点。它记录代码状态、实验结论边界、
本地证据索引和后续顺序。迁移时不得只转录成功率、单个指标或有利发现；必须连同失败、
缺失数据、限制和哈希一起同步。

## 1. 两台机器与两个仓库的职责

| 位置 | 职责 | 应保存 | 不应保存 |
| --- | --- | --- | --- |
| 公共 `RedCell` 仓库 | 代码、测试、公开文档、可审查的工程历史 | 源码、测试、`docs/DEVLOG.md`、本交接文件 | 内部 PRD、密钥、原始 run/trace/DB |
| 私有 `RedCell_Private_Data` 仓库 | 两台机器共享的内部事实来源 | `PRD.md`、`AGENTS.md`、研究综述、冻结 utility baseline、私有迁移清单 | `.env`、凭据、原始模型响应、大型运行数据库 |
| Windows 实验机 | 长时间运行与原始证据保管 | `.env`、run/trace、SQLite、checkpoint、完整报告、运行日志 | 不经摘要和校验就把原始数据当作跨机结论 |
| macOS 开发机 | 日常开发、review、离线测试 | 两个仓库的 clone、重建的 `.venv` | Windows `.venv`、Windows 绝对路径、真实运行凭据 |

私有仓库不是 secrets 仓库。Provider key 只留在 Windows；macOS 默认只能执行离线测试。

## 2. Git 与代码状态

- 公共主干快照：`origin/master` = `3fcc6bb60ec0946e70975577a9e8d84a89390221`。
- PR #57 已合并：Phase 0.5d 矩阵可靠性与证据完整性修复。
- PR #58 已合并：反馈驱动攻击者的接口接缝。它增加了可持续传递 observation、下一步意图、
  假设账本和预算的契约；**尚未接入正式 runner，也没有证明这种攻击者优于现有基线**。
- 待审分支：`fix/replay-checkpoint-recovery`；与最新主干的集成 commit 为 `982649b`。它在本交接时包含以下实现，需在同步后通过
  PR review 决定是否合并：
  1. replay 原子 checkpoint、锁、恢复、失败账本和 unknown usage 传播；
  2. provider-neutral 原生 Function Calling、结构化 tool call、`role=tool` 回传；
  3. 工具协议进入 Run/controls/GatePlan v3 身份，旧 v3 实验证据仍可验证；
  4. preflight 在付费矩阵前检查 Target、工具协议、utility context、aggregate 和逐任务回归；
  5. `controller-prompt-v2` 候选。它明确 reward-per-token 与探索目标，但不属于 Phase 0.5d，
     未进入正式 runner 结论，也未做行为有效性实验。
- 合并前质量门为 `801 passed`。接入 PR #58 后重新执行完整门禁：`852 passed in 46.83s`；
  Ruff lint、Ruff format check（147 files）与 Black check（132 files）全部通过。
- 公共分支已推送到 `origin/fix/replay-checkpoint-recovery`。自动创建 draft PR 时，GitHub 集成
  返回 403，且本机 `gh` token 已失效；因此本快照不把“分支已推送”写成“PR 已创建”。恢复
  GitHub 写权限后，使用 [预填 compare 页面](https://github.com/Sumire-no-kai/RedCell/compare/master...fix/replay-checkpoint-recovery?expand=1)
  创建 draft PR，建议标题为 `Add resumable replay and versioned experiment protocols`。
- 私有仓库 `git@github.com:Sumire-no-kai/RedCell_Private_Data.git` 已推送 `master@bedf688`；
  本地与 `origin/master` 一致。

另有两个旧 worktree，不需要复制到 macOS：

- `feat/feedback-loop-observation` 已通过 PR #58 合并，无待迁移源码。
- `codex/docs/redcell-paper-roadmap` 比主干落后且没有独有 commit；其唯一未提交研究定位记录已
  迁入连续开发日志和本交接。不要把这个旧 worktree 当作较新的项目状态。

## 3. Phase 0.5d 的最终证据边界

### 3.1 可下的结论

最终 Gate verdict 是 **`EXPERIMENT_INVALID`**。这说明冻结 Gate 的保护条件没有满足，当前结果
不能支持“LLM 自适应控制有效”，也不能支持“LLM 自适应控制无效”或“目标足够安全”。

正式矩阵完成了 144 个 primary cells；48 个 reserve cells 保持 pending。validation 对 96 条路径
各重放 5 次，共 480 个 trial，其中 137 次 reproduced。重放结果分布为：

| 5 次中复现次数 | 路径数 |
| ---: | ---: |
| 0 | 36 |
| 1 | 20 |
| 2 | 21 |
| 3 | 8 |
| 4 | 4 |
| 5 | 7 |

validation 有 8 个 `ProviderTransientError`，全部标记 `retry_safety=requires_reset`；Target usage 为
`usage_known=false`。已记录的非完整 usage 是 prompt 799,968、completion 111,305、cached input
404,480、USD 0.5266566。费用数值存在不代表账目完整，Gate 因此 fail closed。

### 3.2 必须整体保留的七项失败

以下是报告的完整 `protection_failures` 数组，缺少任何一项都会改变对实验的判断：

1. `cost_per_attack_path_failed`
2. `finding_category_coverage_failed`
3. `static_off_asr_drift`
4. `strategy_coverage_failed`
5. `utility_baseline_context_mismatch`
6. `utility_failed`
7. `validation_usage_unknown`

其中 baseline context mismatch 的复核结论是 Target model 从 `glm-4.7-flashx` 迁移到
`glm-4.7`，不是 codec v1/v2 损坏。正式 preflight 当时没有检查 utility baseline/context
兼容性，导致本可在矩阵前发现的问题直到最终 Gate 才出现。

### 3.3 必须整体保留的六项限制

1. Controller rationale 只是低强度自述，不是因果证据。
2. 跨模型 Token 相等不代表算力或金钱成本相等。
3. 结果只适用于冻结的 policy-known arena 与条件。
4. 配对 seed 样本是内部可证伪 Gate，不具备论文级统计功效。
5. attack-path identity 包含 `strategy_id`；策略分配更广可能增加路径数，却没有增加新的结构漏洞。
   必须同时解释 finding-signature breadth 与 strategy allocation。
6. benign Finding 需要独立裁决：确认的 detector false positive 使 Gate 失败；确认的目标自发违规
   只能描述性报告，不能事后补一个 rate threshold。

### 3.4 与攻击者架构怀疑的关系

Phase 0.5d 实际比较的是：已经用 LLM 生成消息以后，再加“LLM 选择策略”和有限跨尝试历史，
是否值得成本。它没有完整测到“持续维护事实与假设、诊断失败原因、直接决定下一次具体测试、
跨策略综合证据”的反馈驱动攻击者。

已确认的结构错位包括：Controller 的可执行输出主要是策略 ID；rationale 不传给 Generator；
历史是有限选择而非持续假设账本；跨尝试历史主要在开场注入；工具结果曾把无 error 近似为成功，
可能混淆等待确认与实际执行；推进轮数由策略预设。因此 0.5d 不能用来否定更完整的闭环方向。
这些事实也不证明放开以后一定会赢，增益必须由新实验验证。

## 4. 本地证据索引

以下原始文件留在 Windows，不进入任一 GitHub 仓库。SHA-256 用于之后确认分析针对的是同一份
证据；路径相对 Windows 的公共仓库根目录。

| 文件 | 字节 | SHA-256 |
| --- | ---: | --- |
| `runs/phase-0-5d.db` | 214,994,944 | `d2e85d8538e30ec814b0bb325a4ee364e91b107e1e45ecc13eed1998a84c2ab1` |
| `runs/phase-0-5d/gate-plan.json` | 143,929 | `d9b3c314e4a00960da1a32224eb75bbda717be05c7e46c69f7c29a0ba90090b5` |
| `runs/phase-0-5d/gate-matrix-state.json` | 50,174 | `fca39388a451d89a8b00f081d6714fa5241fdc55d890602d64f5b03a09074e28` |
| `runs/phase-0-5d/validation.checkpoint.json` | 101,232 | `58ece64e16a6ec5a81bea3af189b7a1ed136609a384c95634b36ddfe237111d8` |
| `runs/phase-0-5d/validation.json` | 32,374 | `21347cee2adf2e6d2f7c8f0d612087a5bac4ada01d7ddf947824a11833b4cd02` |
| `runs/phase-0-5d/gate-report.json` | 663,539 | `505d52d66651373bf626c4d8b972ae0282769a5e45656460bbfe66303aaf5b61` |

其他身份：checkpoint token = 160,000；gate context fingerprint =
`627d7a8c52b2202d57c40dc4d79cbbe13fe1ace07614c25f5543ffd4d9ef8970`；matrix state digest =
`9f9d68b60dae42575c335d452b583f6c9e176c1e69bf720ae4335e8a0c6b5ed2`；billing evidence digest =
`d2a9f05705550d3937ee061202ebb035e9982c1473b711602be05e4498df7c80`。

截至本快照，Windows 上没有活动的 `python`/`pythonw` 长运行进程。1 字节 `.lock` 文件只是
历史 marker；锁由操作系统持有与释放，不能仅凭 marker 判断任务仍在运行。

## 5. 未迁移且不需要迁移的内容

- `.env`、`.env.bak`：含真实凭据，只留 Windows。macOS 使用 `.env.example` 或无 `.env`。
- `.venv`：Windows 解释器与二进制不可用于 macOS，必须重建。
- `.tmp-tests/`：约 53 MB 的一次性测试数据库，不传输。
- `runs/`、`redcell.db`、trace、Provider 原始响应：可能敏感且体积大，默认不传输。
- 已合并且无独有 commit 的旧 worktree：不传输。

需要深度审计原始数据时，先明确具体文件和目的，再走加密的私有传输；不要把整个 `runs/`
上传到 GitHub，即使仓库是 private。

内部资料另有完整 Git bundle 备用：Windows 路径
`runs/device-handoff-2026-09-21/RedCell-internal.bundle`，102,726 bytes，SHA-256
`f9fbcf0e11bb7278117dc9c3da41db7ef4fcbe9db4e302b49263db8cfeba8d3f`。只有在 private GitHub
不可用时才通过可信 U 盘或加密私有通道传输；Mac 可执行
`git clone RedCell-internal.bundle RedCell_Private_Data`。该 bundle 包含完整历史到 `bedf688`。

## 6. macOS 开发机初始化

建议两个仓库并排克隆：

```bash
mkdir -p ~/Developer/redcell && cd ~/Developer/redcell
git clone git@github.com:Sumire-no-kai/RedCell.git
git clone git@github.com:Sumire-no-kai/RedCell_Private_Data.git
cd RedCell
git fetch origin
git switch fix/replay-checkpoint-recovery
```

从私有仓库复制内部事实来源，并在本 clone 的本地 exclude 中防止误提交：

```bash
cp ../RedCell_Private_Data/PRD.md ./PRD.md
cp ../RedCell_Private_Data/AGENTS.md ./AGENTS.md
cp ../RedCell_Private_Data/docs/RELATED_WORK.md ./docs/RELATED_WORK.md
cp ../RedCell_Private_Data/docs/PHASE0_5_UTILITY_BASELINE.json ./docs/PHASE0_5_UTILITY_BASELINE.json
```

这些路径也已进入公共仓库 `.gitignore`。不要复制私有仓库的 `.git` 目录进公共 clone。

使用 Python 3.12 重建环境；项目最低要求为 3.11：

```bash
cd ~/Developer/redcell/RedCell
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e '.[dev]'
python -m pytest -p no:cacheprovider
python -m ruff check .
python -m ruff format --check .
python -m black --check src tests
```

首次验证保持离线，不配置 Provider key，不启动正式实验。

## 7. 后续实验结果的跨机同步合同

Windows 每次完成或中止一项长运行后，在公共分支提交一份不含敏感内容的结果摘要。摘要必须由
原始结构化产物生成或逐字段核对，至少包含：

1. 实验 ID、UTC/AEST 时间窗、公共代码 commit、内部 PRD/配置文件 SHA-256；
2. provider/model 的非秘密身份、工具协议、Controller prompt、memory policy 与 schema version；
3. seed plan、GatePlan、matrix state、controls、baseline、validation、report 的哈希和 fingerprint；
4. 计划、完成、pending、censored、失败、重试数量，以及每类失败的 code/stage/retry safety；
5. query/token/cost usage 与 `usage_known`，未知值保留 UNKNOWN，不能填零；
6. utility、ASR、finding/path coverage、复现率及其分母；
7. **完整** `protection_failures`、`limitations`、preflight/controls 失败数组；
8. verdict 以及允许和禁止推出的结论；
9. Windows 原始文件相对路径、字节数、修改时间和 SHA-256；
10. 是否有仍在运行的进程、是否可安全 resume、下一步需要的是开发、重放还是作者决策。

同步规则：数组应整体复制，不能只挑代表项；失败数量与明细必须一致；未知和未运行必须显式写出；
协议、模型、baseline 或 prompt 改变时必须登记为新实验身份，不能静默并入旧实验。

## 8. 下一步顺序

1. 在 macOS clone 上 review 待审分支；Windows 已接入 `master` 并通过四道门，Mac 应复跑同一组
   离线检查以确认跨平台兼容，再决定是否合并 PR。
2. 不重写 Phase 0.5d，也不把 native Function Calling 或 Controller v2 算入旧实验。
3. 在独立开发场景验证 observation 是否忠实区分拒绝、等待确认、格式错误和实际执行，并验证
   下一步行为确实随反馈改变；只看模型自述不算通过。
4. 用同模型、同可见信息、同预算做小规模匹配对照：独立生成 vs. 反馈驱动生成；之后再分别消融
   持续记忆、规划和跨策略假设账本。
5. 只有机制验证显示行为与证据链有效，才预注册新的完整实验矩阵。Phase 0.5e 只回答工具协议
   敏感性，不能代替攻击者架构实验。

任何新结果若与本文冲突，应追加带证据的更正，不要静默改写这份快照。
