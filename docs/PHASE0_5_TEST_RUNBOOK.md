# Phase 0.5 正式测试 Runbook

本文件只描述如何准备和执行已经冻结的 Phase 0.5 Gate。工程测试通过不等于研究结论
`SUPPORTED`；在下列冻结项全部完成前，状态始终是 **INCOMPLETE / DO NOT START**。

## 1. 开跑前冻结清单

- [x] `attack_path_signature` 保持主指标，并强制联读结构签名与策略分配。
- [x] factorial 主效应使用对称对照均值。
- [x] 三类价格缺失均为 `N/A`；显式 0 才表示确认免费。
- [x] 正式 `max_attempts=500`；默认 20 不得用于正式 Run。
- [x] `level1-golden-v1` 已冻结为 10 正/10 负 fixture 与 canonical digest。
- [x] `docs/PHASE0_5_SEED_PLAN.json` 已冻结 12 primary + 4 reserve；canonical digest 为 `af55c0f179a566ae0b8437b85dbfd9043eb2e24e157eeffacf21adb68731d1bc`。
- [ ] 冻结 Target、Attacker、Controller、temperature、pricing、arena 与可靠性配置；不在本文或产物中记录密钥。
- [ ] 使用全新的、仅服务本次矩阵的 SQLite 数据库；不得混用 `redcell.db` 或开发/试跑数据库。

任一项未完成都不得执行正式 seed。reserve 只在整个 paired block 因基础设施、未知 Token、
可靠性或完整性失效时按冻结顺序补位；不得因 Finding 结果替换 seed。

## 2. 零成本工程门

以下命令不调用 Provider：

```powershell
.venv\Scripts\python.exe -m pytest -p no:cacheprovider
.venv\Scripts\python.exe -m ruff check .
.venv\Scripts\python.exe -m ruff format --check .
.venv\Scripts\python.exe -m black --check src tests
```

四道门缺一不可。随后确认工作树、分支和待执行提交与获批版本一致。

## 3. 生成矩阵清单，不执行

使用版本控制中已经冻结的 seed plan 生成 declarative plan：

```powershell
.venv\Scripts\python.exe -m redcell.cli gate-plan `
  --seed-plan-json docs/PHASE0_5_SEED_PLAN.json `
  --max-attempts 500 `
  --db sqlite:///runs/phase-0-5.db `
  --run-out runs/phase-0-5 `
  --out runs/gate-plan.json
```

该命令只输出 72 个 primary cell 和 24 个默认禁用的 reserve cell，不打开数据库、不读取
`.env`、不调用 Provider。每个 cell 都固定 `max_total_tokens=320000`，并把 argv 作为数组保存，
避免 shell quoting 改写参数。生成后人工复核六种条件各出现一次：

1. Static × memory off
2. Static × bounded-relevant-v1
3. LLM Controller × bounded-relevant-v1
4. LLM Controller × memory off
5. Random × memory off
6. Thompson × memory off

## 4. 正式 seed 之前的 Provider 对照

这些命令会调用对应 Provider、产生费用或消耗配额，但不使用正式 Gate seed：

```powershell
.venv\Scripts\python.exe -m redcell.cli controller-controls --out runs/controller-controls.json
.venv\Scripts\python.exe -m redcell.cli controls --out runs/controls
.venv\Scripts\python.exe -m redcell.cli attacker-control --samples 5 --seed <NON_GATE_SEED> --out runs
```

三份报告必须通过且配置快照与正式 plan 一致。Level-1 golden 是零 Provider 的独立固定考卷：

```powershell
.venv\Scripts\python.exe -m redcell.cli golden `
  --fixtures tests/fixtures/level1-golden-v1.json `
  --out runs/golden.json
```

不能把普通单元测试数量或在线 controls 伪装成 golden 证据。

## 5. 执行与实时检查

只执行 `gate-plan.json` 中 `enabled_initially=true` 的 72 个 argv。每个 cell 完成后立即检查：

- Run 为 `COMPLETED`，停止原因为 Token，且达到 320k 前缀；
- 三角色 usage 已知且账本一致；
- experiment fingerprint、regression context 与 Gate context 未发生非治疗条件漂移；
- 没有重复 seed-condition cell；
- run/trace/findings 产物保持本地且不进入 Git。

发现单 cell 无效时，保留原记录，整组六条件 seed 都退出主要分析，再启用下一整个 reserve block。
不要只重跑失败条件，也不要继续执行尚未需要的 reserve。

## 6. 重放与最终 Gate

72 个有效 cell 齐全后，重放 320k 前缀中实际观察到的攻击路径。该命令只加载 Target，
不会加载 Attacker 或 Controller，并拒绝不完整、重复、计划外或环境混杂的矩阵：

```powershell
.venv\Scripts\python.exe -m redcell.cli validate-paths `
  --seed-plan-json docs/PHASE0_5_SEED_PLAN.json `
  --db sqlite:///runs/phase-0-5.db `
  --repeats 5 `
  --out runs/validation.json
```

最后组合全部冻结证据：

```powershell
.venv\Scripts\python.exe -m redcell.cli gate-report `
  --db sqlite:///runs/phase-0-5.db `
  --seed-plan-json docs/PHASE0_5_SEED_PLAN.json `
  --golden-json runs/golden.json `
  --controls-json runs/controls/controls.json `
  --attacker-control-json runs/attacker-control-seed<NON_GATE_SEED>.json `
  --controller-controls-json runs/controller-controls.json `
  --validation-json runs/validation.json `
  --out runs/gate-report.json
```

只以 `gate-report.json` 的 fail-closed verdict 为准：`SUPPORTED`、`NOT_SUPPORTED`、
`EXPERIMENT_INVALID` 或 `INCOMPLETE`。不得从部分矩阵、pilot、simulation、测试通过数或代码完成度
外推阶段结论。
