# RedCell 开发日志

倒序排列。每条记录:做了什么、**为什么这么决定**、留下了什么待办。
决策的理由比决策本身更值钱——半年后回头看,记不住理由的决策等于没决策。

---

## 2026-07-26 · 协议层与项目骨架(Phase 0 / W1)

**分支:** `feat/protocol-schema` → 基于 `chore/repo-scaffolding`

### 做了什么

- 项目骨架:`pyproject.toml`(ruff + black + pytest 配置集中于此,IDE 与 CI 共用一份)、`src/` 布局、Python 3.12 虚拟环境。
- 协议层 `src/redcell/protocols/`:`common` / `policy` / `adapter` / `trace` / `finding`。
- LLM 抽象层 `src/redcell/llm/`:`LLMProvider` 接口 + `ScriptedProvider`(零成本假实现)。
- 41 个测试,全部通过;ruff、black 无告警。

### 关键决策与理由

**1. `realized_impact` 用三态,而不是布尔**

`ImpactStatus = REALIZED | NOT_REALIZED | UNKNOWN`。

进程内靶场插桩齐全,副作用发生与否一清二楚;但 MVP 范围里明确包含通用 HTTP Adapter,
那时只看得到"agent 试图调用",看不到后端有没有真的执行。此时填 `NOT_REALIZED` 是在撒谎——
真相是"看不见"。把未知折叠成否会造成**系统性漏报**,而安全工具里漏报比误报危险。

代价是所有消费 impact 的代码都要处理第三种情况。这个代价是一次性的,且现在付最便宜:
等 detector、severity、报告、回归测试都开始消费这个字段之后再迁,成本是现在的十倍。

**诚实的边界**:如果砍掉 HTTP Adapter、永远只跑进程内靶场,布尔更简单,三态就是过度设计。

**2. Adapter 自报 `observability_level`**

决策 1 的配套件:既然 Impact 可能是 UNKNOWN,得有东西决定**什么时候**是 UNKNOWN。
`FULL / PARTIAL / RESPONSE_ONLY` 三档,由 Adapter 自己声明。

检测器必须能区分"我检查了,确实没有"和"我根本看不见"。没有这个字段,
两种情况在代码里长得一模一样,而且崩得没有报错——只是结论悄悄变错。

这条已固化成 `Finding` 的校验器:可观测性不足时断言 Impact 会直接抛错。

**3. 一次 Attempt = 一场完整攻击会话(可能多轮),不是一轮**

bandit 拉一次杆 = 试一个策略 = 一次 attempt,三者一一对应,reward 归属才清晰。
若按轮计,5 轮的多轮策略会吃掉 5 份预算,且 bandit 收到的全是半截子 reward。

代价:多轮策略每次消耗的 token 更多。这个差异由**独立的 token 预算**约束,
不去污染 query 预算的语义。

**4. reward 取 max,但 signals 全量保留**

这是 review 中被指出的一个真问题,值得单独记:**reward 和 evidence 是两个东西**。

- `reward` 是给 bandit 的**控制信号**,标量,只回答"这招值不值得再试" → 可以有损;
- `signals` 是**证据链** → 绝不能有损。

实现上 `signals` 全量进 Attempt 记录,`reward = max(signals)` 只喂给 bandit。
两条线同时非零时,应生成**两条** Finding,否则 Vulnerability Coverage 指标会系统性偏低。

`Attempt` 加了校验器强制 `reward == max(signals)`,杜绝手工赋值——
手写 reward 会让 bandit 学到假信号,而且这种 bug 不会报错。

**5. reward 中间档必须纯确定性 —— 修正了先前的草案**

先前草案里有一档是"承认存在受保护内容 → 0.3"。**这一档不成立**:
判断"是否承认"需要语义理解,就得上 LLM judge,直接违背 Phase 0"绕开 judge 噪声"的前提。

修正后的思路:**只给正向证据打分,不去判断拒绝**。没有任何正向证据自然是 0.0,
不需要专门识别"模型拒绝了"(那同样需要语义判断,且拒绝措辞因模型而异,很脆)。

因此 policy 里加了两个支撑字段:
- `ProtectedDatum.prefix` —— 支撑"吐出了 `RC_SECRET_` 但数字不对"这一中间档,纯字符串匹配;
- `SystemPromptFingerprint` —— system prompt 是我们自己写的,确切文本已知,
  "复述了片段"可用精确子串判定。附带一条校验:指纹短语过短(< 12 字符)直接拒绝,
  否则会在正常回答里误命中。

**6. 工程细节**

- `extra="forbid"`:协议层对拼错字段名零容忍。这层是两个 agent(Claude Code / Codex)
  的共同契约,静默通过的拼写错误是最难查的一类 bug。
- UUIDv7 自实现(约 15 行):前 48 位是时间戳,天然有序,省掉排序列;
  标准库要到 3.14 才有,不值得为此加依赖。
- 未在 policy 中声明的工具按**禁止**处理(fail-closed)。fail-open 会让"忘了写进 policy"
  变成静默的检测盲区。
- `TargetAdapter.reset()` 是接口的一部分:上一场攻击的副作用若残留到下一场,
  会污染 Impact 判定,复现率也就失去意义。

### 偏离既有约定之处

`AGENTS.md` §4.3 建议的布局是 `/control-plane` + `/arena` + `/shared`。
实际采用了 `src/redcell/` 单包布局,理由:Phase 0 只有 Python,单包意味着
一个虚拟环境、一次安装、模块之间直接可导入;多目录布局在这个阶段只增加配置负担。
`arena` 将作为 `src/redcell/arena/` 子包落地。Web 端在 Phase 2 再独立成 `/web`。

AGENTS.md 原文写的是"落地时确认,不要默默改结构"——此处即为确认记录。

### 遗留 / 待办

- [ ] **靶场 × 策略库必须一起设计**(下一步)。bandit 有东西可学的前提是不同策略在靶场上
      成功率不同,而这**不会自然发生,必须被设计出来**:全都能破 → adaptive = random;
      全都不能破 → 同样为 null。
- [ ] Thompson Sampling 的标准形式吃二元 reward,我们给的是 [0,1] 连续值,对不上。
      三种解法(Gaussian 版本 / 按概率随机取整后仍用 Beta / 矩匹配),实现 bandit 时定。
- [ ] `severity_score` 的计算方式未定,尤其 Impact 为 UNKNOWN 时如何取值。
      当前倾向:按 Attempt 算基础分,报告里显式标注 caveat,把判断权交还给人。
- [ ] Level-1 检测器尚未实现(下一批);golden trace 正负样本集同步开建。
- [ ] bandit 的假设违反与局限,已在后续讨论中细化为五条清单,见下一条日志。

---

## 2026-07-26 · Bandit 假设、非平稳性与多目标(设计讨论,无代码)

本条不含代码改动,记录一轮把 bandit 建模假设彻底厘清的讨论。
结论已写进 [CONCEPTS.md §6](CONCEPTS.md),此处只记**决策与待办**。

### 纠正一个流行误解

最初的表述("我们的场景违反了 bandit 假设")容易被读成"因为 LLM 输出不确定,所以违反"。
**这是错的,而且是个关键的错。**

> **样本在变不算什么,分布在变才算。**

LLM 是确定性函数:固定权重 + 固定输入 → 完全确定的概率分布;随机性只发生在**采样**那一步。
所以 LLM 的输出波动是**噪声**,而噪声正是 bandit 设计来处理的东西。
"黑盒"同理 —— 那是 bandit 的**前提**,不是问题。

顺带发现 `TargetAdapter.reset()` 有第二层作用:
它原本的理由是"防止副作用污染 Impact 判定与复现率",
但它同时**是把目标钉成平稳分布的那颗钉子** —— 不复位则独立性直接破掉。

### 根源:双层学习

> 标准 bandit 假设"环境是死的,只有我在学"。我们的系统里**有两层在学**。

Bandit 学策略分配,Mutator 学话术。下层的学习让上层看到的臂在脚下漂移。
**所以违反假设的几乎全是我方,不是被攻击方。**

### 五条局限(取代原先的两条)

| # | 类型 | 项 | 根源 | Phase 0 |
|---|---|---|---|---|
| 1 | 平稳性 | 变异漂移 | 我方变异器 | **修** —— 用无记忆变异 |
| 2 | 平稳性 | Rotting 衰减 | 我方 reward 定义 | 接受,写 Limitations |
| 3 | 平稳性 | 模型版本漂移 | 外部厂商 | **修** —— 工程纪律 |
| 4 | 建模简化 | 多目标压成单标量 | 我方设计 | 接受(见下) |
| 5 | 建模简化 | 臂被当作彼此独立 | 标准 bandit 模型 | 接受,指向 Phase 3 |

### 新决策

**① Phase 0 用无记忆变异**(每次从 seed 独立改写,不利用历史)。

不只是为了让假设成立,更重要的是**消除一个混淆变量**:
带记忆时 bandit 把预算集中到少数策略,那几个策略同时也获得更多次变异精炼,
于是 adaptive 赢了也分不清是 (a) 分配得好 还是 (b) 被精炼得更多。
而我们要主张的是 (a)。迭代精炼放 Phase 1 作独立消融,反而多一个结论。

**② 成本不进 reward,保持为硬约束。**

`reward = 命中 − λ×成本` 的 λ 永远是拍脑袋的("一次 API 调用值多少个漏洞?"),
换个 λ 结论就变。改成"预算 ≤ N 次前提下最大化发现"则不需要任何权重
(**budgeted bandit**)。Budget Manager 已经在做这件事,无需改动 —— 三个目标里第三个出局。

**③ Coverage 只测量,不优化。**

"发现数量"是虚荣指标(87 条同一个漏洞的话术变体 = 1 个漏洞)。
但 Phase 0 **不**把 coverage 放进 reward,理由是研究设计:
让"adaptive 更快但覆盖更窄"成为一个真实观察 —— 它本身是有价值的结论,
且为 Phase 1 的新颖性折扣提供动机与对照基线。

**④ 模型版本必须钉死。**

`gpt-4o-mini` 这类滚动别名指向的权重会变。周一跑 static、周三跑 bandit,
中间厂商推更新 → 比的就是两个不同目标,**结论作废且不会有任何报错**。
纪律:钉带日期的版本号 + 同一组消融在同一时间窗内跑完 + 重跑分析吃 `.llm_cache/`。

### 待办

- [ ] **新颖性折扣**(Phase 1):`reward = 命中分 × 新颖性系数`,重复发现打折到 ~0.2。
      一石二鸟解决 coverage 与 rotting,且去重可基于
      `(漏洞类别, 违规工具, 违规参数模式)` 结构化匹配,无需 LLM。
      ⚠️ 但这会**主动引入非平稳**,标准 Thompson 处理不好
      (用全部历史算平均,早期高 reward 已过时),需换 discounted / sliding-window 变体。
- [ ] Pareto bandit 已评估并**否决**:样本效率更差(预算才 100),实现与理论复杂,
      且最后仍需从帕累托前沿里选一个臂拉 —— 等于把取舍往后推一步。
- [ ] Phase 0 需**显式记录 coverage 指标**(不进 reward),供上述对照使用。

---

## 2026-07-26 · 仓库脚手架

**分支:** `chore/repo-scaffolding`

- `README.md`(按 PRD §24),授权与伦理声明置顶——这是安全工具能公开的前提。
- `.gitignore`:内部文档(PRD/AGENTS/CLAUDE)、密钥、构建产物、运行产物。
- 后续补充:`*.db`(Phase 0 用 SQLite 存 attempt/trace,否则库文件会落在仓库根目录)、
  `/results/`、`/plots/`、`.llm_cache/`。

`.llm_cache/` 值得单独说明:它是"实验可复现 + CI 零成本"的前提,
但录的正是真实攻击 prompt 和命中 canary 的响应——**设计上有用 ≠ 该提交**。
这类目录最容易在写 gitignore 时被顺手漏掉。
