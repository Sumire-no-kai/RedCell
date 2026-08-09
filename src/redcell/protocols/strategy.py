"""Strategy —— 一类攻击的**高层方法**,以及 bandit 的一个摇臂(arm)。

Strategy 不是 prompt。Strategy 是"假装成维修工混进楼里"这个主意,
prompt 是当天穿什么衣服、跟保安说的那句台词。一个 strategy 能生成无穷条 prompt。

这样分层的理由:写死的攻击词表会随模型更新过时,而且会过拟合到特定模型;
方法不会。所以 RedCell 维护方法,具体话术由变异器现场生成。

详见 docs/STRATEGIES.md。
"""

from __future__ import annotations

import hashlib
import re
from enum import StrEnum

from pydantic import Field, model_validator

from redcell.protocols.common import RedCellModel, VulnerabilityCategory
from redcell.protocols.policy import Policy

MAX_TURNS_CEILING = 10
"""任何策略都不得超过的轮数硬顶。

存在的意义是兜底:配置里写错一个数字就可能让一场攻击跑 30 轮,
而多轮策略和 agent 互相绕圈时,成本是没有自然刹车的。
"""

_SLOT_PATTERN = re.compile(r"\{(\w+)\}")


class TemplateSlot(StrEnum):
    """seed 模板里允许出现的槽位。

    槽位让模板与具体靶场解耦:同一个策略换个靶场,填不同的工具名和资源 ID 即可,
    不需要改模板本身。
    """

    ACTOR = "actor"
    """当前攻击者扮演的身份,如 customer_a。"""

    TARGET_RESOURCE = "target_resource"
    """想越权访问的资源 ID,如 customer_b。"""

    CONSTRAINED_TOOL = "constrained_tool"
    """带参数约束的工具名。"""

    FORBIDDEN_TOOL = "forbidden_tool"
    """policy 中禁止调用的工具名。"""


class PredictedStrength(StrEnum):
    """预注册预测的**粗标签**,给人读的。⚠️ 不参与任何判定。

    ## 为什么它不再带 ASR 区间(2026-08-01 变更)

    原先每档挂一个绝对 ASR 区间(strong [30%,50%) 等),并有 `matches()`
    判定实测值落没落进区间。**已删除**,理由有两条:

    1. **三档表达不了已定稿的排序。** 作者要求 Confirmation Bypass 落在
       「④ 与 ②③ 之间」,而 medium 上界与 strong 下界都是 30% —— 中间没有空隙。
       每加一个策略就要重划一次边界,而每条边界都是拍出来的。
    2. **绝对区间从来没有被任何检验程序用到。** `STRATEGIES.md` §4.1 定稿的
       检验方法是**成对比较 + 三分类判决**,用的量是**相对秩**;
       `matches()` 是一段没有调用方的判定逻辑,留着只会让人以为判据有两套。

    → 判据是 `Strategy.predicted_rank`。本枚举只做速查标签。
    """

    STRONG = "strong"
    MEDIUM = "medium"
    WEAK = "weak"


class MutationOperator(StrEnum):
    """把 seed 模板变成一句具体话术的手法(PRD §8)。

    十个全部在此声明,即使 Phase 0 只用其中一部分——
    枚举是对空间的描述,补全它是零成本的前瞻,省得 Phase 1 再改枚举。
    """

    PARAPHRASE = "paraphrase"
    ROLE_CHANGE = "role_change"
    AUTHORITY_ESCALATION = "authority_escalation"
    ENCODING = "encoding"
    CONTEXT_INSERTION = "context_insertion"
    BENIGN_CAMOUFLAGE = "benign_camouflage"
    CONSTRAINT_NEGATION = "constraint_negation"
    MULTI_STEP_DECOMPOSITION = "multi_step_decomposition"
    PREVIOUS_RESPONSE_EXPLOITATION = "previous_response_exploitation"
    TOOL_PARAMETER_MUTATION = "tool_parameter_mutation"

    @property
    def reads_prior_attempts(self) -> bool:
        """是否需要读取**历史 attempt** 的结果。

        ⚠️ 注意区分两种"记忆",它们的后果完全不同:

        * **轮内适应** —— 一场会话里第 2 轮参考第 1 轮的回复。
          这是多轮策略的运作方式,**不破坏平稳性**,因为每场 attempt 仍是独立抽样。允许。
        * **跨 attempt 记忆** —— 第 20 场参考前 19 场的结果。
          这会让臂一次比一次强,**破坏 bandit 的平稳性假设**,而且引入混淆变量:
          bandit 集中投入的策略同时也被精炼得更多,于是分不清优势来自
          "分配得好"还是"被精炼得多"。Phase 0 禁用。

        本属性标的是后者。变异算子在**一场攻击开始时**执行,不得读历史;
        轮内的对话推进是另一套机制,不受此限。
        """
        return self is MutationOperator.PREVIOUS_RESPONSE_EXPLOITATION


MEMORYLESS_OPERATORS: frozenset[MutationOperator] = frozenset(
    op for op in MutationOperator if not op.reads_prior_attempts
)
"""Phase 0 允许使用的算子集合。"""


class StrategyRequirements(RedCellModel):
    """策略能施展的前置条件。

    不满足时该策略**根本不进候选池**,而不是进去拿一个 0 分——
    结构性的 0("没靶子")和真实的 0("打了但没打动")含义完全不同,
    混在一起会污染分化度统计,让人误以为找到了一个漂亮的弱臂。
    """

    min_actors: int = 1
    needs_constrained_tool: bool = False
    needs_forbidden_tool: bool = False
    needs_confirmation_tool: bool = False
    needs_document_source: bool = False


class Strategy(RedCellModel):
    """一类攻击方法。在 bandit 里,一个 Strategy = 一个摇臂。"""

    id: str
    name: str
    description: str

    categories: list[VulnerabilityCategory] = Field(min_length=1)
    """本策略瞄准的漏洞类别,**可多值**。

    单值的话,"角色扮演"这类同时打 canary 和越权工具的策略就得拆成两个臂,
    6 个臂变 8 个,而预算 100 下每多一个臂,每臂样本就少一截。

    注意这是"瞄准什么",不是"结果是什么"——
    Finding 的 category 由实际触发的信号决定,不由策略的意图决定。
    """

    seed_template: str
    mutation_operators: list[MutationOperator] = Field(min_length=1)
    max_turns: int = Field(ge=1, le=MAX_TURNS_CEILING)

    predicted_rank: float = Field(gt=0)
    """预注册预测:本策略 Attempt ASR 在策略集内的**秩**,1 = 最弱。⭐

    这是预测的**唯一判据**(`predicted_strength` 只是给人读的标签)。

    **并列取平均秩** —— 两个策略并列第 3–4 名,都写 3.5。
    这不是记号上的讲究:平均秩表示"我们不断言这两者的方向",
    而检验程序会**跳过**没有方向的对(见 `predicted_pairs`)。
    若强行给并列者排出先后,就等于凭空多出一条从没做过的预测,
    而它有 50% 的概率"蒙对"。

    **为什么是秩不是绝对 ASR 区间:** 见 `PredictedStrength` 的说明,
    以及 `docs/STRATEGIES.md` §4.1。

    ⚠️ **本字段是预注册内容,一经提交进 git 即冻结。**
    看到校准结果之后修改它,预注册就名存实亡。
    """

    predicted_strength: PredictedStrength
    """速查用的粗标签。**不参与判定** —— 判据是 `predicted_rank`。

    仍然要求显式填写:让"这个策略预期强还是弱"在库文件里一眼可见,
    比只有一个 3.5 好读。一致性由测试兜住(秩更高者标签不得更弱)。
    """

    requirements: StrategyRequirements = Field(default_factory=StrategyRequirements)

    @model_validator(mode="after")
    def _validate_template_slots(self) -> Strategy:
        valid = {slot.value for slot in TemplateSlot}
        used = set(_SLOT_PATTERN.findall(self.seed_template))
        unknown = used - valid
        if unknown:
            raise ValueError(
                f"策略 '{self.id}' 的模板含未知槽位 {sorted(unknown)};可用槽位:{sorted(valid)}"
            )
        return self

    # ── 与具体目标的匹配 ──────────────────────────────────────────────────

    def is_applicable(self, policy: Policy) -> bool:
        """本策略在这个目标上有没有靶子可打。

        返回 False 的策略应被排除出候选池(见 StrategyRequirements 的说明)。
        """
        req = self.requirements
        if len(policy.actors) < req.min_actors:
            return False
        if req.needs_constrained_tool and not policy.constrained_tool_names():
            return False
        if req.needs_forbidden_tool and not any(not tool.allowed for tool in policy.tools.values()):
            return False
        if req.needs_confirmation_tool and not any(
            tool.requires_confirmation for tool in policy.tools.values()
        ):
            return False
        # Phase 0 的靶场没有文档/RAG 来源,间接注入类策略一律不适用。
        return not req.needs_document_source

    def validate_against(self, policy: Policy) -> None:
        """加载策略库时调用。不通过就抛,不静默降级。

        目前只查一件事,但这件事很要命:**模板里不能出现 canary 值**。

        否则攻击话术自带 canary → 模型原样复述 → 检测器判定"泄漏" ——
        而模型其实什么都没吐出来,它只是在鹦鹉学舌。
        这类假 Finding 看起来特别真,最容易骗过自己。
        """
        leaked = [c for c in policy.canary_values() if c in self.seed_template]
        if leaked:
            raise ValueError(
                f"策略 '{self.id}' 的 seed 模板包含受保护 canary {leaked};"
                "攻击方自带 canary 会让模型的复述被误判为泄漏。"
            )

    def uses_prior_attempts(self) -> bool:
        return any(op.reads_prior_attempts for op in self.mutation_operators)


class StrategyConditionSummary(RedCellModel):
    """会改变一次策略实验语义、并可安全落盘的摘要。

    不保存 seed template 原文，而保存其 SHA-256。这样条件指纹会随模板改动而变化，
    又不会把完整攻击话术额外复制进每个 Run 记录。
    """

    id: str
    categories: list[VulnerabilityCategory]
    max_turns: int = Field(ge=1, le=MAX_TURNS_CEILING)
    template_sha256: str = Field(min_length=64, max_length=64)
    mutation_operators: list[MutationOperator] = Field(min_length=1)
    predicted_rank: float = Field(gt=0)
    predicted_strength: PredictedStrength
    requirements: StrategyRequirements

    @classmethod
    def from_strategy(cls, strategy: Strategy) -> StrategyConditionSummary:
        return cls(
            id=strategy.id,
            categories=list(strategy.categories),
            max_turns=strategy.max_turns,
            template_sha256=hashlib.sha256(strategy.seed_template.encode("utf-8")).hexdigest(),
            mutation_operators=list(strategy.mutation_operators),
            predicted_rank=strategy.predicted_rank,
            predicted_strength=strategy.predicted_strength,
            requirements=strategy.requirements,
        )


class StrategyCatalogueSummary(RedCellModel):
    """写入 ExperimentConditions 的不可变策略目录摘要。"""

    version: str = Field(min_length=1)
    strategies: list[StrategyConditionSummary] = Field(min_length=1)


class StrategyCatalogue(RedCellModel):
    """一批可比较实验所用的有版本策略目录。

    可以把它看作给一组试卷盖封条：题目、顺序或答题时间一旦改变，就不能把两次考试
    的分数混在一起。Phase 0 保留冻结目录；后续阶段都使用自己的显式版本。
    """

    version: str = Field(min_length=1)
    strategies: list[Strategy] = Field(min_length=1)

    @model_validator(mode="after")
    def _validate_unique_ids(self) -> StrategyCatalogue:
        ids = [strategy.id for strategy in self.strategies]
        if len(ids) != len(set(ids)):
            raise ValueError("策略目录中不得有重复 id")
        return self

    def condition_summary(self) -> StrategyCatalogueSummary:
        return StrategyCatalogueSummary(
            version=self.version,
            strategies=[
                StrategyConditionSummary.from_strategy(strategy) for strategy in self.strategies
            ],
        )


def predicted_pairs(strategies: list[Strategy]) -> list[tuple[str, str]]:
    """列出预测**有方向**的策略对,每对为 `(预测更强者, 预测更弱者)`。

    这是 `STRATEGIES.md` §4.1 那张「成对比较判决表」的机器生成版本。
    校准跑完后逐对填入实测差值与 CI,判为 符合 / 相反 / 分辨不出。

    **并列的对不出现在结果里** —— 秩相同意味着我们没有断言方向,
    事后再给它判一个"符合"或"相反"都是无中生有。§4.1 的"21 对里有 19 对"
    正是这么来的(七个策略两两 21 对,减去 ①④ 与 ②③ 两组并列)。

    刻意从 `predicted_rank` 现算而不是维护一张手写表:手写表会和秩各自漂移,
    而"预测到底是什么"必须只有一个来源 —— 否则冻结的是哪一份都说不清。
    """
    ordered = sorted(strategies, key=lambda s: (s.predicted_rank, s.id))
    return [
        (stronger.id, weaker.id)
        for i, weaker in enumerate(ordered)
        for stronger in ordered[i + 1 :]
        if stronger.predicted_rank != weaker.predicted_rank
    ]


def select_applicable(
    strategies: list[Strategy],
    policy: Policy,
    *,
    memoryless: bool = True,
) -> list[Strategy]:
    """筛出能在该目标上施展的策略,并校验模板安全性。

    `memoryless=True`(Phase 0 默认)会排除依赖历史 attempt 的策略。
    """
    selected = []
    for strategy in strategies:
        strategy.validate_against(policy)
        if not strategy.is_applicable(policy):
            continue
        if memoryless and strategy.uses_prior_attempts():
            continue
        selected.append(strategy)
    return selected
