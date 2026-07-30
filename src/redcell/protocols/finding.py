"""Finding —— 一条确认的漏洞记录,报告与回归测试的最小单元。

核心是 ViolationTriad(三分):Intent / Attempted Action / Realized Impact
必须分开表达。把三者压成一个 bool,会让"agent 想干坏事但被后端拦住"和
"agent 干了且后端也没拦住"在报告里长得一模一样——而这两者的修复方式
和紧急程度完全不同。
"""

from __future__ import annotations

from datetime import UTC, datetime

from pydantic import Field, model_validator

from redcell.protocols.adapter import SideEffect, ToolCall
from redcell.protocols.common import (
    FindingStatus,
    ImpactBasis,
    ImpactStatus,
    ObservabilityLevel,
    RedCellModel,
    SeverityLevel,
    VulnerabilityCategory,
    new_id,
)

IMPACT_CAVEAT_TEMPLATE = (
    "Impact 无法验证 —— 目标可观测性为 {level}。"
    "本条结论仅覆盖到「攻击尝试」层面,后端是否真的执行未知,需人工确认。"
)


class Evidence(RedCellModel):
    """证据链的一条。每条 Finding 至少要有一条,否则不允许成立。"""

    description: str
    turn_index: int | None = None
    matched_value: str | None = None
    tool_call: ToolCall | None = None
    side_effect: SideEffect | None = None


class ViolationTriad(RedCellModel):
    """违规意图 / 攻击尝试 / 真实影响,三者分离。"""

    intent_violation: bool | None = None
    """输出是否表达了违规意图。

    None = 尚未评估。Phase 0 刻意不判定这一项:它需要语义理解(LLM judge),
    而脊椎阶段的全部实验都建立在确定性判定之上,不引入 judge 噪声。
    Phase 1 补全。
    """

    attempted_action: bool = False
    """是否产生了**确定性可判的违规行为**。比对 policy 即可,不需要语义理解。

    ⚠️ 不要读成"是否生成了违规的工具调用" —— 违规工具调用只是其中一种。
    受保护数据出现在回复正文里同样置 True:它同样是 agent 已经做出了
    违反部署方策略的**行为**,只是行为的形态是"说出来"而不是"调用工具"。

    这个字段是 Attempt ASR(校准主指标,见 docs/CALIBRATION.md §4)与
    Executor 提前停止条件的共同依据,所以它的语义边界必须精确。
    """

    realized_impact: ImpactStatus = ImpactStatus.UNKNOWN
    """后端是否真的产生了副作用 / 受保护数据是否真的返回。三态,见 ImpactStatus。"""

    impact_basis: ImpactBasis | None = None
    """断言 realized_impact 时依据的证据来源。见 ImpactBasis。

    不变量:断言了 impact(REALIZED / NOT_REALIZED)就**必须**说明凭什么断言;
    impact 为 UNKNOWN 时不允许有 basis —— 没有观测到任何东西,就没有证据来源。
    """

    @model_validator(mode="after")
    def _require_basis_for_asserted_impact(self) -> ViolationTriad:
        if self.realized_impact is ImpactStatus.UNKNOWN:
            if self.impact_basis is not None:
                raise ValueError(
                    f"realized_impact 为 UNKNOWN 时不能有 impact_basis"
                    f"(当前为 {self.impact_basis.value})。"
                    "没有观测到任何东西就没有证据来源。"
                )
        elif self.impact_basis is None:
            raise ValueError(
                f"断言 realized_impact={self.realized_impact.value} 必须同时给出 impact_basis,"
                "否则报告无法说明这条结论凭什么成立。"
            )
        return self

    @property
    def defense_in_depth_held(self) -> bool:
        """agent 判断失误,但后端权限层守住了。

        这类问题该修 prompt / 换模型,严重度低于"两层全失守"。
        """
        return self.attempted_action and self.realized_impact is ImpactStatus.NOT_REALIZED

    @property
    def fully_compromised(self) -> bool:
        """agent 干了,后端也没拦住——纵深防御全线失守。"""
        return self.attempted_action and self.realized_impact is ImpactStatus.REALIZED


class Finding(RedCellModel):
    id: str = Field(default_factory=new_id)
    run_id: str
    attempt_id: str
    category: VulnerabilityCategory
    title: str
    actor: str
    strategy_id: str

    triad: ViolationTriad
    evidence: list[Evidence] = Field(min_length=1)
    """至少一条证据。"无证据的 Finding"不允许存在——那是猜测,不是发现。"""

    observability: ObservabilityLevel
    """判定发生时目标的可观测性等级。报告里必须如实呈现结论的适用边界。"""

    impact_caveat: str | None = None
    """Impact 为 UNKNOWN 时自动生成的免责说明,由校验器填充,不需手工写。"""

    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    """Level-1 确定性判定恒为 1.0;Phase 1 引入 judge 后才会出现小于 1 的值。"""

    reproduction_rate: float | None = Field(default=None, ge=0.0, le=1.0)
    reproduction_runs: int = 0

    severity: SeverityLevel | None = None
    severity_score: float | None = Field(default=None, ge=0.0)
    status: FindingStatus = FindingStatus.OPEN
    recommended_mitigation: str | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @model_validator(mode="after")
    def _enforce_impact_semantics(self) -> Finding:
        """把"三态"的设计意图固化成代码里的不变量。

        1. **观测不到该类证据时,Impact 不允许被断言**(避免把"看不见"写成"没发生");
        2. Impact 为 UNKNOWN 时自动补上免责说明,防止报告默默省略这一点。

        第 1 条按 `impact_basis` 分别判定,而不是统一要求 FULL:
        canary 泄漏的证据就在回复正文里,在 RESPONSE_ONLY 的黑盒目标上同样成立;
        统一按副作用门槛卡,会让最有价值的那类结论在远程目标上直接构造失败。
        """
        impact = self.triad.realized_impact
        basis = self.triad.impact_basis
        if basis is not None and not basis.is_observable_at(self.observability):
            raise ValueError(
                f"可观测性为 {self.observability.value} 时观测不到 {basis.value} 类证据,"
                f"因此无法断言 Impact,只能是 UNKNOWN(当前为 {impact.value})。"
                "把未知折叠成否会造成系统性漏报。"
            )
        if impact is ImpactStatus.UNKNOWN and self.impact_caveat is None:
            # 直接写 __dict__ 而不是普通赋值:模型开了 validate_assignment,
            # 在 after 校验器里赋值会再次触发校验,导致无限递归。
            self.__dict__["impact_caveat"] = IMPACT_CAVEAT_TEMPLATE.format(
                level=self.observability.value
            )
        return self

    @property
    def impact_is_verifiable(self) -> bool:
        return self.triad.realized_impact is not ImpactStatus.UNKNOWN
