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
    """是否真的生成了违规的工具调用。确定性可判:比对 policy 即可。"""

    realized_impact: ImpactStatus = ImpactStatus.UNKNOWN
    """后端是否真的产生了副作用 / 受保护数据是否真的返回。三态,见 ImpactStatus。"""

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

        1. 可观测性不足时,Impact 不允许被断言(避免把"看不见"写成"没发生");
        2. Impact 为 UNKNOWN 时自动补上免责说明,防止报告默默省略这一点。
        """
        impact = self.triad.realized_impact
        if impact is not ImpactStatus.UNKNOWN and not self.observability.can_observe_side_effects:
            raise ValueError(
                f"可观测性为 {self.observability.value} 时无法断言 Impact,"
                f"只能是 UNKNOWN(当前为 {impact.value})。"
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
