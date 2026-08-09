"""报告数据 —— 从 Run / Attempt / Finding 聚合出报告需要的一切。

渲染与聚合分开:同一份 `ReportData` 既能输出 JSON 也能输出 HTML,
两种格式的数字保证一致(否则某天改了 HTML 模板而漏了 JSON,
两份报告会对不上,而且不会有人立刻发现)。
"""

from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime

from pydantic import Field, computed_field

from redcell.finding_identity import attack_path_signature, finding_signature
from redcell.protocols.common import ImpactStatus, RedCellModel, VulnerabilityCategory
from redcell.protocols.finding import Finding
from redcell.protocols.run import Run
from redcell.protocols.trace import Attempt
from redcell.success_metrics import derive_success_metrics

DISCLAIMER = (
    "自动化扫描不能证明系统是安全的。未发现问题不等于不存在问题;"
    "本报告的结论仅适用于所测试的模型、提示词、工具集与配置版本。"
    "每条发现都应经过人工复核。"
)
"""PRD §16 要求的报告声明。**每份报告都必须带上,不设开关。**

安全报告最容易造成的伤害,是让读者以为"扫过了 = 安全了"。
"""


class StrategyStat(RedCellModel):
    strategy_id: str
    attempts: int
    attempt_hits: int
    impact_hits: int

    mean_signal_score: float

    @computed_field
    @property
    def attempt_success_rate(self) -> float:
        return self.attempt_hits / self.attempts if self.attempts else 0.0

    @computed_field
    @property
    def impact_success_rate(self) -> float:
        return self.impact_hits / self.attempts if self.attempts else 0.0


class ImpactBreakdown(RedCellModel):
    """三态各自的计数。

    分开统计不是为了好看:"确认发生""被拦下""观测不到"对应完全不同的处置 ——
    第一种要立刻修后端,第二种说明纵深防御有效,第三种是**我们不知道**,
    合并成一个数字会把第三种伪装成前两种之一。
    """

    realized: int = 0
    not_realized: int = 0
    unknown: int = 0

    @property
    def total(self) -> int:
        return self.realized + self.not_realized + self.unknown


class ReportData(RedCellModel):
    run: Run
    findings: list[Finding] = Field(default_factory=list)
    strategy_stats: list[StrategyStat] = Field(default_factory=list)
    budget_share: dict[str, float] = Field(default_factory=dict)
    impact: ImpactBreakdown = Field(default_factory=ImpactBreakdown)
    categories: dict[str, int] = Field(default_factory=dict)
    finding_signature_count: int = 0
    attack_path_signature_count: int = 0
    finding_signatures: dict[str, int] = Field(default_factory=dict)
    attack_path_signatures: dict[str, int] = Field(default_factory=dict)
    queries_to_first_attempt_success: int | None = None
    queries_to_first_impact_success: int | None = None
    """**未成功时均为 null,不填预算值。**

    用预算值顶替会把删失观测混进普通观测,均值被系统性拉低。
    """

    total_attempts: int = 0
    logical_attempts: int = 0
    abandoned_attempts: int = 0
    execution_retries: int = 0
    disclaimer: str = DISCLAIMER
    generated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @property
    def unverifiable_impact_count(self) -> int:
        return self.impact.unknown

    @classmethod
    def build(cls, run: Run, attempts: list[Attempt], findings: list[Finding]) -> ReportData:
        per_strategy: Counter[str] = Counter()
        reward_sum: Counter[str] = Counter()

        for attempt in attempts:
            per_strategy[attempt.strategy_id] += 1
            reward_sum[attempt.strategy_id] += attempt.reward

        success = derive_success_metrics(attempts, findings)

        stats = [
            StrategyStat(
                strategy_id=sid,
                attempts=count,
                attempt_hits=success.by_strategy[sid].attempt_hits,
                impact_hits=success.by_strategy[sid].impact_hits,
                mean_signal_score=reward_sum[sid] / count if count else 0.0,
            )
            for sid, count in sorted(per_strategy.items())
        ]

        total = len(attempts)
        share = {sid: count / total for sid, count in per_strategy.items()} if total else {}

        impact = ImpactBreakdown()
        for finding in findings:
            status = finding.triad.realized_impact
            if status is ImpactStatus.REALIZED:
                impact.realized += 1
            elif status is ImpactStatus.NOT_REALIZED:
                impact.not_realized += 1
            else:
                impact.unknown += 1

        categories = Counter(f.category.value for f in findings)
        finding_signatures = Counter(finding_signature(finding) for finding in findings)
        attack_path_signatures = Counter(attack_path_signature(finding) for finding in findings)

        return cls(
            run=run,
            findings=findings,
            strategy_stats=stats,
            budget_share=share,
            impact=impact,
            categories=dict(categories),
            finding_signature_count=len(finding_signatures),
            attack_path_signature_count=len(attack_path_signatures),
            finding_signatures=dict(sorted(finding_signatures.items())),
            attack_path_signatures=dict(sorted(attack_path_signatures.items())),
            queries_to_first_attempt_success=success.queries_to_first_attempt_success,
            queries_to_first_impact_success=success.queries_to_first_impact_success,
            total_attempts=total,
            logical_attempts=max(run.usage.attempts, total),
            abandoned_attempts=run.usage.abandoned_attempts,
            execution_retries=run.usage.retries,
        )

    def covered_categories(self) -> set[VulnerabilityCategory]:
        return {f.category for f in self.findings}
