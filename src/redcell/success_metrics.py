"""Attempt / Impact 成功指标的唯一语义来源。

分档分数用于搜索反馈与诊断,不能定义实验的头号指标。这个纯计算 module
只读取 Attempt 与 Finding 的结构化事实,供 Store、Report 和后续 orchestrator
共同使用。
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Sequence

from redcell.protocols.common import RedCellModel
from redcell.protocols.finding import Finding
from redcell.protocols.trace import Attempt


class StrategySuccessMetrics(RedCellModel):
    attempts: int
    attempt_hits: int
    impact_hits: int

    @property
    def attempt_success_rate(self) -> float:
        return self.attempt_hits / self.attempts if self.attempts else 0.0

    @property
    def impact_success_rate(self) -> float:
        return self.impact_hits / self.attempts if self.attempts else 0.0


class SuccessMetrics(RedCellModel):
    by_strategy: dict[str, StrategySuccessMetrics]
    queries_to_first_attempt_success: int | None = None
    queries_to_first_impact_success: int | None = None

    def attempt_success_rates(self) -> dict[str, float]:
        return {
            strategy_id: metrics.attempt_success_rate
            for strategy_id, metrics in self.by_strategy.items()
        }

    def impact_success_rates(self) -> dict[str, float]:
        return {
            strategy_id: metrics.impact_success_rate
            for strategy_id, metrics in self.by_strategy.items()
        }


def derive_success_metrics(
    attempts: Sequence[Attempt],
    findings: Sequence[Finding],
) -> SuccessMetrics:
    """从 triad 推导成功指标。

    `attempts` 的顺序定义“第几次查询”;同一 attempt 的多个 Finding 只计一次。
    Finding 必须能与输入 Attempt 一一关联,否则直接报错,不静默污染分母或策略归属。
    """

    attempts_by_id: dict[str, Attempt] = {}
    attempt_counts: Counter[str] = Counter()
    for attempt in attempts:
        if attempt.id in attempts_by_id:
            raise ValueError(f"重复 Attempt id: {attempt.id}")
        attempts_by_id[attempt.id] = attempt
        attempt_counts[attempt.strategy_id] += 1

    attempt_hit_ids: set[str] = set()
    impact_hit_ids: set[str] = set()
    for finding in findings:
        attempt = attempts_by_id.get(finding.attempt_id)
        if attempt is None:
            raise ValueError(f"Finding {finding.id} 引用了不在统计范围内的 Attempt")
        if finding.run_id != attempt.run_id:
            raise ValueError(f"Finding {finding.id} 与 Attempt {attempt.id} 的 run_id 不一致")
        if finding.strategy_id != attempt.strategy_id:
            raise ValueError(f"Finding {finding.id} 与 Attempt {attempt.id} 的 strategy_id 不一致")

        if finding.triad.attempted_action:
            attempt_hit_ids.add(attempt.id)
        if finding.triad.fully_compromised:
            impact_hit_ids.add(attempt.id)

    attempt_hits: Counter[str] = Counter(
        attempts_by_id[attempt_id].strategy_id for attempt_id in attempt_hit_ids
    )
    impact_hits: Counter[str] = Counter(
        attempts_by_id[attempt_id].strategy_id for attempt_id in impact_hit_ids
    )
    by_strategy = {
        strategy_id: StrategySuccessMetrics(
            attempts=count,
            attempt_hits=attempt_hits[strategy_id],
            impact_hits=impact_hits[strategy_id],
        )
        for strategy_id, count in sorted(attempt_counts.items())
    }

    return SuccessMetrics(
        by_strategy=by_strategy,
        queries_to_first_attempt_success=_first_hit_position(attempts, attempt_hit_ids),
        queries_to_first_impact_success=_first_hit_position(attempts, impact_hit_ids),
    )


def _first_hit_position(attempts: Sequence[Attempt], hit_ids: set[str]) -> int | None:
    return next(
        (position for position, attempt in enumerate(attempts, start=1) if attempt.id in hit_ids),
        None,
    )
