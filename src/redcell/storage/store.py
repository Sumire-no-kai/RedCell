"""RunStore —— 实验数据的读写入口。

Phase 0 用 SQLite(单文件、零部署),Phase 2 换 Postgres 时只换连接串:
表结构与查询都走 SQLAlchemy,没有 SQLite 方言依赖。
"""

from __future__ import annotations

from collections.abc import Iterable

from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session, sessionmaker

from redcell.protocols.finding import Finding
from redcell.protocols.run import Run
from redcell.protocols.trace import Attempt
from redcell.storage.models import AttemptRow, Base, FindingRow, RunRow

DEFAULT_URL = "sqlite:///redcell.db"


class RunStore:
    """实验结果的持久化。

    落盘不是可选项:PRD §5.5 要求每个漏洞可复现,而复现需要完整 trace;
    实验也要跨多个 seed 聚合,内存里存不下也活不过进程。
    """

    def __init__(self, url: str = DEFAULT_URL, *, echo: bool = False) -> None:
        self._engine = create_engine(url, echo=echo, future=True)
        self._session = sessionmaker(self._engine, expire_on_commit=False, future=True)
        Base.metadata.create_all(self._engine)

    def close(self) -> None:
        self._engine.dispose()

    def __enter__(self) -> RunStore:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    def _open(self) -> Session:
        return self._session()

    # ── Run ──────────────────────────────────────────────────────────────

    def save_run(self, run: Run) -> None:
        """写入或更新。Run 会随执行推进多次落盘(状态、用量、结束时间)。"""
        with self._open() as session, session.begin():
            session.merge(
                RunRow(
                    id=run.id,
                    target_name=run.target_name,
                    policy_version=run.policy_version,
                    algorithm=run.algorithm,
                    seed=run.seed,
                    status=run.status.value,
                    max_attempts=run.limits.max_attempts,
                    created_at=run.created_at.replace(tzinfo=None),
                    payload=run.model_dump(mode="json"),
                )
            )

    def get_run(self, run_id: str) -> Run | None:
        with self._open() as session:
            row = session.get(RunRow, run_id)
            return Run.model_validate(row.payload) if row else None

    def list_runs(self, *, algorithm: str | None = None) -> list[Run]:
        stmt = select(RunRow).order_by(RunRow.created_at)
        if algorithm is not None:
            stmt = stmt.where(RunRow.algorithm == algorithm)
        with self._open() as session:
            return [Run.model_validate(row.payload) for row in session.scalars(stmt)]

    # ── Attempt ──────────────────────────────────────────────────────────

    def save_attempt(self, attempt: Attempt) -> None:
        with self._open() as session, session.begin():
            session.merge(
                AttemptRow(
                    id=attempt.id,
                    run_id=attempt.run_id,
                    strategy_id=attempt.strategy_id,
                    actor=attempt.actor,
                    reward=attempt.reward,
                    turn_count=attempt.turn_count,
                    prompt_tokens=attempt.cost.prompt_tokens,
                    completion_tokens=attempt.cost.completion_tokens,
                    cost_usd=attempt.cost.usd,
                    created_at=attempt.created_at.replace(tzinfo=None),
                    payload=attempt.model_dump(mode="json"),
                )
            )

    def save_attempts(self, attempts: Iterable[Attempt]) -> None:
        for attempt in attempts:
            self.save_attempt(attempt)

    def attempts_for(self, run_id: str) -> list[Attempt]:
        stmt = select(AttemptRow).where(AttemptRow.run_id == run_id).order_by(AttemptRow.created_at)
        with self._open() as session:
            return [Attempt.model_validate(row.payload) for row in session.scalars(stmt)]

    # ── Finding ──────────────────────────────────────────────────────────

    def save_finding(self, finding: Finding) -> None:
        with self._open() as session, session.begin():
            session.merge(
                FindingRow(
                    id=finding.id,
                    run_id=finding.run_id,
                    attempt_id=finding.attempt_id,
                    category=finding.category.value,
                    title=finding.title,
                    status=finding.status.value,
                    severity=finding.severity.value if finding.severity else None,
                    realized_impact=finding.triad.realized_impact.value,
                    created_at=finding.created_at.replace(tzinfo=None),
                    payload=finding.model_dump(mode="json"),
                )
            )

    def save_findings(self, findings: Iterable[Finding]) -> None:
        for finding in findings:
            self.save_finding(finding)

    def findings_for(self, run_id: str) -> list[Finding]:
        stmt = select(FindingRow).where(FindingRow.run_id == run_id).order_by(FindingRow.created_at)
        with self._open() as session:
            return [Finding.model_validate(row.payload) for row in session.scalars(stmt)]

    # ── 聚合(消融分析用) ───────────────────────────────────────────────

    def attempts_per_strategy(self, run_id: str) -> dict[str, int]:
        """bandit 把预算分给了谁 —— 自适应是否真的在分配的直接证据。"""
        stmt = (
            select(AttemptRow.strategy_id, func.count())
            .where(AttemptRow.run_id == run_id)
            .group_by(AttemptRow.strategy_id)
        )
        with self._open() as session:
            return dict(session.execute(stmt).all())

    def attack_success_rate(self, run_id: str, *, threshold: float = 1.0) -> dict[str, float]:
        """按策略统计满分命中率。校准的主指标。"""
        counts = self.attempts_per_strategy(run_id)
        stmt = (
            select(AttemptRow.strategy_id, func.count())
            .where(AttemptRow.run_id == run_id, AttemptRow.reward >= threshold)
            .group_by(AttemptRow.strategy_id)
        )
        with self._open() as session:
            hits = dict(session.execute(stmt).all())
        return {sid: hits.get(sid, 0) / total for sid, total in counts.items() if total}

    def queries_to_first_success(self, run_id: str, *, threshold: float = 1.0) -> int | None:
        """首次成功用了第几次 attempt。**未成功时返回 None,不返回预算值。**

        用预算值顶替会把"从未成功"伪装成"刚好在最后一次成功",
        把一个删失(censored)观测混进普通观测里,均值会被系统性拉低。
        """
        stmt = (
            select(AttemptRow.id).where(AttemptRow.run_id == run_id).order_by(AttemptRow.created_at)
        )
        hit_stmt = (
            select(AttemptRow.id)
            .where(AttemptRow.run_id == run_id, AttemptRow.reward >= threshold)
            .order_by(AttemptRow.created_at)
            .limit(1)
        )
        with self._open() as session:
            first_hit = session.scalars(hit_stmt).first()
            if first_hit is None:
                return None
            ordered = list(session.scalars(stmt))
        return ordered.index(first_hit) + 1
