"""RunStore —— 实验数据的读写入口。

Phase 0 用 SQLite(单文件、零部署),Phase 2 换 Postgres 时只换连接串:
表结构与查询都走 SQLAlchemy,没有 SQLite 方言依赖。
"""

from __future__ import annotations

from collections.abc import Iterable

from sqlalchemy import create_engine, event, func, select
from sqlalchemy.orm import Session, sessionmaker

from redcell.protocols.finding import Finding
from redcell.protocols.run import Run, RunEvent
from redcell.protocols.trace import Attempt
from redcell.search.base import ControllerDecision, ControllerDecisionOutcome
from redcell.storage.models import (
    AttemptRow,
    Base,
    ControllerDecisionRow,
    FindingRow,
    RunEventRow,
    RunRow,
)
from redcell.success_metrics import SuccessMetrics, derive_success_metrics

DEFAULT_URL = "sqlite:///redcell.db"


class RunStore:
    """实验结果的持久化。

    落盘不是可选项:PRD §5.5 要求每个漏洞可复现,而复现需要完整 trace;
    实验也要跨多个 seed 聚合,内存里存不下也活不过进程。
    """

    def __init__(self, url: str = DEFAULT_URL, *, echo: bool = False) -> None:
        connect_args = {"timeout": 30} if url.startswith("sqlite") else {}
        self._engine = create_engine(
            url,
            echo=echo,
            future=True,
            pool_pre_ping=True,
            connect_args=connect_args,
        )
        if url.startswith("sqlite"):
            event.listen(self._engine, "connect", _configure_sqlite_connection)
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
            self._merge_run(session, run)

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
            self._merge_attempt(session, attempt)

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
            self._merge_finding(session, finding)

    def save_findings(self, findings: Iterable[Finding]) -> None:
        for finding in findings:
            self.save_finding(finding)

    def findings_for(self, run_id: str) -> list[Finding]:
        stmt = select(FindingRow).where(FindingRow.run_id == run_id).order_by(FindingRow.created_at)
        with self._open() as session:
            return [Finding.model_validate(row.payload) for row in session.scalars(stmt)]

    # ── Controller 决策与运行事件 ───────────────────────────────────────

    def save_decision(
        self,
        *,
        run_id: str,
        attempt_id: str,
        decision: ControllerDecision,
    ) -> None:
        with self._open() as session, session.begin():
            self._merge_decision(session, run_id, attempt_id, decision)

    def decisions_for(self, run_id: str) -> list[ControllerDecision]:
        stmt = (
            select(ControllerDecisionRow)
            .where(ControllerDecisionRow.run_id == run_id)
            .order_by(ControllerDecisionRow.attempt_index)
        )
        with self._open() as session:
            return [ControllerDecision.model_validate(row.payload) for row in session.scalars(stmt)]

    def pending_decision_for(self, run_id: str) -> tuple[str, ControllerDecision] | None:
        """Return the one selected decision whose outcome was never committed.

        A RUNNING run is allowed to have at most one such row: decisions are
        selected serially, and the next selection only occurs after the prior
        decision has atomically become COMPLETED or ABANDONED.  Treating more
        than one as corruption is safer than guessing which target call to
        replay.
        """
        stmt = (
            select(ControllerDecisionRow)
            .where(
                ControllerDecisionRow.run_id == run_id,
                ControllerDecisionRow.outcome == ControllerDecisionOutcome.PENDING.value,
            )
            .order_by(ControllerDecisionRow.attempt_index)
        )
        with self._open() as session:
            rows = list(session.scalars(stmt))
        if len(rows) > 1:
            raise ValueError(f"Run '{run_id}' has {len(rows)} pending decisions")
        if not rows:
            return None
        row = rows[0]
        return row.attempt_id, ControllerDecision.model_validate(row.payload)

    def save_event(self, run_event: RunEvent) -> None:
        with self._open() as session, session.begin():
            self._merge_event(session, run_event)

    def events_for(self, run_id: str) -> list[RunEvent]:
        stmt = (
            select(RunEventRow).where(RunEventRow.run_id == run_id).order_by(RunEventRow.sequence)
        )
        with self._open() as session:
            return [RunEvent.model_validate(row.payload) for row in session.scalars(stmt)]

    # ── Orchestrator 原子提交 ────────────────────────────────────────────

    def commit_attempt_outcome(
        self,
        *,
        run: Run,
        attempt: Attempt,
        findings: Iterable[Finding],
        decision: ControllerDecision,
        run_event: RunEvent,
    ) -> None:
        """原子提交一场有效 Attempt 的全部权威状态。

        任一步失败都会回滚;调用方只能用同一组稳定 ID 重试本事务,
        不得重新执行目标。
        """
        finding_list = list(findings)
        self._validate_attempt_commit(run, attempt, finding_list, decision, run_event)
        with self._open() as session, session.begin():
            self._merge_run(session, run)
            self._merge_attempt(session, attempt)
            for finding in finding_list:
                self._merge_finding(session, finding)
            self._merge_decision(session, run.id, attempt.id, decision)
            self._merge_event(session, run_event)

    def commit_decision_selected(
        self,
        *,
        run: Run,
        attempt_id: str,
        decision: ControllerDecision,
        run_event: RunEvent,
    ) -> None:
        if decision.outcome is not ControllerDecisionOutcome.PENDING:
            raise ValueError("新选择只能提交 PENDING ControllerDecision")
        if run_event.run_id != run.id or run_event.attempt_id != attempt_id:
            raise ValueError("decision selected 的 RunEvent 关联不一致")
        with self._open() as session, session.begin():
            self._merge_run(session, run)
            self._merge_decision(session, run.id, attempt_id, decision)
            self._merge_event(session, run_event)

    def commit_abandonment(
        self,
        *,
        run: Run,
        attempt_id: str,
        decision: ControllerDecision,
        run_events: Iterable[RunEvent],
    ) -> None:
        if decision.outcome is not ControllerDecisionOutcome.ABANDONED:
            raise ValueError("abandonment 只能提交 ABANDONED ControllerDecision")
        event_list = list(run_events)
        if not event_list:
            raise ValueError("abandonment 至少需要一条 RunEvent")
        for run_event in event_list:
            if run_event.run_id != run.id:
                raise ValueError("abandonment 的 RunEvent.run_id 不一致")
            if run_event.attempt_id is not None and run_event.attempt_id != attempt_id:
                raise ValueError("abandonment 的 RunEvent.attempt_id 不一致")
        with self._open() as session, session.begin():
            self._merge_run(session, run)
            self._merge_decision(session, run.id, attempt_id, decision)
            for run_event in event_list:
                self._merge_event(session, run_event)

    def commit_run_state(self, *, run: Run, run_event: RunEvent) -> None:
        if run_event.run_id != run.id:
            raise ValueError("RunEvent.run_id 与 Run.id 不一致")
        with self._open() as session, session.begin():
            self._merge_run(session, run)
            self._merge_event(session, run_event)

    # ── 行级映射集中在此,事务方法不复制字段列表 ──────────────────────────

    def _merge_run(self, session: Session, run: Run) -> None:
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

    def _merge_attempt(self, session: Session, attempt: Attempt) -> None:
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

    def _merge_finding(self, session: Session, finding: Finding) -> None:
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

    def _merge_decision(
        self,
        session: Session,
        run_id: str,
        attempt_id: str,
        decision: ControllerDecision,
    ) -> None:
        session.merge(
            ControllerDecisionRow(
                id=_decision_id(run_id, decision.attempt_index),
                run_id=run_id,
                attempt_id=attempt_id,
                attempt_index=decision.attempt_index,
                controller=decision.controller,
                selected_strategy_id=decision.selected_strategy_id,
                outcome=decision.outcome.value,
                payload=decision.model_dump(mode="json"),
            )
        )

    def _merge_event(self, session: Session, run_event: RunEvent) -> None:
        session.merge(
            RunEventRow(
                id=run_event.id,
                run_id=run_event.run_id,
                attempt_id=run_event.attempt_id,
                sequence=run_event.sequence,
                event_type=run_event.event_type.value,
                created_at=run_event.created_at.replace(tzinfo=None),
                payload=run_event.model_dump(mode="json"),
            )
        )

    @staticmethod
    def _validate_attempt_commit(
        run: Run,
        attempt: Attempt,
        findings: list[Finding],
        decision: ControllerDecision,
        run_event: RunEvent,
    ) -> None:
        if attempt.run_id != run.id:
            raise ValueError("Attempt.run_id 与 Run.id 不一致")
        if decision.outcome is not ControllerDecisionOutcome.COMPLETED:
            raise ValueError("有效 Attempt 只能提交 COMPLETED ControllerDecision")
        if decision.selected_strategy_id != attempt.strategy_id:
            raise ValueError("ControllerDecision 与 Attempt.strategy_id 不一致")
        if run_event.run_id != run.id or run_event.attempt_id != attempt.id:
            raise ValueError("Attempt commit 的 RunEvent 关联不一致")
        for finding in findings:
            if finding.run_id != run.id or finding.attempt_id != attempt.id:
                raise ValueError("Finding 与 Attempt/Run 关联不一致")

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

    def success_metrics(self, run_id: str) -> SuccessMetrics:
        """按 triad 语义聚合,不依赖可调整的分档数字。"""
        return derive_success_metrics(self.attempts_for(run_id), self.findings_for(run_id))

    def attempt_success_rate(self, run_id: str) -> dict[str, float]:
        """Agent 生成违规行为的比例。校准的主指标。"""
        return self.success_metrics(run_id).attempt_success_rates()

    def impact_success_rate(self, run_id: str) -> dict[str, float]:
        """违规行为实际产生影响的比例。纵深防御指标。"""
        return self.success_metrics(run_id).impact_success_rates()

    def queries_to_first_attempt_success(self, run_id: str) -> int | None:
        """首次 Attempt 成功的位置;未成功返回 None。"""
        return self.success_metrics(run_id).queries_to_first_attempt_success

    def queries_to_first_impact_success(self, run_id: str) -> int | None:
        """首次 Impact 成功的位置;未成功返回 None。"""
        return self.success_metrics(run_id).queries_to_first_impact_success


def _decision_id(run_id: str, attempt_index: int) -> str:
    return f"{run_id}:decision:{attempt_index}"


def _configure_sqlite_connection(dbapi_connection, _connection_record) -> None:
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.close()
