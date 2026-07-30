"""SQLite 表结构。

**存储策略:可查询的列 + 完整 JSON payload。**

不把 Pydantic 模型逐字段映射成列,理由有两条:

1. **Trace 是深度嵌套的**(Run → Attempt → Turn → ToolCall/ToolResult/SideEffect)。
   拆成关系表要写一堆映射代码,而我们从来不需要按 tool_call 的某个字段做联表查询;
2. **协议还在演进。** 逐字段映射意味着每加一个字段就要写一次迁移,
   而 Phase 0 的协议几乎每批都在动。

抽出来单独成列的,只有**分配与筛选真正会用到的维度**:run / strategy / reward /
category / 时间。其余留在 payload 里,读出来仍是完整的 Pydantic 对象,零信息损失。

代价:没法对嵌套字段写任意 SQL。Attempt/Impact ASR 必须读取 Finding payload
里的 triad,不能从 reward 列反推;Phase 0 每个 Run 约百次 Attempt,优先保证语义正确。
规模扩大后可再把 attempted_action 单独成列,payload 里的原始数据不会丢。
"""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import JSON, DateTime, Float, ForeignKey, Index, Integer, String
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


def _utcnow() -> datetime:
    return datetime.now(UTC)


class RunRow(Base):
    __tablename__ = "runs"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    target_name: Mapped[str] = mapped_column(String, index=True)
    policy_version: Mapped[str] = mapped_column(String)
    algorithm: Mapped[str] = mapped_column(String, index=True)
    """消融对比的分组键。"""

    seed: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    """多 seed 重复是报置信区间的前提,所以它必须可查询。"""

    status: Mapped[str] = mapped_column(String, index=True)
    max_attempts: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    """预算点也是分组键 —— query-budget 曲线要按它分组。"""

    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow, index=True)
    payload: Mapped[dict] = mapped_column(JSON)


class AttemptRow(Base):
    __tablename__ = "attempts"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    run_id: Mapped[str] = mapped_column(String, ForeignKey("runs.id"), index=True)
    strategy_id: Mapped[str] = mapped_column(String, index=True)
    actor: Mapped[str] = mapped_column(String)
    reward: Mapped[float] = mapped_column(Float, index=True)
    turn_count: Mapped[int] = mapped_column(Integer)
    prompt_tokens: Mapped[int] = mapped_column(Integer, default=0)
    completion_tokens: Mapped[int] = mapped_column(Integer, default=0)
    cost_usd: Mapped[float] = mapped_column(Float, default=0.0)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow, index=True)
    payload: Mapped[dict] = mapped_column(JSON)


class FindingRow(Base):
    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    run_id: Mapped[str] = mapped_column(String, ForeignKey("runs.id"), index=True)
    attempt_id: Mapped[str] = mapped_column(String, index=True)
    category: Mapped[str] = mapped_column(String, index=True)
    title: Mapped[str] = mapped_column(String)
    status: Mapped[str] = mapped_column(String, index=True)
    severity: Mapped[str | None] = mapped_column(String, nullable=True)
    realized_impact: Mapped[str] = mapped_column(String, index=True)
    """三态的 Impact 需要单独成列 —— 报告里"确认发生 / 被拦下 / 观测不到"
    是三种要分开统计的结论,埋在 payload 里就没法直接聚合。"""

    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow, index=True)
    payload: Mapped[dict] = mapped_column(JSON)


Index("ix_attempts_run_strategy", AttemptRow.run_id, AttemptRow.strategy_id)
Index("ix_findings_run_category", FindingRow.run_id, FindingRow.category)
