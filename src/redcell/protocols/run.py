"""Run —— 一次评测任务。

字段依据 PRD §15。存在的意义不只是"一条记录":
Run 把**目标版本、policy 版本、算法、预算、随机种子**绑在一起,
少了其中任何一项,跑出来的数字就无法归因 ——
"这个结论是在哪个 policy、哪个算法、多大预算下得到的"必须永远可查。
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum

from pydantic import Field

from redcell.budget import BudgetLimit, BudgetLimits, BudgetUsage
from redcell.protocols.common import REDCELL_PROTOCOL_VERSION, RedCellModel, new_id


class RunStatus(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    """跑到预算用尽,正常结束。"""

    FAILED = "failed"
    """异常中断。**结论不可用** —— 部分完成的 run 会系统性低估发现数。"""

    ABORTED = "aborted"
    """人工中止。同样不可用于结论。"""


class Run(RedCellModel):
    id: str = Field(default_factory=new_id)
    target_name: str
    policy_version: str
    adapter_type: str
    algorithm: str
    """搜索算法标识,如 "static" / "random" / "thompson"。消融对比的分组键。"""

    limits: BudgetLimits
    usage: BudgetUsage = Field(default_factory=BudgetUsage)
    status: RunStatus = RunStatus.PENDING
    stopped_by: BudgetLimit | None = None
    """因为哪一项预算耗尽而停止。让"为什么停了"永远是明确的。"""

    seed: int | None = None
    """实验随机种子。多 seed 重复是报置信区间的前提,单次结果说明不了任何事。"""

    target_model: str | None = None
    target_temperature: float | None = None
    attacker_model: str | None = None
    strategy_ids: list[str] = Field(default_factory=list)
    protocol_version: str = REDCELL_PROTOCOL_VERSION
    notes: str | None = None

    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    started_at: datetime | None = None
    completed_at: datetime | None = None

    @property
    def is_conclusive(self) -> bool:
        """这次 run 的结果能不能拿来下结论。

        只有正常跑完的 run 算数。中断的 run 会系统性低估发现数,
        混进统计里会把结论往"没找到东西"的方向拉,而且不会有任何提示。
        """
        return self.status is RunStatus.COMPLETED
