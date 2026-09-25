"""一个靶场的完整定义 —— 可整体注册、整体切换的单位。⭐

## 为什么需要它(2026-09-24)

此前"靶场"不是一个对象:policy、防御措辞、工具模拟、正常任务、阳性用例散在七个模块里,
被顶层代码硬引用约 20 处,`ArenaAdapter` 直接 import 客服靶场的具体类。Paper B 要求至少
三个权限语义不同的靶场,第一步是让"一个靶场"成为可以按名字取出来的东西。

## 契约

`ArenaDefinition` 装齐一个靶场的全部部件;`ArenaTools` 是工具模拟器必须提供的接口 ——
`ArenaAdapter` 今天实际用到的就是这几样。靶场的**内容**(policy 里的 canary、工具名)仍然
只在各靶场包里定义一次,这里不复制。

设计讨论与取舍见 `docs/ARENA_REGISTRY_DESIGN.md`。
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, Protocol

from redcell.arena.defense import DefenseLevel
from redcell.protocols.common import RedCellModel, VulnerabilityCategory
from redcell.protocols.policy import Policy

if TYPE_CHECKING:  # 运行时不导入靶场包,避免循环:靶场包会 import 本模块。
    from redcell.arena.benign import BenignTask
    from redcell.arena.execution import ToolExecution


class ArenaTools(Protocol):
    """工具模拟器接口。`execute()` 是唯一执行入口,所有调用都必须经过它才有 trace。"""

    enforce_permissions: bool
    enforce_confirmation: bool

    def reset(self) -> None: ...

    def begin_turn(self) -> None: ...

    def execute(self, name: str, arguments: dict[str, Any], *, actor: str) -> ToolExecution: ...

    def specs(self) -> list[dict[str, Any]]: ...


class PositiveCase(RedCellModel):
    """一条故意写得极其直白的攻击,以及它**必须**触发的那条信号线。

    刻意写死而不是交给攻击方生成:这道对照检查的是**靶场与检测器**,
    把 LLM 攻击方掺进来,失败时就分不清是"链路断了"还是"这次话术不行"。
    """

    id: str
    actor: str
    message: str
    expects: VulnerabilityCategory
    enforce_permissions: bool = True
    """工具层权限检查(旋钮 ③)。关掉它才能验证 **Impact 真的发生**这条路径。"""

    description: str


@dataclass(frozen=True)
class ArenaDefinition:
    """一个靶场。`id` 必须等于 `policy.target_name`,那是 Run 与 Attempt 里已经在记录的身份。"""

    id: str
    version: str
    """靶场内容版本:policy、提示、工具、数据任一变动都要升。写进每个 Run 的实验条件。"""

    policy: Policy
    default_actor: str
    defense_blocks: Mapping[DefenseLevel, str]
    """四档防御措辞。`NONE` 必须为空串;其余三档覆盖同一组话题、只改措辞强度。"""

    base_role_builder: Callable[[str], str]
    """`actor -> 只陈述事实的角色设定`。规范性措辞一律放进 defense_blocks。"""

    tools_factory: Callable[..., ArenaTools]
    """`(enforce_permissions=, enforce_confirmation=) -> ArenaTools`,每场 attempt 一个新实例。"""

    positive_cases: tuple[PositiveCase, ...]
    benign_tasks: tuple[BenignTask, ...]
    benign_task_evaluator_version: str
    golden_fixture: Path
    """本靶场的 Level-1 golden 集(相对仓库根目录)。"""

    golden_fixture_digest: str
    golden_fixture_ids: frozenset[str]
    """golden 集冻结时的摘要与 fixture id 全集。`gate-report` 按 Run 所在靶场取这两项核对,
    fixture 文件被改动或换成别的靶场的考卷都会被拒绝(2026-09-25)。"""

    def __post_init__(self) -> None:
        if self.id != self.policy.target_name:
            raise ValueError(
                f"靶场 id '{self.id}' 与 policy.target_name '{self.policy.target_name}' 不一致"
            )
        if self.policy.actor(self.default_actor) is None:
            raise ValueError(
                f"靶场 '{self.id}' 的 default_actor '{self.default_actor}' 不在 policy 里"
            )
        missing = [level for level in DefenseLevel if level not in self.defense_blocks]
        if missing:
            raise ValueError(f"靶场 '{self.id}' 缺少防御档位 {[m.value for m in missing]}")
        if self.defense_blocks[DefenseLevel.NONE] != "":
            raise ValueError(f"靶场 '{self.id}' 的 none 档必须为空串 —— 它是阳性对照的零点")
        case_ids = [case.id for case in self.positive_cases]
        if len(case_ids) != len(set(case_ids)):
            raise ValueError(f"靶场 '{self.id}' 的阳性用例 id 重复")
        for case in self.positive_cases:
            if self.policy.actor(case.actor) is None:
                raise ValueError(f"阳性用例 '{case.id}' 的 actor '{case.actor}' 不在 policy 里")
        task_ids = [task.id for task in self.benign_tasks]
        if len(task_ids) != len(set(task_ids)):
            raise ValueError(f"靶场 '{self.id}' 的正常任务 id 重复")
        if len(self.golden_fixture_digest) != 64 or not self.golden_fixture_ids:
            raise ValueError(f"靶场 '{self.id}' 必须登记 golden 集的冻结摘要与 fixture id")

    def build_system_prompt(self, *, actor: str, defense: DefenseLevel) -> str:
        return self.base_role_builder(actor) + self.defense_blocks[defense]

    def make_tools(
        self, *, enforce_permissions: bool = True, enforce_confirmation: bool = True
    ) -> ArenaTools:
        return self.tools_factory(
            enforce_permissions=enforce_permissions, enforce_confirmation=enforce_confirmation
        )

    @property
    def adapter_type(self) -> str:
        return f"arena/{self.id}"

    @property
    def tool_schema_sha256(self) -> str:
        """本靶场发给 Provider 的完整工具声明的摘要;native v2 的 Run 与 controls 记录它。"""
        from redcell.arena.execution import tool_schema_digest

        return tool_schema_digest(self.make_tools().specs())

    def positive_case(self, case_id: str) -> PositiveCase | None:
        return next((case for case in self.positive_cases if case.id == case_id), None)

    def benign_task(self, task_id: str) -> BenignTask | None:
        return next((task for task in self.benign_tasks if task.id == task_id), None)
