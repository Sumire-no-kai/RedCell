"""靶场 A:`ops-console` —— 公司内部工单台,权限语义是**角色等级**。

与客服靶场(资源归属)的区别:同一套工具对不同角色开放的动作不同。默认登录身份是
一线坐席 `agent_l1`;审计记录与退款审批只对主管(L2)开放,密码重置只对管理员开放。
设计见 `docs/ARENA_REGISTRY_DESIGN.md` §4。
"""

from redcell.arena.ops_console.arena import OPS_CONSOLE_ARENA, OPS_CONSOLE_ARENA_VERSION
from redcell.arena.ops_console.benign import BENIGN_TASKS
from redcell.arena.ops_console.cases import POSITIVE_CASES
from redcell.arena.ops_console.data import (
    AGENTS,
    AUDIT_CANARY,
    AUDIT_CANARY_PREFIX,
    AUDIT_LOG,
    KB,
    SYSTEM_PROMPT_CANARY,
    SYSTEM_PROMPT_CANARY_PREFIX,
    TICKETS,
    USERS,
    AgentRecord,
    AuditEntry,
    Ticket,
    UserAccount,
)
from redcell.arena.ops_console.policy import OPS_CONSOLE_POLICY, POLICY_VERSION, TARGET_NAME
from redcell.arena.ops_console.prompts import (
    DEFENCE_BLOCKS,
    SYSTEM_PROMPT_FINGERPRINTS,
    build_base_role,
    build_system_prompt,
)
from redcell.arena.ops_console.tools import (
    CONFIRMATION_REQUIRED_TOOLS,
    REFUND_APPROVAL_LIMIT_USD,
    ROLE_REQUIREMENTS,
    OpsConsoleTools,
)

__all__ = [
    "AGENTS",
    "AUDIT_CANARY",
    "AUDIT_CANARY_PREFIX",
    "AUDIT_LOG",
    "BENIGN_TASKS",
    "CONFIRMATION_REQUIRED_TOOLS",
    "DEFENCE_BLOCKS",
    "KB",
    "OPS_CONSOLE_ARENA",
    "OPS_CONSOLE_ARENA_VERSION",
    "OPS_CONSOLE_POLICY",
    "POLICY_VERSION",
    "POSITIVE_CASES",
    "REFUND_APPROVAL_LIMIT_USD",
    "ROLE_REQUIREMENTS",
    "SYSTEM_PROMPT_CANARY",
    "SYSTEM_PROMPT_CANARY_PREFIX",
    "SYSTEM_PROMPT_FINGERPRINTS",
    "TARGET_NAME",
    "TICKETS",
    "USERS",
    "AgentRecord",
    "AuditEntry",
    "OpsConsoleTools",
    "Ticket",
    "UserAccount",
    "build_base_role",
    "build_system_prompt",
]
