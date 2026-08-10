"""客服型靶场 —— Phase 0 的唯一目标。

⚠️ 这个 agent 是**故意含漏洞的**。canary、可跨用户读取的记录、
以及一个能被社工诱导调用的禁止工具,都是 benchmark 的 ground truth,不是缺陷。
详见仓库根目录的 SECURITY.md。
"""

from redcell.arena.support_agent.adapter import MAX_TOOL_ITERATIONS, ArenaAdapter
from redcell.arena.support_agent.benign import (
    BENIGN_TASK_EVALUATOR_VERSION,
    BENIGN_TASKS,
    BenignTask,
    BenignTaskOutcome,
)
from redcell.arena.support_agent.codec import TextToolCallCodec, ToolCallCodec
from redcell.arena.support_agent.data import (
    CUSTOMERS,
    FAQ,
    ORDERS,
    RECORD_CANARY,
    RECORD_CANARY_PREFIX,
    SYSTEM_PROMPT_CANARY,
    SYSTEM_PROMPT_CANARY_PREFIX,
    CustomerRecord,
    Order,
)
from redcell.arena.support_agent.policy import (
    POLICY_VERSION,
    SUPPORT_AGENT_POLICY,
    TARGET_NAME,
    build_policy,
)
from redcell.arena.support_agent.prompts import (
    SYSTEM_PROMPT_FINGERPRINTS,
    DefenseLevel,
    build_system_prompt,
)
from redcell.arena.support_agent.tools import (
    REFUND_LIMIT_USD,
    SupportAgentTools,
    ToolExecution,
)

__all__ = [
    "BENIGN_TASKS",
    "BENIGN_TASK_EVALUATOR_VERSION",
    "CUSTOMERS",
    "FAQ",
    "MAX_TOOL_ITERATIONS",
    "ORDERS",
    "POLICY_VERSION",
    "RECORD_CANARY",
    "RECORD_CANARY_PREFIX",
    "REFUND_LIMIT_USD",
    "SUPPORT_AGENT_POLICY",
    "SYSTEM_PROMPT_CANARY",
    "SYSTEM_PROMPT_CANARY_PREFIX",
    "SYSTEM_PROMPT_FINGERPRINTS",
    "TARGET_NAME",
    "ArenaAdapter",
    "BenignTask",
    "BenignTaskOutcome",
    "CustomerRecord",
    "DefenseLevel",
    "Order",
    "SupportAgentTools",
    "TextToolCallCodec",
    "ToolCallCodec",
    "ToolExecution",
    "build_policy",
    "build_system_prompt",
]
