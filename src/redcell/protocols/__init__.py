"""RedCell 协议层 —— 所有组件之间的契约。

改这里的任何结构都会波及靶场、执行器、检测器、bandit 和报告,
按 AGENTS.md §3,属于"难以回退的决策",改动前需先讨论。
"""

from redcell.protocols.adapter import (
    AdapterInput,
    AdapterOutput,
    Message,
    SideEffect,
    TargetAdapter,
    ToolCall,
    ToolResult,
    TraceMetadata,
)
from redcell.protocols.common import (
    REDCELL_PROTOCOL_VERSION,
    FindingStatus,
    ImpactStatus,
    ObservabilityLevel,
    RedCellModel,
    Role,
    SeverityLevel,
    SignalChannel,
    VulnerabilityCategory,
    new_id,
    uuid7,
)
from redcell.protocols.finding import Evidence, Finding, ViolationTriad
from redcell.protocols.policy import (
    ActorPolicy,
    ConstraintKind,
    ParameterConstraint,
    Policy,
    ProtectedDataKind,
    ProtectedDatum,
    SystemPromptFingerprint,
    ToolPolicy,
)
from redcell.protocols.trace import (
    Attempt,
    CostRecord,
    ReproductionContext,
    SignalScore,
    Turn,
    build_attempt,
    compute_reward,
)

__all__ = [
    "REDCELL_PROTOCOL_VERSION",
    "ActorPolicy",
    "AdapterInput",
    "AdapterOutput",
    "Attempt",
    "ConstraintKind",
    "CostRecord",
    "Evidence",
    "Finding",
    "FindingStatus",
    "ImpactStatus",
    "Message",
    "ObservabilityLevel",
    "ParameterConstraint",
    "Policy",
    "ProtectedDataKind",
    "ProtectedDatum",
    "RedCellModel",
    "ReproductionContext",
    "Role",
    "SeverityLevel",
    "SideEffect",
    "SignalChannel",
    "SignalScore",
    "SystemPromptFingerprint",
    "TargetAdapter",
    "ToolCall",
    "ToolPolicy",
    "ToolResult",
    "TraceMetadata",
    "Turn",
    "ViolationTriad",
    "VulnerabilityCategory",
    "build_attempt",
    "compute_reward",
    "new_id",
    "uuid7",
]
