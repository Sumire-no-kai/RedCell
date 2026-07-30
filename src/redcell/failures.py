"""结构化运行故障。

异常负责打断控制流,FailureRecord 负责保存可判定、可持久化的事实。
Orchestrator 不解析异常字符串;它只依据这里的 kind / stage / retry_safety
决定重试、放弃 Attempt 或终止 Run。
"""

from __future__ import annotations

import re
from enum import StrEnum

from pydantic import Field

from redcell.protocols.common import RedCellModel
from redcell.protocols.trace import CostRecord


class FailureKind(StrEnum):
    AGENT_TRANSIENT = "agent_transient"
    NETWORK_TRANSIENT = "network_transient"
    PERSISTENCE_TRANSIENT = "persistence_transient"
    CONFIGURATION = "configuration"
    PROTOCOL = "protocol"
    SCORING = "scoring"
    PERSISTENCE_FATAL = "persistence_fatal"
    AMBIGUOUS_SIDE_EFFECT = "ambiguous_side_effect"
    EXPERIMENT_INVALID = "experiment_invalid"
    INTERNAL = "internal"

    @property
    def transient(self) -> bool:
        return self in {
            FailureKind.AGENT_TRANSIENT,
            FailureKind.NETWORK_TRANSIENT,
            FailureKind.PERSISTENCE_TRANSIENT,
        }


class FailureStage(StrEnum):
    PREFLIGHT = "preflight"
    RESET = "reset"
    GENERATION = "generation"
    TARGET_SEND = "target_send"
    TOOL_EXECUTION = "tool_execution"
    SCORING = "scoring"
    PERSISTENCE = "persistence"
    REPORTING = "reporting"
    ORCHESTRATION = "orchestration"


class DeliveryStatus(StrEnum):
    NOT_SENT = "not_sent"
    SENT = "sent"
    UNKNOWN = "unknown"


class SideEffectStatus(StrEnum):
    NONE = "none"
    REALIZED = "realized"
    UNKNOWN = "unknown"


class RetrySafety(StrEnum):
    SAFE = "safe"
    REQUIRES_IDEMPOTENCY_KEY = "requires_idempotency_key"
    REQUIRES_RESET = "requires_reset"
    UNSAFE = "unsafe"
    UNKNOWN = "unknown"


class FailureRecord(RedCellModel):
    """一次运行故障的持久化语义,不包含凭据或完整敏感响应。"""

    kind: FailureKind
    stage: FailureStage
    code: str
    message: str
    cause_type: str
    retry_safety: RetrySafety
    delivery_status: DeliveryStatus = DeliveryStatus.UNKNOWN
    side_effect_status: SideEffectStatus = SideEffectStatus.UNKNOWN
    usage: CostRecord = Field(default_factory=CostRecord)
    details: dict[str, str | int | float | bool | None] = Field(default_factory=dict)

    @property
    def retryable(self) -> bool:
        return self.kind.transient and self.retry_safety in {
            RetrySafety.SAFE,
            RetrySafety.REQUIRES_IDEMPOTENCY_KEY,
            RetrySafety.REQUIRES_RESET,
        }

    @property
    def serious(self) -> bool:
        return not self.retryable


class StructuredExecutionError(RuntimeError):
    """携带 FailureRecord 的类型化异常基类。"""

    def __init__(self, failure: FailureRecord) -> None:
        super().__init__(
            f"{failure.kind.value}@{failure.stage.value} [{failure.code}]: {failure.message}"
        )
        self.failure = failure


class TransientAgentError(StructuredExecutionError):
    """Generator / agent 侧明确可恢复的临时故障。"""


class TransientNetworkError(StructuredExecutionError):
    """传输或远端服务明确可安全恢复的临时故障。"""


class SeriousExecutionError(StructuredExecutionError):
    """配置、协议、评分或内部不变量等不可继续的严重错误。"""


class AmbiguousSideEffectError(SeriousExecutionError):
    """请求可能已执行且无法确定副作用,禁止普通重试。"""


_SECRET_PATTERNS = (
    re.compile(r"(?i)(authorization:\s*bearer\s+)\S+"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{12,}\b"),
    re.compile(r"(?i)(api[_-]?key\s*[=:]\s*)\S+"),
)


def safe_error_message(exc: Exception) -> str:
    """限制长度并清理常见凭据形态,供持久化错误摘要使用。"""
    message = str(exc)[:1000]
    for pattern in _SECRET_PATTERNS:
        if pattern.groups:
            message = pattern.sub(r"\1[REDACTED]", message)
        else:
            message = pattern.sub("[REDACTED]", message)
    return message
