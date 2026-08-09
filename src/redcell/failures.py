"""结构化运行故障。

异常负责打断控制流,FailureRecord 负责保存可判定、可持久化的事实。
Orchestrator 不解析异常字符串;它只依据这里的 kind / stage / retry_safety
决定重试、放弃 Attempt 或终止 Run。

## 为什么 `RATE_LIMITED` 要从 `NETWORK_TRANSIENT` 里独立出来

一开始 429 和 5xx 都归在 `NETWORK_TRANSIENT`。分开有两个理由,
**第二个是正确性问题,不只是参数调优:**

1. **退避曲线不同。** 免费层的 429 需要秒到分钟级的等待
   (实测 GLM 需累计等 116 秒才恢复),而 5xx / 超时通常几秒就好。
   共用一套参数,要么对 429 太短(白白判死),要么对 5xx 太长(白白拖慢)。
2. **⚠️ 送达状态不同 —— 这条更重要。**
   429 是服务端**在处理之前**明确拒绝,所以请求**确定没有送达**
   (`NOT_SENT` / 副作用 `NONE` / 重试 `SAFE`);
   而网络超时**无法确定**请求是否已被处理(`UNKNOWN`),
   在不支持幂等键的目标上会升级为 `AMBIGUOUS_SIDE_EFFECT` 而**禁止重试**。

   把 429 混进 `NETWORK_TRANSIENT`,就会让一个**本可安全重试**的限流
   被当成"可能已产生副作用"而放弃 —— 在免费层上这会频繁误伤。

3. 附带好处:跑批日志里能直接分出"**我们发太快了**"(该调节流)
   和"**对方挂了**"(只能等)。这两种情况的处置完全不同。
"""

from __future__ import annotations

import re
from enum import StrEnum

from pydantic import Field

# ⚠️ 只依赖 `redcell._base`,**不要**改成从 `redcell.protocols.*` 导入 ——
# 那会重新制造 failures ↔ protocols 的循环导入(见 `_base.py` 的模块文档)。
from redcell._base import CostRecord, RedCellModel


class FailureKind(StrEnum):
    AGENT_TRANSIENT = "agent_transient"
    NETWORK_TRANSIENT = "network_transient"
    RATE_LIMITED = "rate_limited"
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
            FailureKind.RATE_LIMITED,
            FailureKind.PERSISTENCE_TRANSIENT,
        }


class FailureStage(StrEnum):
    PREFLIGHT = "preflight"
    CONTROLLER_SELECTION = "controller_selection"
    USAGE_ACCOUNTING = "usage_accounting"
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
