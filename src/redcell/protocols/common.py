"""共享基元:ID 生成、基类模型、跨模块枚举。

这一层不依赖 redcell 的任何其他模块,是整个协议层的最底座。
"""

from __future__ import annotations

import secrets
import time
import uuid
from enum import StrEnum

from pydantic import BaseModel, ConfigDict

REDCELL_PROTOCOL_VERSION = "0.3.0"


# ── ID ───────────────────────────────────────────────────────────────────────


def uuid7() -> uuid.UUID:
    """生成 UUIDv7(RFC 9562):前 48 位是毫秒时间戳,因此天然按时间有序。

    选它而不是 uuid4 的理由:attempt / trace 会按时间顺序大量写入,
    有序 ID 让"按时间翻 trace"和数据库索引都不需要额外的排序列。

    Python 3.11/3.12 的标准库还没有 uuid7(3.14 才加入),这里自己实现,
    以免为 15 行代码引入一个依赖。
    """
    timestamp_ms = int(time.time() * 1000)
    raw = bytearray(16)
    raw[0:6] = timestamp_ms.to_bytes(6, "big")
    raw[6:16] = secrets.token_bytes(10)
    raw[6] = (raw[6] & 0x0F) | 0x70  # version = 7
    raw[8] = (raw[8] & 0x3F) | 0x80  # variant = RFC 4122
    return uuid.UUID(bytes=bytes(raw))


def new_id() -> str:
    return str(uuid7())


# ── 基类 ─────────────────────────────────────────────────────────────────────


class RedCellModel(BaseModel):
    """协议层所有模型的基类。

    `extra="forbid"`:多写一个字段就报错。协议层是两个 agent(Claude Code / Codex)
    和所有下游组件的契约,拼错字段名却静默通过是最难查的一类 bug。
    """

    model_config = ConfigDict(extra="forbid", validate_assignment=True)


# ── 枚举 ─────────────────────────────────────────────────────────────────────


class Role(StrEnum):
    SYSTEM = "system"
    USER = "user"
    ASSISTANT = "assistant"
    TOOL = "tool"


class ObservabilityLevel(StrEnum):
    """Adapter 自报"我能看见目标的多少内部行为"。

    Impact(真实影响)能不能判定,完全取决于这个等级——
    看不见副作用的目标上,Impact 只能是 UNKNOWN,而不能填 False。
    见 ImpactStatus 的说明。
    """

    FULL = "full"
    """完整插桩:回复 + tool_calls + tool_results + side_effects 都可见(进程内靶场)。"""

    PARTIAL = "partial"
    """能看到 tool_calls,但看不到后端是否真的执行(典型的远程 HTTP agent)。"""

    RESPONSE_ONLY = "response_only"
    """只有文本回复(黑盒 chat API)。"""

    @property
    def can_observe_side_effects(self) -> bool:
        return self is ObservabilityLevel.FULL

    @property
    def can_observe_tool_calls(self) -> bool:
        return self in (ObservabilityLevel.FULL, ObservabilityLevel.PARTIAL)


class ImpactStatus(StrEnum):
    """Realized Impact 的三态。

    为什么不是 bool:测自家靶场时插桩齐全,副作用发生与否一清二楚;
    但测远程 endpoint 时我们只看得到"它试图调用",看不到后端有没有真的执行。
    此时填 NOT_REALIZED 是在撒谎——真相是"看不见"。

    把 UNKNOWN 折叠成 NOT_REALIZED 会造成系统性漏报,
    而安全工具里漏报比误报危险得多。
    """

    REALIZED = "realized"
    """确认产生了副作用 / 受保护数据确实被返回。"""

    NOT_REALIZED = "not_realized"
    """确认没有产生副作用(例如被后端权限层拦下),且我们有能力观测到这一点。"""

    UNKNOWN = "unknown"
    """目标可观测性不足,无法判定。既不算命中,也不算安全。"""


class VulnerabilityCategory(StrEnum):
    """MVP 覆盖的三类漏洞(PRD §4)。"""

    PROMPT_INJECTION = "prompt_injection"
    SENSITIVE_DATA_DISCLOSURE = "sensitive_data_disclosure"
    UNAUTHORIZED_TOOL_USE = "unauthorized_tool_use"


class SignalChannel(StrEnum):
    """确定性 reward 的两条独立信号线(见 docs/CONCEPTS.md「Reward v1」)。"""

    CANARY = "canary"
    """受保护数据泄漏线:完整 canary / canary 前缀 / system prompt 指纹。"""

    TOOL = "tool"
    """工具越权线:禁止工具 / 参数越权 / 触碰敏感工具。"""


class SeverityLevel(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class FindingStatus(StrEnum):
    OPEN = "open"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    FIXED = "fixed"
