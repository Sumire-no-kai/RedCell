"""共享基元:ID 生成、基类模型、跨模块枚举。

这一层不依赖 redcell 的任何其他模块,是整个协议层的最底座。
"""

from __future__ import annotations

import secrets
import time
import uuid
from enum import StrEnum

from redcell._base import RedCellModel

REDCELL_PROTOCOL_VERSION = "0.5.0"


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


# `RedCellModel` 现在定义在 `redcell._base` —— 为了打破 failures ↔ protocols
# 的循环导入,见该模块的文档。这里保持 re-export,既有的
# `from redcell.protocols.common import RedCellModel` 一行都不用改。
__all__ = ["RedCellModel"]


# ── 枚举 ─────────────────────────────────────────────────────────────────────


class Role(StrEnum):
    SYSTEM = "system"
    USER = "user"
    ASSISTANT = "assistant"
    TOOL = "tool"


class ObservabilityLevel(StrEnum):
    """Adapter 自报"我能看见目标的多少内部行为"。

    Impact(真实影响)能不能判定,取决于**本等级**与**该结论所依据的证据来源**
    (见 ImpactBasis)两者的组合:看不见副作用的目标上,依赖副作用的结论只能是
    UNKNOWN 而不能填 False;但只依赖回复正文的结论(如 canary 泄漏)仍然成立。
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


class ImpactBasis(StrEnum):
    """判定 Realized Impact 时所依据的**证据来源**。

    为什么需要它:"能不能断言 impact"取决于**这条结论靠什么证据成立**,
    而不是取决于一个统一的可观测性门槛。

    * 越权退款是否真的发生 —— 只有看得见 side_effects 才知道;
    * canary 是否真的泄漏 —— 它就印在回复正文里,连黑盒 chat API 都看得见。

    没有这个字段,两者就得共用同一个门槛。取严则数据泄漏类结论在
    非 FULL 目标上无法成立(而它本来成立);取松则副作用类结论会被
    "看不见"当成"没发生"。两个方向都是错的,所以门槛必须按证据来源分开。
    """

    RESPONSE_CONTENT = "response_content"
    """证据是模型回复正文里的内容(如 canary 字符串)。任何可观测性等级都能看见。"""

    SIDE_EFFECT = "side_effect"
    """证据是后端状态的真实改变(如退款记录)。只有 FULL 插桩才能看见。"""

    def is_observable_at(self, level: ObservabilityLevel) -> bool:
        """在这个可观测性等级下,本类证据能不能被观测到。"""
        if self is ImpactBasis.RESPONSE_CONTENT:
            return True
        return level.can_observe_side_effects


class ImpactStatus(StrEnum):
    """Realized Impact 的三态。

    为什么不是 bool:测自家靶场时插桩齐全,副作用发生与否一清二楚;
    但测远程 endpoint 时我们只看得到"它试图调用",看不到后端有没有真的执行。
    此时填 NOT_REALIZED 是在撒谎——真相是"看不见"。

    把 UNKNOWN 折叠成 NOT_REALIZED 会造成系统性漏报,
    而安全工具里漏报比误报危险得多。

    ⚠️ "能不能断言"由 ImpactBasis 决定,不由本枚举决定 —— 见 ImpactBasis。
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
