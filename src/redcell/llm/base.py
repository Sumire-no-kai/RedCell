"""LLMProvider —— 所有大模型调用的唯一出口。

存在的理由有两个,而且它们其实是同一件事:

1. **可测试性**:测试注入 ScriptedProvider,CI 里零网络、零成本、完全确定;
2. **省钱与换供应商**:W1–W2 全程用假 provider 开发,一分不花;
   真正接 API 时只换实现,上层逻辑一行不改。

任何组件都不允许绕过这层直接调 SDK。
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from pydantic import Field

from redcell.protocols.common import RedCellModel, Role


class LLMMessage(RedCellModel):
    role: Role
    content: str


class LLMResponse(RedCellModel):
    content: str
    model: str = "unknown"
    prompt_tokens: int = 0
    completion_tokens: int = 0
    latency_ms: float = 0.0
    raw: dict[str, Any] = Field(default_factory=dict)

    @property
    def total_tokens(self) -> int:
        return self.prompt_tokens + self.completion_tokens


class LLMProvider(ABC):
    @property
    @abstractmethod
    def name(self) -> str:
        """写进 trace,用于复现时确认当时用的是哪个 provider。"""

    @abstractmethod
    async def complete(
        self,
        messages: list[LLMMessage],
        *,
        model: str | None = None,
        temperature: float = 0.0,
        max_tokens: int | None = None,
    ) -> LLMResponse: ...


class LLMProviderExhaustedError(RuntimeError):
    """脚本化 provider 的预设回复用完了。

    这在测试里通常意味着被测代码比预期多调了一次 LLM——
    是个信号,不是噪音,所以直接抛出而不是静默返回空串。
    """
