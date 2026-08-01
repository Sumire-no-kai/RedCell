"""最底层的共享类型 —— 不依赖 redcell 的任何其他模块。

## 为什么需要这一层

`failures.py`(运行故障)与 `protocols/`(协议层)都需要 `RedCellModel` 和
`CostRecord`。而 `protocols/run.py` 又需要 `failures.FailureRecord`
(`RunEvent.failure` 字段)。于是形成了一个环:

```
failures.py  →  protocols.common(取 RedCellModel)
                    ↓ 导入子模块会先执行 protocols/__init__.py
                protocols/run.py  →  failures.FailureRecord   ✗ 此时 failures 还没初始化完
```

症状是 `ImportError: cannot import name 'FailureRecord' from partially
initialized module`。**它依赖导入顺序** —— 只要有别的模块先导入了
`redcell.protocols`,环就不会显现,所以整套测试都碰不到它;
但 `from redcell.failures import FailureKind` 作为首个 redcell 导入必炸。

## 解法:把真正共享的基础类型下沉到两者之下

```
        redcell/_base.py          ← 本模块,不依赖任何 redcell 模块
           ↑            ↑
     failures.py    protocols/*   ← 两边都只向下依赖,环消失
```

`protocols.common` 与 `protocols.trace` 保留 re-export,现有 import 路径不变。
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict


class RedCellModel(BaseModel):
    """协议层所有模型的基类。

    `extra="forbid"`:多写一个字段就报错。协议层是所有下游组件的契约,
    拼错字段名却静默通过是最难查的一类 bug。
    """

    model_config = ConfigDict(extra="forbid", validate_assignment=True)


class CostRecord(RedCellModel):
    """一次调用或一段执行的资源消耗。

    放在最底层是因为**故障记录也要带成本** —— 一次失败的 attempt 同样烧了 token,
    不记就会让预算统计系统性偏低。
    """

    prompt_tokens: int = 0
    completion_tokens: int = 0
    usd: float = 0.0
    wall_ms: float = 0.0

    @property
    def total_tokens(self) -> int:
        return self.prompt_tokens + self.completion_tokens
