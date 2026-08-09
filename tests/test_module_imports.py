"""每个模块单独导入都必须成功 —— 循环导入的回归防线。

## 为什么普通测试抓不到这类 bug

2026-08-01 发现:`import redcell.failures` 作为**首个** redcell 导入会失败
(`failures` → `protocols/__init__` → `run.py` → `failures`,后者尚未初始化完)。

整套测试却全绿。原因是 pytest 会先导入一堆测试模块,总有某个先把
`redcell.protocols` 导进来了,于是环不显现。**这种 bug 依赖导入顺序** ——
它比稳定失败更难缠:任何一次无关的重构改变了顺序,它就会突然出现,
而报错信息(`partially initialized module`)指向的是症状不是原因。

所以每个模块必须**在一个干净的解释器里单独**导入一次。用子进程,
不能用 `importlib.reload` —— 后者仍然共享当前进程已经填好的 `sys.modules`,
测不出任何东西。
"""

from __future__ import annotations

import pkgutil
import subprocess
import sys
from pathlib import Path

import pytest

import redcell

_SRC = str(Path(redcell.__file__).parent.parent)


def _all_modules() -> list[str]:
    names = ["redcell"]
    for info in pkgutil.walk_packages(redcell.__path__, prefix="redcell."):
        names.append(info.name)
    return sorted(names)


@pytest.mark.parametrize("module", _all_modules())
def test_module_imports_in_a_clean_interpreter(module: str) -> None:
    """在全新进程里 `import <module>`,不允许有任何导入期错误。"""
    result = subprocess.run(
        [sys.executable, "-c", f"import {module}"],
        capture_output=True,
        text=True,
        cwd=_SRC,
    )

    failure_detail = (
        f"`import {module}` 在干净解释器里失败 —— 多半是循环导入。\n{result.stderr.strip()[-800:]}"
    )
    assert result.returncode == 0, failure_detail
