"""阻止执行主机在长跑期间进入睡眠 —— 桌面侧的 `termux-wake-lock`。

## 为什么需要它(2026-08-18 的代价)

Phase 0.5b 的 144-cell 矩阵在跑了 9 小时 43 分后死于主机睡眠:机器 02:15 进入
**Modern Standby**、09:19 才出来,期间 `Adaptive Connected Standby` 周期性切断网络。
后果不是"暂停一下":

* Target 延迟中位数从 2.1 s 涨到 15.9 s(约 7 倍),越过客户端 60 s 超时;
* 超时 → 重试 → 放弃,单 Run 放弃率越过 10% 判据,**两个 seed block 直接作废**;
* 最后一次断网把整棵进程树带走,进程退出码 1、日志里连 traceback 都没有。

⚠️ **开跑前那道人工电源检查看不见这件事。** Runbook 当时要求
`powercfg /query SCHEME_CURRENT SUB_SLEEP` 确认自动睡眠为「从不」——而在只支持
`Standby (S0 Low Power Idle)` 的机器上,S3 已被禁用,**那个超时是死的**,
设成 0 也不会阻止 Modern Standby。检查通过了,机器照睡。

所以这条防线不能继续留在文档和人的记忆里,必须由**进程自己**持有。

## 为什么连 `ES_DISPLAY_REQUIRED` 一起要

`ES_SYSTEM_REQUIRED` 在 connected standby 机器上的语义与传统 S3 不同;而实测触发点是
**关屏**。把显示器一并钉住,消掉的是触发条件本身,而不是赌系统会尊重某一位标志。
代价是长跑期间屏幕常亮 —— 与烧掉一个正式 seed block 相比不值一提。

## 为什么获取失败就不许开跑

这正是 fail-closed 该管的形状:静默地少一条防线,和 2026-08-18 那次一模一样 ——
配置看着没问题,失败发生在无人看管的凌晨。宁可当场拒绝派发。

## 为什么非 Windows 是显式空操作,而不是假装成功

Termux 侧有自己的 `termux-wake-lock`,是 Runbook 的独立步骤。本模块不冒充它:
在别的平台返回一句"不适用",让日志说实话,好过给出一个并不存在的保证。
"""

from __future__ import annotations

import sys
from collections.abc import Callable, Iterator
from contextlib import contextmanager

ES_CONTINUOUS = 0x80000000
"""标志持续生效,直到本线程显式复位或退出 —— 而不是只影响下一次空闲判定。"""

ES_SYSTEM_REQUIRED = 0x00000001
ES_DISPLAY_REQUIRED = 0x00000002

WAKELOCK_FLAGS = ES_CONTINUOUS | ES_SYSTEM_REQUIRED | ES_DISPLAY_REQUIRED

NOT_APPLICABLE = "未获取(非 Windows 主机;Termux 请按 Runbook 使用 termux-wake-lock)"
HELD = "已获取(Windows:system + display,进程退出时释放)"


class HostWakelockError(RuntimeError):
    """无法阻止主机睡眠;此时不得派发正式 cell。"""


def _windows_set_execution_state(flags: int) -> int:  # pragma: no cover - 真实 Win32 调用
    import ctypes

    return int(ctypes.windll.kernel32.SetThreadExecutionState(ctypes.c_uint(flags)))


@contextmanager
def host_wakelock(
    *,
    platform_name: str | None = None,
    set_execution_state: Callable[[int], int] | None = None,
) -> Iterator[str]:
    """在上下文期间阻止主机睡眠;yield 一句可写进日志的状态说明。

    参数只为测试注入而存在:正式调用不传参,走真实平台与真实 Win32 API。
    """
    platform = sys.platform if platform_name is None else platform_name
    if platform != "win32":
        yield NOT_APPLICABLE
        return

    call = _windows_set_execution_state if set_execution_state is None else set_execution_state
    if call(WAKELOCK_FLAGS) == 0:
        raise HostWakelockError(
            "SetThreadExecutionState 拒绝了唤醒锁请求;主机可能在长跑中进入睡眠,拒绝派发正式 cell。"
        )
    try:
        yield HELD
    finally:
        # 只留 ES_CONTINUOUS 即为释放;不复位会把常亮状态泄漏给后续进程。
        call(ES_CONTINUOUS)
