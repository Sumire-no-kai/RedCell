"""主机唤醒锁的测试 —— 守住 2026-08-18 那次事故的三条教训。

那次矩阵死于 Modern Standby:开跑前的人工电源检查全绿,机器照样睡了七小时,
两个 seed block 作废。因此这里要钉死的不是"能调用 API",而是:

* 拿不到锁就**不许开跑**(而不是打条警告继续);
* 用完必须**释放**,包括抛异常那条路径 —— 否则常亮状态会泄漏给后续进程;
* 非 Windows 上**说实话**,不冒充成功。
"""

from __future__ import annotations

import pytest

from redcell.host_wakelock import (
    ES_CONTINUOUS,
    ES_DISPLAY_REQUIRED,
    ES_SYSTEM_REQUIRED,
    HELD,
    NOT_APPLICABLE,
    WAKELOCK_FLAGS,
    HostWakelockError,
    host_wakelock,
)


class _Recorder:
    """记下每次 SetThreadExecutionState 的入参,并可脚本化返回值。"""

    def __init__(self, *returns: int) -> None:
        self.calls: list[int] = []
        self._returns = list(returns) or [1]

    def __call__(self, flags: int) -> int:
        self.calls.append(flags)
        return self._returns[min(len(self.calls) - 1, len(self._returns) - 1)]


def test_windows_pins_both_system_and_display() -> None:
    """只钉 system 不够:实测的进入触发点是关屏。"""
    recorder = _Recorder()

    with host_wakelock(platform_name="win32", set_execution_state=recorder) as detail:
        assert detail == HELD
        assert recorder.calls == [WAKELOCK_FLAGS]

    acquired = recorder.calls[0]
    assert acquired & ES_CONTINUOUS
    assert acquired & ES_SYSTEM_REQUIRED
    assert acquired & ES_DISPLAY_REQUIRED


def test_windows_releases_on_exit() -> None:
    recorder = _Recorder()

    with host_wakelock(platform_name="win32", set_execution_state=recorder):
        pass

    assert recorder.calls[-1] == ES_CONTINUOUS


def test_windows_releases_even_when_the_body_raises() -> None:
    """崩溃路径同样要释放,否则屏幕常亮会泄漏给下一个进程。"""
    recorder = _Recorder()

    with (
        pytest.raises(ZeroDivisionError),
        host_wakelock(platform_name="win32", set_execution_state=recorder),
    ):
        raise ZeroDivisionError

    assert recorder.calls[-1] == ES_CONTINUOUS


def test_a_refused_request_blocks_the_run_instead_of_warning() -> None:
    """fail-closed:2026-08-18 的教训正是"少一条防线但照跑"。"""
    recorder = _Recorder(0)

    with (
        pytest.raises(HostWakelockError),
        host_wakelock(platform_name="win32", set_execution_state=recorder),
    ):
        raise AssertionError("不应进入正文")

    assert recorder.calls == [WAKELOCK_FLAGS]


def test_non_windows_is_an_explicit_no_op_not_a_fake_guarantee() -> None:
    """Termux 有自己的 termux-wake-lock;本模块不冒充它。"""
    recorder = _Recorder()

    with host_wakelock(platform_name="linux", set_execution_state=recorder) as detail:
        assert detail == NOT_APPLICABLE

    assert recorder.calls == []
