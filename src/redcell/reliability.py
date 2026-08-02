"""Run 可靠性阈值 —— 少量偶发故障可继续,超过阈值则这次 Run 不再具有实验可信度。

## 为什么单独一个模块

它同时被两边需要:`retry.py`(判定用)与 `protocols/run.py`(落盘记录用)。
而 `retry.py` 依赖 `protocols`,若 `protocols/run.py` 反过来导入 `retry`,
就会重新制造 2026-08-01 Step 11 修掉的那种循环导入 ——
那种 bug 依赖导入顺序,测试全绿也照样存在。

所以按当时的修法把共享类型**下沉到两者之下**:本模块只依赖 `redcell._base`。
⚠️ **不要**为了省一个文件而把它搬回 `retry.py`,那会重新制造循环。
"""

from __future__ import annotations

from pydantic import Field

from redcell._base import RedCellModel


class ReliabilityPolicy(RedCellModel):
    """什么程度的运行故障会让这次 Run 不能用于下结论。

    ⚠️ **这组阈值必须随 Run 一起落盘**(`Run.reliability`)。
    它决定了"这次 run 算不算数",而事后只看结果是**看不出**当时用的是哪组阈值的 ——
    那正是 `CALIBRATION.md` §12 要求记录"改了哪个旋钮"的同一条理由。
    """

    max_consecutive_abandoned: int = Field(default=5, ge=1)
    """连续放弃多少场就判定这次 Run 作废。

    **2026-08-01 由 3 改为 5,理由是代价不对称。** 重试已经在一场 attempt 内部
    吸收了约 116 秒的退避(见 `RetryPolicy` 的限流档),所以连续 3 次放弃
    意味着已经持续失败 6 分钟以上 —— 但免费层的配额窗口经常就是这个量级。
    为一次可恢复的抖动作废整轮 2.3 小时的校准,比多等几场糟糕得多;
    而真正的宕机不会在第 4、5 场就自己好转,仍然抓得住。
    """

    max_abandoned_fraction: float = Field(default=0.10, ge=0.0, le=1.0)
    """放弃比例的上限。

    ⚠️ **含义取决于预算怎么计数,这一点必须说清楚:**

    * `count_abandoned_against_attempts=True`(默认,给普通扫描用)——
      它是"允许多少样本缺失",因为放弃的场次会真的吃掉预算;
    * `False`(校准用,放弃的场次会被补跑)—— 它变成
      **"补跑量超过这个比例就说明环境有问题,停下来查"**,
      而不再是允许样本缺失。校准的 N=200 是冻结的统计标准,
      不该被运行故障悄悄改小。
    """

    fraction_min_attempts: int = Field(default=10, ge=1)
    """样本太少时比例没有意义,低于这个数不启用比例判据。"""

    def invalidates_run(
        self,
        *,
        logical_attempts: int,
        abandoned_attempts: int,
        consecutive_abandoned: int,
    ) -> bool:
        if consecutive_abandoned >= self.max_consecutive_abandoned:
            return True
        if logical_attempts < self.fraction_min_attempts:
            return False
        return abandoned_attempts / logical_attempts > self.max_abandoned_fraction

    def invalidates_completed_run(
        self,
        *,
        logical_attempts: int,
        completed_attempts: int,
        abandoned_attempts: int,
    ) -> bool:
        """预算结束时没有"再观察几次"的机会,直接按最终有效比例判定。"""
        if logical_attempts == 0 or completed_attempts == 0:
            return True
        return abandoned_attempts / logical_attempts > self.max_abandoned_fraction
