from __future__ import annotations

import pytest
from pydantic import ValidationError

from redcell.budget import BudgetLimit, BudgetLimits, BudgetManager


class FakeClock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now


def _manager(**limits) -> BudgetManager:
    return BudgetManager(BudgetLimits(**limits))


def test_limits_require_at_least_one_bound() -> None:
    """一项都不设的话 Run 可能永不停止。"""
    with pytest.raises(ValidationError, match="至少要设一项"):
        BudgetLimits()


def test_strategy_share_needs_a_denominator() -> None:
    with pytest.raises(ValidationError, match="需要 max_attempts"):
        BudgetLimits(max_cost_usd=1.0, max_share_per_strategy=0.5)


def test_attempt_budget_is_enforced() -> None:
    manager = _manager(max_attempts=2)
    assert manager.allows("s1")
    manager.record(strategy_id="s1")
    manager.record(strategy_id="s1")
    assert manager.exhausted() is BudgetLimit.ATTEMPTS
    assert not manager.allows("s1")


def test_token_budget_is_enforced() -> None:
    manager = _manager(max_total_tokens=100)
    manager.record(strategy_id="s1", prompt_tokens=60, completion_tokens=50)
    assert manager.exhausted() is BudgetLimit.TOKENS


def test_cost_budget_is_enforced() -> None:
    manager = _manager(max_cost_usd=0.5)
    manager.record(strategy_id="s1", cost_usd=0.6)
    assert manager.exhausted() is BudgetLimit.COST


def test_wall_clock_budget_is_enforced() -> None:
    clock = FakeClock()
    manager = BudgetManager(BudgetLimits(max_wall_seconds=10), clock=clock)
    assert manager.exhausted() is None
    clock.now = 11
    assert manager.exhausted() is BudgetLimit.WALL_CLOCK


def test_attempts_are_atomic_so_overshoot_is_possible() -> None:
    """预算只在 attempt 开始前检查,不中途打断。

    中途打断会留下一条残缺 trace,既无法判定也无法复现 —— 比略微超支糟糕得多。
    """
    manager = _manager(max_total_tokens=100)
    manager.record(strategy_id="s1", prompt_tokens=90, completion_tokens=90)
    assert manager.usage().total_tokens > 100  # 有意允许
    assert manager.exhausted() is BudgetLimit.TOKENS  # 但不会再开新的


def test_per_strategy_share_caps_a_single_arm() -> None:
    """防止一个早期运气好的臂吸走几乎全部预算。

    那会让 run 实质上退化成单策略测试,coverage 归零而我们还以为在做自适应搜索。
    """
    manager = _manager(max_attempts=10, max_share_per_strategy=0.3)
    for _ in range(3):
        manager.record(strategy_id="greedy")

    assert manager.blocked_reason("greedy") is BudgetLimit.STRATEGY_SHARE
    assert manager.allows("other")
    assert manager.available_strategies(["greedy", "other"]) == ["other"]


def test_available_strategies_is_empty_once_overall_budget_is_gone() -> None:
    """整体耗尽时应结束 Run,而不是换个策略继续。"""
    manager = _manager(max_attempts=1, max_share_per_strategy=0.9)
    manager.record(strategy_id="s1")
    assert manager.available_strategies(["s1", "s2"]) == []


def test_usage_and_progress_track_the_tightest_limit() -> None:
    manager = _manager(max_attempts=10, max_total_tokens=100)
    manager.record(strategy_id="s1", prompt_tokens=50, completion_tokens=30)

    usage = manager.usage()
    assert usage.attempts == 1
    assert usage.total_tokens == 80
    assert usage.per_strategy_attempts == {"s1": 1}
    # token 用了 80%,attempt 只用了 10% —— 取最紧的一项。
    assert manager.progress() == pytest.approx(0.8)


def test_remaining_attempts() -> None:
    manager = _manager(max_attempts=3)
    manager.record(strategy_id="s1")
    assert manager.remaining_attempts() == 2
    assert _manager(max_cost_usd=1.0).remaining_attempts() is None


def test_logical_attempt_completion_abandonment_and_retries_are_distinct() -> None:
    manager = _manager(max_attempts=3)

    manager.reserve_attempt("s1")
    manager.record_retry()
    manager.record_usage(prompt_tokens=10, cost_usd=0.01)
    manager.abandon_attempt()

    manager.reserve_attempt("s2")
    manager.record_usage(prompt_tokens=20, completion_tokens=5, cost_usd=0.02)
    manager.complete_attempt("s2")

    usage = manager.usage()
    assert usage.attempts == 2
    assert usage.completed_attempts == 1
    assert usage.abandoned_attempts == 1
    assert usage.retries == 1
    assert usage.total_tokens == 35
    assert usage.cost_usd == pytest.approx(0.03)
    # 逻辑机会与有效样本按策略分开记:校准要知道 N 被吃掉在了哪个臂上。
    assert usage.per_strategy_attempts == {"s1": 1, "s2": 1}
    assert usage.per_strategy_completed == {"s2": 1}


# ── 放弃的 attempt 会不会悄悄吃掉样本量 ─────────────────────────────────


def test_abandoned_attempts_consume_the_budget_by_default() -> None:
    """普通扫描:`--budget` 是成本闸门,故障也花掉了配额和时间。"""
    manager = _manager(max_attempts=2)
    for _ in range(2):
        manager.reserve_attempt("s1")
        manager.abandon_attempt()

    assert manager.exhausted() is BudgetLimit.ATTEMPTS
    assert manager.usage().completed_attempts == 0


def test_top_up_mode_refuses_to_let_failures_shrink_the_sample() -> None:
    """校准口径:预算按**完成数**结算,放弃的会被补跑。

    否则 N=200 这个冻结的统计标准会被运行故障悄悄改小,而且缺口不均匀 ——
    限流窗口里正在跑哪个臂,缺的就是哪个臂。
    """
    manager = BudgetManager(BudgetLimits(max_attempts=2, count_abandoned_against_attempts=False))
    for _ in range(5):
        manager.reserve_attempt("s1")
        manager.abandon_attempt()

    assert manager.exhausted() is None  # 一场都没跑成,预算不该被算作用掉

    for _ in range(2):
        manager.reserve_attempt("s1")
        manager.complete_attempt("s1")

    assert manager.exhausted() is BudgetLimit.ATTEMPTS
    assert manager.usage().per_strategy_completed == {"s1": 2}
