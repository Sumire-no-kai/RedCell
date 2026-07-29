from __future__ import annotations

import random
from collections import Counter

import pytest

from redcell.randomness import controller_seed_for
from redcell.search import (
    ControllerDecisionOutcome,
    ControllerProtocolError,
    NoAvailableStrategiesError,
    RandomController,
    StaticController,
)

STRATEGIES = [f"s{i}" for i in range(6)]


def _select_and_update(controller, available: list[str], score: float = 0.0) -> str:
    selected = controller.select(available)
    controller.update(selected, score)
    return selected


def test_static_controller_cycles_in_frozen_order() -> None:
    controller = StaticController(["a", "b", "c"])
    selected = [_select_and_update(controller, ["a", "b", "c"]) for _ in range(5)]

    assert selected == ["a", "b", "c", "a", "b"]


def test_static_controller_skips_temporarily_unavailable_strategy() -> None:
    controller = StaticController(["a", "b", "c"])

    assert _select_and_update(controller, ["b", "c"]) == "b"
    assert _select_and_update(controller, ["a", "c"]) == "c"
    assert _select_and_update(controller, ["a"]) == "a"


def test_static_100_over_6_has_only_17_or_16_attempts() -> None:
    controller = StaticController(STRATEGIES)
    counts = Counter(_select_and_update(controller, STRATEGIES) for _ in range(100))

    assert sorted(counts.values()) == [16, 16, 17, 17, 17, 17]


def test_random_controller_is_reproducible_from_injected_rng() -> None:
    seed = controller_seed_for(42)
    first = RandomController(random.Random(seed))
    second = RandomController(random.Random(seed))

    first_choices = [_select_and_update(first, STRATEGIES) for _ in range(20)]
    # 干扰全局 RNG 不应影响两个 Controller 的私有 RNG。
    for _ in range(100):
        random.random()
    second_choices = [_select_and_update(second, STRATEGIES) for _ in range(20)]

    assert first_choices == second_choices


def test_decision_record_captures_candidates_choice_and_feedback() -> None:
    controller = RandomController(random.Random(7))
    selected = controller.select(["a", "b"])
    controller.update(selected, 0.7)

    decision = controller.decisions[0]
    assert decision.available_strategy_ids == ["a", "b"]
    assert decision.selected_strategy_id == selected
    assert decision.observed_score == 0.7
    assert decision.outcome is ControllerDecisionOutcome.COMPLETED
    assert decision.decision_state["selected_index"] in (0, 1)


def test_select_requires_feedback_before_next_decision() -> None:
    controller = StaticController(["a"])
    controller.select(["a"])

    with pytest.raises(ControllerProtocolError, match="尚未收到"):
        controller.select(["a"])


def test_update_must_match_latest_selection() -> None:
    controller = StaticController(["a", "b"])
    controller.select(["a", "b"])

    with pytest.raises(ControllerProtocolError, match="不一致"):
        controller.update("b", 0.0)


def test_abandon_releases_pending_without_learning_from_fake_zero() -> None:
    controller = StaticController(["a", "b"])
    selected = controller.select(["a", "b"])

    controller.abandon(selected, "target timeout")

    decision = controller.decisions[0]
    assert decision.outcome is ControllerDecisionOutcome.ABANDONED
    assert decision.observed_score is None
    assert decision.failure_reason == "target timeout"
    assert _select_and_update(controller, ["a", "b"]) == "b"


def test_abandon_requires_matching_selection_and_reason() -> None:
    controller = StaticController(["a"])
    controller.select(["a"])

    with pytest.raises(ControllerProtocolError, match="不一致"):
        controller.abandon("b", "timeout")
    with pytest.raises(ValueError, match="不能为空"):
        controller.abandon("a", " ")


def test_empty_or_duplicate_available_set_is_rejected() -> None:
    controller = StaticController(["a"])
    with pytest.raises(NoAvailableStrategiesError):
        controller.select([])
    with pytest.raises(ValueError, match="重复"):
        controller.select(["a", "a"])


def test_unknown_static_candidates_fail_loudly() -> None:
    controller = StaticController(["a"])
    with pytest.raises(NoAvailableStrategiesError, match="冻结顺序"):
        controller.select(["outside"])
