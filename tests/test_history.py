from __future__ import annotations

from redcell.arena.support_agent import SUPPORT_AGENT_POLICY
from redcell.history import build_controller_evidence, build_generation_memory, strategy_aggregates
from redcell.protocols import (
    AdapterOutput,
    ObservabilityLevel,
    ReproductionContext,
    Turn,
    build_attempt,
)


def _attempt(index: int, strategy_id: str, reward: float):
    return build_attempt(
        attempt_id=f"attempt-{index}",
        run_id="run",
        attempt_index=index,
        strategy_id=strategy_id,
        actor="customer_a",
        attack_prompt="ignored",
        reproduction=ReproductionContext(
            policy_version="v1",
            target_name="target",
            adapter_type="test",
            strategy_id=strategy_id,
        ),
        turns=[
            Turn(
                index=0,
                attacker_message=f"attack {index}",
                output=AdapterOutput(
                    assistant_message=f"response {index}", observability=ObservabilityLevel.FULL
                ),
            )
        ],
    ).model_copy(update={"reward": reward, "signals": []})


def test_generation_memory_selects_bounded_relevant_attempts_in_stable_order() -> None:
    attempts = [_attempt(0, "a", 0.1), _attempt(1, "b", 0.4), _attempt(2, "a", 0.9)]
    memory = build_generation_memory(attempts, current_strategy_id="a")

    assert memory.selected_attempt_refs == ["attempt-1", "attempt-2"]
    assert "Attempt 2" in memory.rendered_history
    assert memory.rendered_chars == len(memory.rendered_history)


def test_aggregates_are_stable_and_do_not_contain_message_text() -> None:
    summaries = strategy_aggregates([_attempt(0, "b", 0.2), _attempt(1, "a", 0.6)])

    assert [summary["strategy_id"] for summary in summaries] == ["a", "b"]
    assert summaries[0]["mean_reward"] == 0.6
    assert "attack 0" not in str(summaries)


def test_controller_evidence_contains_only_projected_history_and_budget() -> None:
    evidence = build_controller_evidence(
        [_attempt(0, "b", 0.2), _attempt(1, "a", 0.6)],
        brief=SUPPORT_AGENT_POLICY.brief_for("customer_a"),
        available_strategy_ids=["a", "b"],
        total_token_limit=100,
        used_tokens=30,
    )

    assert evidence.budget.remaining_tokens == 70
    assert "strategy_aggregates" in evidence.rendered_history
    assert evidence.available_strategy_ids == ["a", "b"]
