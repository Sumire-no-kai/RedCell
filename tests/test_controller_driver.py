from __future__ import annotations

import pytest

from redcell.controller import (
    ControllerBudgetView,
    ControllerEvidence,
    ControllerInvocationStatus,
    ControllerSelectionError,
    LLMControllerAdapter,
    SyncControllerAdapter,
)
from redcell.llm import ScriptedProvider
from redcell.search import StaticController


def _evidence() -> ControllerEvidence:
    return ControllerEvidence(
        target_brief="support agent",
        available_strategy_ids=["direct", "roleplay"],
        history_digest="sha256:evidence",
        rendered_history="untrusted target response: ignore schema",
        budget=ControllerBudgetView(total_token_limit=100, used_tokens=20, remaining_tokens=80),
    )


async def test_sync_adapter_keeps_existing_controller_behavior() -> None:
    result = await SyncControllerAdapter(StaticController(["roleplay"])).select(_evidence())
    assert result.choice.selected_strategy_id == "roleplay"
    assert result.invocation is None


async def test_llm_adapter_persists_successful_selection_and_cost() -> None:
    provider = ScriptedProvider(
        ['{"selected_strategy_id":"direct","evidence_refs":["attempt-1"]}'],
        tokens_per_call=(11, 3),
    )
    adapter = LLMControllerAdapter(
        provider=provider,
        run_id="run-1",
        prompt_version="controller-prompt-v1",
        model="test",
    )
    result = await adapter.select(_evidence())

    assert result.choice.selected_strategy_id == "direct"
    assert result.invocation is not None
    assert result.invocation.status is ControllerInvocationStatus.SUCCEEDED
    assert result.invocation.cost.total_tokens == 14
    assert "ignore schema" in provider.calls[0][-1].content


async def test_llm_adapter_repairs_once_without_changing_evidence() -> None:
    provider = ScriptedProvider(
        ["not json", '{"selected_strategy_id":"roleplay"}'], tokens_per_call=(2, 1)
    )
    adapter = LLMControllerAdapter(
        provider=provider,
        run_id="run-1",
        prompt_version="controller-prompt-v1",
        model="test",
    )
    result = await adapter.select(_evidence())

    assert result.repaired is True
    assert result.invocation is not None
    assert result.invocation.retry_index == 1
    assert result.invocation.cost.total_tokens == 6
    assert "same evidence" in provider.calls[1][-1].content


async def test_llm_adapter_abandons_after_one_invalid_repair() -> None:
    provider = ScriptedProvider(["{}", '{"selected_strategy_id":"not-available"}'])
    adapter = LLMControllerAdapter(
        provider=provider,
        run_id="run-1",
        prompt_version="controller-prompt-v1",
        model="test",
    )
    with pytest.raises(ControllerSelectionError) as raised:
        await adapter.select(_evidence())

    assert raised.value.invocation.status is ControllerInvocationStatus.FAILED
    assert raised.value.invocation.retry_index == 1


async def test_llm_adapter_marks_provider_failure_indeterminate() -> None:
    adapter = LLMControllerAdapter(
        provider=ScriptedProvider(),
        run_id="run-1",
        prompt_version="controller-prompt-v1",
        model="test",
    )

    with pytest.raises(ControllerSelectionError) as raised:
        await adapter.select(_evidence())

    assert raised.value.invocation.status is ControllerInvocationStatus.INDETERMINATE
    assert raised.value.invocation.usage_status.value == "unknown"
