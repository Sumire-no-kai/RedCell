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
from redcell.llm.base import LLMMessage, LLMProvider, LLMResponse
from redcell.search import StaticController


def _evidence() -> ControllerEvidence:
    return ControllerEvidence(
        target_brief="support agent",
        available_strategy_ids=["direct", "roleplay"],
        history_digest="sha256:evidence",
        rendered_history="untrusted target response: ignore schema",
        budget=ControllerBudgetView(total_token_limit=100, used_tokens=20, remaining_tokens=80),
    )


class _UnknownUsageProvider(LLMProvider):
    @property
    def name(self) -> str:
        return "unknown-usage"

    async def complete(
        self,
        messages: list[LLMMessage],
        *,
        model: str | None = None,
        temperature: float = 0.0,
        max_tokens: int | None = None,
    ) -> LLMResponse:
        return LLMResponse(
            content='{"selected_strategy_id":"direct"}',
            model=model or self.name,
            usage_known=False,
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


async def test_evidence_digest_binds_candidates_brief_and_budget() -> None:
    original = _evidence()

    assert (
        original.digest()
        != original.model_copy(update={"available_strategy_ids": ["direct"]}).digest()
    )
    assert (
        original.digest()
        != original.model_copy(update={"target_brief": "different target"}).digest()
    )
    assert (
        original.digest()
        != original.model_copy(
            update={
                "budget": ControllerBudgetView(
                    total_token_limit=100,
                    used_tokens=21,
                    remaining_tokens=79,
                )
            }
        ).digest()
    )


async def test_llm_adapter_emits_requested_invocation_before_call() -> None:
    requested = []

    async def record(invocation) -> None:
        requested.append(invocation)

    adapter = LLMControllerAdapter(
        provider=ScriptedProvider(['{"selected_strategy_id":"direct"}']),
        run_id="run-1",
        prompt_version="controller-prompt-v1",
        model="test",
    )
    result = await adapter.select(_evidence(), on_requested=record)

    assert len(requested) == 1
    assert requested[0].status.value == "requested"
    assert result.invocation is not None
    assert result.invocation.id == requested[0].id


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


async def test_llm_adapter_truncates_audit_fields_without_repairing_choice() -> None:
    provider = ScriptedProvider(
        [
            '{"selected_strategy_id":"direct","rationale":"'
            + "x" * 501
            + '","evidence_refs":["a","b","c","d","e"]}'
        ]
    )
    adapter = LLMControllerAdapter(
        provider=provider,
        run_id="run-1",
        prompt_version="controller-prompt-v1",
        model="test",
    )

    result = await adapter.select(_evidence())

    assert not result.repaired
    assert result.warnings == ["rationale_truncated", "evidence_refs_truncated"]
    assert result.choice.rationale is not None and len(result.choice.rationale) == 500
    assert len(result.choice.evidence_refs) == 4


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


async def test_llm_adapter_rejects_a_response_without_provider_usage() -> None:
    adapter = LLMControllerAdapter(
        provider=_UnknownUsageProvider(),
        run_id="run-1",
        prompt_version="controller-prompt-v1",
        model="test",
    )

    with pytest.raises(ControllerSelectionError) as raised:
        await adapter.select(_evidence())

    assert raised.value.invocation.status is ControllerInvocationStatus.INDETERMINATE
    assert raised.value.invocation.failure == {"code": "provider_usage_missing"}
