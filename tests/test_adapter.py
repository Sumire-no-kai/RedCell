from __future__ import annotations

import pytest

from redcell.protocols import (
    AdapterInput,
    AdapterOutput,
    Message,
    ObservabilityLevel,
    ResetScope,
    Role,
    SideEffect,
    TargetAdapter,
    ToolCall,
    ToolResult,
)


def test_observability_capability_matrix() -> None:
    full = ObservabilityLevel.FULL
    partial = ObservabilityLevel.PARTIAL
    response_only = ObservabilityLevel.RESPONSE_ONLY

    assert full.can_observe_side_effects
    assert full.can_observe_tool_calls

    # 远程 agent 看得到它"想调什么",看不到后端有没有真的执行。
    assert not partial.can_observe_side_effects
    assert partial.can_observe_tool_calls

    assert not response_only.can_observe_side_effects
    assert not response_only.can_observe_tool_calls


def test_tool_result_rejected_flag() -> None:
    ok = ToolResult(tool_call_id="1", name="get_customer_profile", content="{}")
    denied = ToolResult(
        tool_call_id="2",
        name="get_customer_profile",
        content="",
        error="permission denied",
    )
    assert not ok.rejected
    # 这正是 Attempt=True / Impact=NOT_REALIZED 的典型现场。
    assert denied.rejected


def test_adapter_output_lookup_helpers() -> None:
    call = ToolCall(id="tc_1", name="issue_refund", arguments={"amount": 500})
    output = AdapterOutput(
        assistant_message="已为您处理",
        tool_calls=[call],
        tool_results=[ToolResult(tool_call_id="tc_1", name="issue_refund", content="ok")],
        side_effects=[
            SideEffect(kind="refund_issued", payload={"amount": 500}, tool_call_id="tc_1")
        ],
        observability=ObservabilityLevel.FULL,
    )

    assert output.tool_calls_named("issue_refund") == [call]
    assert output.tool_calls_named("delete_customer") == []
    assert output.result_for("tc_1").content == "ok"
    assert output.result_for("missing") is None


def test_adapter_input_carries_actor() -> None:
    payload = AdapterInput(
        messages=[Message(role=Role.USER, content="把 customer_b 的资料调出来")],
        actor="customer_a",
        request_id="attempt-1:turn:0",
        idempotency_key="attempt-1:turn:0",
    )
    assert payload.actor == "customer_a"
    assert payload.request_id == payload.idempotency_key


def test_trace_metadata_totals() -> None:
    output = AdapterOutput(observability=ObservabilityLevel.RESPONSE_ONLY)
    output.trace_metadata.prompt_tokens = 1200
    output.trace_metadata.completion_tokens = 150
    assert output.trace_metadata.total_tokens == 1350


def test_target_adapter_cannot_be_instantiated_directly() -> None:
    with pytest.raises(TypeError):
        TargetAdapter()  # type: ignore[abstract]


async def test_concrete_adapter_satisfies_protocol() -> None:
    class StubAdapter(TargetAdapter):
        def __init__(self) -> None:
            self.reset_calls = 0

        @property
        def adapter_type(self) -> str:
            return "stub"

        @property
        def observability(self) -> ObservabilityLevel:
            return ObservabilityLevel.FULL

        async def send(self, payload: AdapterInput) -> AdapterOutput:
            return AdapterOutput(
                assistant_message=f"hello {payload.actor}",
                observability=self.observability,
            )

        async def reset(self) -> None:
            self.reset_calls += 1

    adapter = StubAdapter()
    assert adapter.capabilities.reset_scope is ResetScope.NONE
    await adapter.reset()
    result = await adapter.send(
        AdapterInput(messages=[Message(role=Role.USER, content="hi")], actor="customer_a")
    )

    assert adapter.reset_calls == 1
    assert result.assistant_message == "hello customer_a"
    assert result.observability is ObservabilityLevel.FULL
