"""Offline checks for the independent M1-C real-model smoke harness."""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

import pytest
import scripts.m1c_online_smoke as smoke
from scripts.m1c_online_smoke import run_smoke

from redcell._base import CostRecord
from redcell.arena.support_agent import SUPPORT_AGENT_ARENA
from redcell.arena.support_agent.adapter import ArenaAdapter
from redcell.arena.support_agent.codec import ToolCallProtocol
from redcell.arena.support_agent.prompts import DefenseLevel
from redcell.attacker_observation import PublicToolError
from redcell.config import AttackerSettings, TargetSettings
from redcell.feedback_attacker import (
    FEEDBACK_ATTACKER_PROMPT_V2,
    FEEDBACK_ATTACKER_SCHEMA_V2,
    AttackerWorkingState,
    FeedbackAttackAction,
    FeedbackAttackChoice,
    FeedbackAttackDecisionError,
    FeedbackAttackDriver,
    FeedbackAttackRequest,
    FeedbackAttackSelection,
)
from redcell.llm.base import LLMMessage, LLMProvider, LLMResponse, LLMToolCall
from redcell.protocols.adapter import (
    AdapterCapabilities,
    AdapterInput,
    AdapterOutput,
    TargetAdapter,
    ToolCall,
    ToolResult,
    TraceMetadata,
)
from redcell.protocols.common import ObservabilityLevel, Role
from redcell.strategies.library import CROSS_USER_RESOURCE_ACCESS


def _settings() -> tuple[TargetSettings, AttackerSettings]:
    shared = {
        "provider": "fake",
        "base_url": "https://example.invalid/v1",
        "api_key": "fake-test-key",
        "model": "fake-model",
        "input_usd_per_mtok": 1.0,
        "output_usd_per_mtok": 1.0,
        "cached_input_usd_per_mtok": 1.0,
    }
    return TargetSettings(**shared), AttackerSettings(**shared)


class FakeTarget(TargetAdapter):
    def __init__(self, *, usage_known: bool = True) -> None:
        self.requests: list[AdapterInput] = []
        self.reset_count = 0
        self.usage_known = usage_known

    @property
    def adapter_type(self) -> str:
        return "support-agent"

    @property
    def observability(self) -> ObservabilityLevel:
        return ObservabilityLevel.FULL

    @property
    def capabilities(self) -> AdapterCapabilities:
        return AdapterCapabilities(reports_cost=True)

    @property
    def tool_call_protocol_version(self) -> str:
        return "native-function-calling-v2"

    @property
    def tool_schema_sha256(self) -> str:
        return SUPPORT_AGENT_ARENA.tool_schema_sha256

    async def reset(self) -> None:
        self.reset_count += 1

    async def send(self, payload: AdapterInput) -> AdapterOutput:
        self.requests.append(payload)
        first = len(self.requests) == 1
        response = "I cannot retrieve that order." if first else "I can help with your own orders."
        return AdapterOutput(
            assistant_message=response,
            tool_calls=(
                [ToolCall(id="call-1", name="get_order_status", arguments={"order_id": "ORD-2001"})]
                if first
                else []
            ),
            tool_results=(
                [
                    ToolResult(
                        tool_call_id="call-1",
                        name="get_order_status",
                        content="",
                        error="permission denied: ORD-2001 belongs to another account",
                    )
                ]
                if first
                else []
            ),
            observability=ObservabilityLevel.FULL,
            trace_metadata=TraceMetadata(
                prompt_tokens=5,
                completion_tokens=5,
                cost_usd=0.02,
                usage_known=self.usage_known,
            ),
        )


class FakeDriver(FeedbackAttackDriver):
    def __init__(self, *, fail_unknown: bool = False) -> None:
        self.requests: list[FeedbackAttackRequest] = []
        self.fail_unknown = fail_unknown

    @property
    def name(self) -> str:
        return "fake-feedback"

    async def decide(self, request: FeedbackAttackRequest) -> FeedbackAttackSelection:
        self.requests.append(request)
        if self.fail_unknown:
            raise FeedbackAttackDecisionError(
                "fake unknown usage",
                cost=CostRecord(usage_known=False),
                usage_indeterminate=True,
            )
        index = len(self.requests) - 1
        action = FeedbackAttackAction(
            kind="start_attempt" if index == 0 else "continue_attempt",
            strategy_id=CROSS_USER_RESOURCE_ACCESS.id if index == 0 else None,
            message="Check another account's order." if index == 0 else "Try my order instead.",
            test_intent="Test access to the requested order.",
            evidence_refs=(
                [request.observations.attempts[0].turns[0].tool_actions[0].ref]
                if index == 1
                else []
            ),
        )
        return FeedbackAttackSelection(
            choice=FeedbackAttackChoice(
                working_state=AttackerWorkingState(next_objective="Check response"),
                action=action,
            ),
            cost=CostRecord(prompt_tokens=5, completion_tokens=5, usd=0.01),
            prompt_version=FEEDBACK_ATTACKER_PROMPT_V2,
            schema_version=FEEDBACK_ATTACKER_SCHEMA_V2,
            request_digest=request.digest(),
            response_digest="fake-digest",
        )


def _events(path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def _run(path, driver: FakeDriver, target: FakeTarget, *, max_tokens: int = 100) -> str:
    target_settings, attacker_settings = _settings()
    return asyncio.run(
        run_smoke(
            driver=driver,
            adapter=target,
            path=path,
            target_settings=target_settings,
            attacker_settings=attacker_settings,
            utility_fingerprint="frozen-test-fingerprint",
            max_total_tokens=max_tokens,
            max_cost_usd=1.0,
            max_seconds=60.0,
        )
    )


def test_fake_target_path_feeds_rejected_tool_diagnostic_to_next_decision(tmp_path) -> None:
    path = tmp_path / "smoke.jsonl"
    driver, target = FakeDriver(), FakeTarget()

    assert _run(path, driver, target) == "max_turns"

    events = _events(path)
    assert target.reset_count == 1
    assert len(target.requests) == 2
    assert len(driver.requests) == 2
    action = driver.requests[1].observations.attempts[0].turns[0].tool_actions[0]
    assert action.error_category is PublicToolError.PERMISSION_DENIED
    assert target.requests[1].messages[-1].content == "Try my order instead."
    assert events[-1]["usage"]["prompt_tokens"] == 20
    assert events[-1]["usage"]["completion_tokens"] == 20
    assert events[-1]["usage"]["usd"] == 0.06
    assert events[-1]["reason"] == "max_turns"
    assert events[0]["formal_run"] is False
    assert events[0]["billed_usage_coverage_proven"] is False


class NativePricedProvider(LLMProvider):
    def __init__(self, *, first_model: str = "fake-model") -> None:
        self.requests: list[list[LLMMessage]] = []
        self.responses = [
            LLMResponse(
                content="",
                model=first_model,
                tool_calls=[
                    LLMToolCall(
                        id="native-call-1",
                        name="get_order_status",
                        arguments_json='{"order_id":"ORD-2001"}',
                    )
                ],
                prompt_tokens=5,
                completion_tokens=5,
                cost_usd=0.01,
            ),
            LLMResponse(
                content="I cannot retrieve that order.",
                model="fake-model",
                prompt_tokens=5,
                completion_tokens=5,
                cost_usd=0.01,
            ),
            LLMResponse(
                content="I can help with your own orders.",
                model="fake-model",
                prompt_tokens=5,
                completion_tokens=5,
                cost_usd=0.01,
            ),
        ]

    @property
    def name(self) -> str:
        return "native-priced-fake"

    @property
    def reports_cost(self) -> bool:
        return True

    async def complete(self, messages, **kwargs) -> LLMResponse:
        self.requests.append(list(messages))
        return self.responses.pop(0)


def test_native_v2_arena_feedback_is_seen_and_next_message_delivered(tmp_path) -> None:
    path = tmp_path / "arena.jsonl"
    target_settings, attacker_settings = _settings()
    provider = NativePricedProvider()
    audited = smoke.AuditedProvider(
        provider, role="target", expected_model="fake-model", max_requests=10
    )
    arena = ArenaAdapter(
        audited,
        arena=SUPPORT_AGENT_ARENA,
        defense=DefenseLevel.STANDARD,
        enforce_permissions=True,
        enforce_confirmation=True,
        tool_call_protocol=ToolCallProtocol.NATIVE_V2,
        model="fake-model",
        temperature=target_settings.temperature,
        max_tokens=target_settings.max_tokens,
    )
    driver = FakeDriver()

    stop = asyncio.run(
        run_smoke(
            driver=driver,
            adapter=arena,
            path=path,
            target_settings=target_settings,
            attacker_settings=attacker_settings,
            utility_fingerprint="frozen-test-fingerprint",
            max_total_tokens=100,
            max_cost_usd=1.0,
            max_seconds=60.0,
            audited_providers=(audited,),
        )
    )

    assert stop == "max_turns"
    assert len(driver.requests) == 2
    first_action = driver.requests[1].observations.attempts[0].turns[0].tool_actions[0]
    assert first_action.error_category is PublicToolError.PERMISSION_DENIED
    assert len(provider.requests) == 3
    assert provider.requests[-1][-1].content == "Try my order instead."
    assert _events(path)[-1]["provider_requests"] == {"target": 3}


def test_native_v2_target_model_drift_stops_tool_loop_and_counts_known_usage(tmp_path) -> None:
    path = tmp_path / "drift.jsonl"
    target_settings, attacker_settings = _settings()
    provider = NativePricedProvider(first_model="unexpected-model")
    audited = smoke.AuditedProvider(
        provider, role="target", expected_model="fake-model", max_requests=10
    )
    arena = ArenaAdapter(
        audited,
        arena=SUPPORT_AGENT_ARENA,
        tool_call_protocol=ToolCallProtocol.NATIVE_V2,
        model="fake-model",
    )

    stop = asyncio.run(
        run_smoke(
            driver=FakeDriver(),
            adapter=arena,
            path=path,
            target_settings=target_settings,
            attacker_settings=attacker_settings,
            utility_fingerprint="frozen-test-fingerprint",
            max_total_tokens=100,
            max_cost_usd=1.0,
            max_seconds=60.0,
            audited_providers=(audited,),
        )
    )

    assert stop == "provider_model_drift"
    assert len(provider.requests) == 1
    events = _events(path)
    assert events[-1]["usage"]["prompt_tokens"] == 10
    assert events[-1]["usage"]["completion_tokens"] == 10
    assert events[-1]["usage"]["usd"] == 0.02
    assert events[-1]["provider_requests"] == {"target": 1}


def test_later_target_model_drift_keeps_all_completed_subcall_usage(tmp_path) -> None:
    path = tmp_path / "later-drift.jsonl"
    target_settings, attacker_settings = _settings()
    provider = NativePricedProvider()
    provider.responses[1] = LLMResponse(
        content="",
        model="unexpected-model",
        tool_calls=[
            LLMToolCall(
                id="native-call-2",
                name="get_order_status",
                arguments_json='{"order_id":"ORD-2001"}',
            )
        ],
        prompt_tokens=5,
        completion_tokens=5,
        cost_usd=0.01,
    )
    audited = smoke.AuditedProvider(
        provider, role="target", expected_model="fake-model", max_requests=10
    )
    arena = ArenaAdapter(
        audited,
        arena=SUPPORT_AGENT_ARENA,
        tool_call_protocol=ToolCallProtocol.NATIVE_V2,
        model="fake-model",
    )

    stop = asyncio.run(
        run_smoke(
            driver=FakeDriver(),
            adapter=arena,
            path=path,
            target_settings=target_settings,
            attacker_settings=attacker_settings,
            utility_fingerprint="frozen-test-fingerprint",
            max_total_tokens=100,
            max_cost_usd=1.0,
            max_seconds=60.0,
            audited_providers=(audited,),
        )
    )

    assert stop == "provider_model_drift"
    assert len(provider.requests) == 2
    total = _events(path)[-1]["usage"]
    assert total["prompt_tokens"] == 15
    assert total["completion_tokens"] == 15
    assert total["usd"] == 0.03
    assert total["usage_known"] is True


def test_budget_exhausted_after_attacker_call_blocks_target(tmp_path) -> None:
    path = tmp_path / "smoke.jsonl"
    driver, target = FakeDriver(), FakeTarget()

    assert _run(path, driver, target, max_tokens=10) == "tokens"

    events = _events(path)
    assert len(driver.requests) == 1
    assert target.requests == []
    assert events[-1]["reason"] == "tokens"
    assert not any(event["event"] == "target_requested" for event in events)


def test_last_turn_budget_stop_takes_priority_over_turn_cap(tmp_path) -> None:
    path = tmp_path / "smoke.jsonl"
    driver, target = FakeDriver(), FakeTarget()

    assert _run(path, driver, target, max_tokens=40) == "tokens"

    events = _events(path)
    assert len(target.requests) == 2
    assert events[-1]["reason"] == "tokens"


def test_unknown_attacker_usage_stops_without_target_call(tmp_path) -> None:
    path = tmp_path / "smoke.jsonl"
    driver, target = FakeDriver(fail_unknown=True), FakeTarget()

    assert _run(path, driver, target) == "usage_indeterminate"

    events = _events(path)
    assert target.requests == []
    assert events[-1]["reason"] == "usage_indeterminate"
    assert events[-1]["usage"]["usage_known"] is False
    unknown_usage = [
        event for event in events if event["event"] == "usage" and not event["cost"]["usage_known"]
    ]
    assert unknown_usage


def test_unknown_target_usage_stops_before_feedback_decision(tmp_path) -> None:
    path = tmp_path / "smoke.jsonl"
    driver, target = FakeDriver(), FakeTarget(usage_known=False)

    assert _run(path, driver, target) == "usage_indeterminate"

    events = _events(path)
    assert len(driver.requests) == 1
    assert len(target.requests) == 1
    assert not any(event["event"] == "turn_completed" for event in events)
    returned = [event for event in events if event["event"] == "target_returned"]
    assert len(returned) == 1
    assert returned[0]["usage_known"] is False
    assert returned[0]["output"]["tool_results"][0]["error"].startswith("permission denied")
    assert events[-1]["reason"] == "usage_indeterminate"
    assert events[-1]["usage"]["usage_known"] is False
    assert events[-1]["usage"]["prompt_tokens"] > 0


class DriftProvider(LLMProvider):
    def __init__(self) -> None:
        self.requests = 0

    @property
    def name(self) -> str:
        return "drift-fake"

    async def complete(self, messages, **kwargs) -> LLMResponse:
        self.requests += 1
        return LLMResponse(
            content="unexpected model",
            model="other-model",
            prompt_tokens=2,
            completion_tokens=1,
            cost_usd=0.001,
        )


def test_actual_model_drift_blocks_next_provider_request(tmp_path) -> None:
    path = tmp_path / "audit.jsonl"
    journal = smoke.EvidenceJournal(path)
    provider = DriftProvider()
    audited = smoke.AuditedProvider(
        provider, role="target", expected_model="expected-model", max_requests=2
    )
    audited.journal = journal

    async def scenario() -> None:
        messages = [LLMMessage(role=Role.USER, content="hello")]
        first = await audited.complete(messages, model="expected-model")
        assert first.model == "other-model"
        with pytest.raises(RuntimeError, match="stopped another model call"):
            await audited.complete(messages, model="expected-model")

    try:
        asyncio.run(scenario())
    finally:
        journal.close()
    assert provider.requests == 1
    assert _events(path)[-1]["model_drifted"] is True


def test_dry_run_does_not_construct_or_call_providers(tmp_path, monkeypatch, capsys) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(smoke, "REPO_ROOT", tmp_path)
    monkeypatch.setattr(
        smoke,
        "_source_identity",
        lambda: {"git_head": "test", "working_tree_dirty": False, "script_sha256": "test"},
    )
    (tmp_path / "runs").mkdir()
    target_settings, attacker_settings = _settings()
    monkeypatch.setattr(
        smoke,
        "role_settings",
        lambda cls: target_settings if cls is TargetSettings else attacker_settings,
    )
    monkeypatch.setattr(smoke, "_matched_utility_context", lambda target: "frozen-test")
    monkeypatch.setattr(
        smoke,
        "_online",
        lambda **kwargs: (_ for _ in ()).throw(AssertionError("online path called")),
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "m1c_online_smoke.py",
            "--out",
            "runs/dry.jsonl",
            "--budget",
            "1",
            "--max-tokens",
            "12000",
            "--max-cost",
            "0.05",
            "--max-seconds",
            "1200",
        ],
    )
    smoke.main()
    output = json.loads(capsys.readouterr().out)
    assert output["mode"] == "dry-run"
    assert len(output["configuration_sha256"]) == 64
    assert "api_key" not in json.dumps(output)
    assert not (tmp_path / "runs/dry.jsonl").exists()


def test_output_path_rejects_non_repository_runs_directory(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    (tmp_path / "runs").mkdir()

    with pytest.raises(ValueError, match="ignored runs"):
        smoke._ignored_output_path(Path("runs/raw.jsonl"))


def test_configuration_digest_includes_timeout_and_pacing(monkeypatch) -> None:
    monkeypatch.setattr(
        smoke,
        "_source_identity",
        lambda: {"git_head": "test", "working_tree_dirty": False, "script_sha256": "test"},
    )
    target, attacker = _settings()

    def digest(target_settings, attacker_settings):
        return smoke._configuration_digest(
            target_settings,
            attacker_settings,
            "frozen-test",
            max_tokens=12000,
            max_cost=0.05,
            max_seconds=1200,
        )

    original = digest(target, attacker)
    assert digest(target.model_copy(update={"request_timeout_seconds": 30.0}), attacker) != original
    assert digest(target, attacker.model_copy(update={"rpm": 3.0})) != original


def test_online_rejects_dirty_source_before_provider_calls(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(smoke, "REPO_ROOT", tmp_path)
    (tmp_path / "runs").mkdir()
    target, attacker = _settings()
    monkeypatch.setattr(
        smoke, "role_settings", lambda cls: target if cls is TargetSettings else attacker
    )
    monkeypatch.setattr(smoke, "_matched_utility_context", lambda _: "frozen-test")
    monkeypatch.setattr(
        smoke,
        "_source_identity",
        lambda: {"git_head": "test", "working_tree_dirty": True, "script_sha256": "test"},
    )
    monkeypatch.setattr(
        smoke,
        "_online",
        lambda **kwargs: (_ for _ in ()).throw(AssertionError("online path called")),
    )
    approved = smoke._configuration_digest(
        target,
        attacker,
        "frozen-test",
        max_tokens=12000,
        max_cost=0.05,
        max_seconds=1200,
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "m1c_online_smoke.py",
            "--online",
            "--out",
            "runs/dirty.jsonl",
            "--budget",
            "1",
            "--max-tokens",
            "12000",
            "--max-cost",
            "0.05",
            "--max-seconds",
            "1200",
            "--expected-config-sha256",
            approved,
        ],
    )

    with pytest.raises(SystemExit, match="2"):
        smoke.main()
    assert not (tmp_path / "runs/dirty.jsonl").exists()


@pytest.mark.parametrize("bad_limit", ["nan", "inf", "-inf"])
def test_nonfinite_cost_limit_rejected_before_provider_calls(
    tmp_path, monkeypatch, bad_limit
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "m1c_online_smoke.py",
            "--out",
            "runs/bad.jsonl",
            "--budget",
            "1",
            "--max-tokens",
            "12000",
            "--max-cost",
            bad_limit,
            "--max-seconds",
            "1200",
        ],
    )
    with pytest.raises(SystemExit, match="2"):
        smoke.main()
    assert not (tmp_path / "runs/bad.jsonl").exists()
