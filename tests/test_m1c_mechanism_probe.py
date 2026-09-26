"""Offline contract checks for the frozen M1-C paired research probe."""

from __future__ import annotations

import hashlib
import json
import math

import pytest
import scripts.m1c_mechanism_probe as probe
from scripts.m1c_mechanism_probe import TRIALS, build_request, run_probe, verify_pairs

from redcell.attacker_observation import AttackerVisibility
from redcell.llm import ScriptedProvider
from redcell.llm.base import LLMMessage, LLMProvider, LLMResponse, LLMToolDefinition


def _choice(message: str) -> str:
    return json.dumps(
        {
            "working_state": {"hypotheses": [], "next_objective": "Check the order boundary."},
            "action": {
                "kind": "continue_attempt",
                "strategy_id": None,
                "message": message,
                "test_intent": "Test the next authorized boundary.",
                "reason": None,
                "evidence_refs": [],
            },
        }
    )


def _events(path):
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def test_frozen_pairs_change_only_public_feedback() -> None:
    verify_pairs()
    requests = [build_request(trial) for trial in TRIALS]
    assert len(requests) == 8
    assert [trial.feedback for trial in TRIALS] == [
        "permission_denied",
        "not_found",
        "permission_denied",
        "not_found",
        "not_found",
        "permission_denied",
        "not_found",
        "permission_denied",
    ]
    assert all(
        request.observations.visibility is AttackerVisibility.RESPONSE_ONLY
        for request in (requests[index] for index in (2, 3, 6, 7))
    )
    assert len({requests[index].model_dump_json() for index in (2, 3, 6, 7)}) == 1
    assert requests[0].model_dump_json() == requests[5].model_dump_json()
    assert requests[1].model_dump_json() == requests[4].model_dump_json()

    a = requests[0].observations.attempts[0].turns[0].tool_actions[0]
    b = requests[1].observations.attempts[0].turns[0].tool_actions[0]
    assert a.error_category.value == "permission_denied"
    assert b.error_category.value == "not_found"
    assert "ORD-2001" not in (a.error_summary or "")
    assert "ORD-2001" not in (b.error_summary or "")
    assert requests[0].observations.digest != requests[1].observations.digest


async def test_probe_journals_eight_decisions_and_delivers_exact_messages(tmp_path) -> None:
    messages = [f"Check boundary {index}" for index in range(8)]
    provider = ScriptedProvider([_choice(message) for message in messages], tokens_per_call=(10, 4))
    path = tmp_path / "probe.jsonl"

    summary = await run_probe(
        provider,
        model="test",
        output_path=path,
        max_total_tokens=1000,
        max_cost_usd=1.0,
        max_seconds=60.0,
    )

    events = _events(path)
    assert summary["status"] == "complete"
    assert summary["completed_trials"] == 8
    assert summary["provider_requests"] == 8
    assert summary["delivered_messages"] == 8
    assert provider.call_count == 8
    delivered = [
        event["message_sha256"] for event in events if event["event"] == "message_delivered"
    ]
    assert delivered == [hashlib.sha256(message.encode()).hexdigest() for message in messages]
    assert [event["trial"] for event in events if event["event"] == "decision_requested"] == [
        trial.label for trial in TRIALS
    ]
    assert events[-1] == summary


class _UnknownUsageProvider(LLMProvider):
    def __init__(self, *, response_model: str | None = None) -> None:
        self.calls = 0
        self.response_model = response_model

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
        tools: list[LLMToolDefinition] | None = None,
        tool_choice: str | None = None,
    ) -> LLMResponse:
        self.calls += 1
        return LLMResponse(
            content=_choice("Unknown usage"),
            model=self.response_model or model or "test",
            usage_known=self.response_model is not None,
            prompt_tokens=10 if self.response_model is not None else 0,
            completion_tokens=4 if self.response_model is not None else 0,
        )


async def test_probe_stops_on_unknown_usage_without_another_call(tmp_path) -> None:
    provider = _UnknownUsageProvider()
    path = tmp_path / "unknown.jsonl"

    summary = await run_probe(
        provider,
        model="test",
        output_path=path,
        max_total_tokens=1000,
        max_cost_usd=1.0,
        max_seconds=60.0,
    )

    events = _events(path)
    assert summary["status"] == "stopped"
    assert summary["completed_trials"] == 0
    assert summary["provider_requests"] == provider.calls == 1
    assert summary["delivered_messages"] == 0
    assert [event["event"] for event in events if event["event"] == "decision_failed"] == [
        "decision_failed"
    ]
    assert not any(event["event"] == "message_delivered" for event in events)


async def test_probe_stops_on_response_model_drift(tmp_path) -> None:
    provider = _UnknownUsageProvider(response_model="different-model")
    path = tmp_path / "drift.jsonl"

    summary = await run_probe(
        provider,
        model="test",
        output_path=path,
        max_total_tokens=1000,
        max_cost_usd=1.0,
        max_seconds=60.0,
    )

    assert summary["status"] == "stopped"
    assert summary["provider_requests"] == provider.calls == 1
    assert summary["total"]["prompt_tokens"] == 10
    assert summary["delivered_messages"] == 0
    assert [event["reason"] for event in _events(path) if event["event"] == "decision_failed"] == [
        "model_drift"
    ]


async def test_probe_counts_one_repair_inside_its_trial(tmp_path) -> None:
    provider = ScriptedProvider(
        ["invalid json", *[_choice(f"Message {index}") for index in range(8)]],
        tokens_per_call=(10, 4),
    )
    path = tmp_path / "repair.jsonl"

    summary = await run_probe(
        provider,
        model="test",
        output_path=path,
        max_total_tokens=1000,
        max_cost_usd=1.0,
        max_seconds=60.0,
    )

    events = _events(path)
    selections = [event for event in events if event["event"] == "decision_selected"]
    responses = [event for event in events if event["event"] == "provider_response_received"]
    assert summary["status"] == "complete"
    assert summary["completed_trials"] == 8
    assert summary["provider_requests"] == provider.call_count == 9
    assert summary["total"]["prompt_tokens"] == 90
    assert responses[0]["response_content"] == "invalid json"
    assert selections[0]["selection"]["repaired"] is True
    assert all(selection["selection"]["repaired"] is False for selection in selections[1:])


async def test_probe_accounts_for_call_that_crosses_token_cap(tmp_path) -> None:
    provider = ScriptedProvider([_choice("First"), _choice("Second")], tokens_per_call=(10, 4))
    path = tmp_path / "budget.jsonl"

    summary = await run_probe(
        provider,
        model="test",
        output_path=path,
        max_total_tokens=25,
        max_cost_usd=1.0,
        max_seconds=60.0,
    )

    events = _events(path)
    assert summary["status"] == "stopped"
    assert summary["completed_trials"] == 1
    assert summary["provider_requests"] == provider.call_count == 2
    assert summary["delivered_messages"] == 1
    assert summary["total"]["prompt_tokens"] == 20
    assert summary["total"]["completion_tokens"] == 8
    assert [event["reason"] for event in events if event["event"] == "decision_failed"] == [
        "tokens"
    ]


@pytest.mark.parametrize("invalid", [math.nan, math.inf, -math.inf, 0.0])
async def test_probe_rejects_non_finite_or_zero_budget_before_provider_call(
    tmp_path, invalid: float
) -> None:
    provider = ScriptedProvider([_choice("Unused")])

    with pytest.raises(ValueError, match="limits must be positive"):
        await run_probe(
            provider,
            model="test",
            output_path=tmp_path / "invalid.jsonl",
            max_total_tokens=1000,
            max_cost_usd=invalid,
            max_seconds=60.0,
        )
    with pytest.raises(ValueError, match="limits must be positive"):
        await run_probe(
            provider,
            model="test",
            output_path=tmp_path / "invalid-time.jsonl",
            max_total_tokens=1000,
            max_cost_usd=1.0,
            max_seconds=invalid,
        )

    assert provider.call_count == 0


def test_probe_rejects_tampered_frozen_utility_file(tmp_path, monkeypatch) -> None:
    changed = tmp_path / "baseline.json"
    changed.write_bytes(probe.BASELINE_PATH.read_bytes() + b"\n")
    monkeypatch.setattr(probe, "BASELINE_PATH", changed)

    with pytest.raises(ValueError, match="Frozen utility baseline file changed"):
        probe._check_utility_precondition()
