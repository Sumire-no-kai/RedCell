from __future__ import annotations

import json
from pathlib import Path

from redcell.controller import LLMControllerAdapter
from redcell.controller_controls import (
    ControllerContractReport,
    controller_contract_cases,
    run_controller_contract_controls,
)
from redcell.llm import ScriptedProvider


def test_controller_contract_cases_are_frozen_and_do_not_use_gate_inputs() -> None:
    cases = controller_contract_cases()

    assert len(cases) == 12
    assert cases[5].evidence.available_strategy_ids == ["direct"]
    assert all("finding" not in case.evidence.model_dump_json().lower() for case in cases)


async def test_controller_contract_report_requires_the_frozen_thresholds() -> None:
    responses = ['{"selected_strategy_id":"direct"}'] * 12
    report = await run_controller_contract_controls(
        LLMControllerAdapter(
            provider=ScriptedProvider(responses, tokens_per_call=(3, 1)),
            run_id="controls",
            prompt_version="controller-prompt-v1",
            model="scripted",
        )
    )

    assert report.passed
    assert report.successful_count == 12
    assert report.first_pass_count == 12
    assert report.known_usage_count == 12


async def test_report_totals_provider_usage_for_billing_reconciliation() -> None:
    """对账要的是 RedCell 侧的用量数字;12 次成功、无 repair → 12 次请求,token 逐次相加。"""
    responses = ['{"selected_strategy_id":"direct"}'] * 12
    report = await run_controller_contract_controls(
        LLMControllerAdapter(
            provider=ScriptedProvider(responses, tokens_per_call=(3, 1)),
            run_id="controls",
            prompt_version="controller-prompt-v1",
            model="scripted",
        )
    )

    usage = report.usage
    assert usage is not None
    assert (usage.requests, usage.prompt_tokens, usage.completion_tokens) == (12, 36, 12)
    assert usage.total_tokens == 48
    assert usage.usage_known
    assert usage.started_at <= usage.finished_at


async def test_a_repair_counts_as_a_second_provider_request() -> None:
    responses = ["not json", '{"selected_strategy_id":"direct"}'] + [
        '{"selected_strategy_id":"direct"}'
    ] * 11
    report = await run_controller_contract_controls(
        LLMControllerAdapter(
            provider=ScriptedProvider(responses, tokens_per_call=(3, 1)),
            run_id="controls",
            prompt_version="controller-prompt-v1",
            model="scripted",
        )
    )

    assert report.first_pass_count == 11
    assert report.usage is not None
    assert report.usage.requests == 13
    assert report.usage.prompt_tokens == 39


def test_a_report_written_before_usage_was_recorded_still_loads(tmp_path: Path) -> None:
    payload = {
        "policy_version": "controller-contract-controls-v1",
        "outcomes": [
            {
                "id": f"case-{i}",
                "passed": True,
                "first_pass": True,
                "known_usage": True,
                "repaired": False,
            }
            for i in range(12)
        ],
    }
    loaded = ControllerContractReport.model_validate_json(json.dumps(payload))
    assert loaded.passed
    assert loaded.usage is None
