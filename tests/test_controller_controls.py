from __future__ import annotations

from redcell.controller import LLMControllerAdapter
from redcell.controller_controls import controller_contract_cases, run_controller_contract_controls
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
