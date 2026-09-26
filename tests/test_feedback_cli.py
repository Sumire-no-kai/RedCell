from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest
from typer.testing import CliRunner

from redcell.arena.support_agent.arena import SUPPORT_AGENT_ARENA
from redcell.budget import BudgetLimit
from redcell.cli import ExitCode, app
from redcell.feedback_attacker import LLMFeedbackAttackAdapter
from redcell.llm.scripted import ScriptedProvider
from redcell.orchestrator import RunExecutionResult
from redcell.protocols.run import (
    ProviderRunConfiguration,
    RunEventType,
    RunStatus,
    UsageAccountingMode,
)
from redcell.storage import RunStore
from redcell.versions import FEEDBACK_EXPERIMENT_CONDITIONS_SCHEMA_VERSION

runner = CliRunner()


def _db(tmp_path: Path) -> str:
    return f"sqlite:///{tmp_path / 'feedback.db'}"


def _feedback_args(tmp_path: Path) -> list[str]:
    return [
        "run",
        "--attack-driver",
        "feedback",
        "--budget",
        "1",
        "--max-tokens",
        "100",
        "--db",
        _db(tmp_path),
        "--out",
        str(tmp_path / "reports"),
    ]


def test_offline_feedback_cli_persists_v5_run_and_decision_events(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        [
            *_feedback_args(tmp_path),
            "--feedback-visibility",
            "tool-status",
            "--max-decision-steps",
            "3",
            "--max-turns-per-attempt",
            "1",
        ],
    )

    assert result.exit_code == ExitCode.CLEAN, result.output
    with RunStore(_db(tmp_path)) as store:
        runs = store.list_runs()
        assert len(runs) == 1
        run = runs[0]
        assert run.status is RunStatus.COMPLETED
        assert run.stopped_by is BudgetLimit.ATTEMPTS
        assert run.feedback_stop_reason == BudgetLimit.ATTEMPTS.value
        assert run.algorithm == "scripted-feedback"
        assert run.conditions_fingerprint_verified
        assert run.experiment_conditions is not None
        conditions = run.experiment_conditions
        assert conditions.conditions_schema_version == FEEDBACK_EXPERIMENT_CONDITIONS_SCHEMA_VERSION
        assert conditions.feedback is not None
        assert conditions.feedback.driver_name == "scripted-feedback"
        assert conditions.feedback.observation_visibility == "tool-status"
        assert conditions.feedback.max_decision_steps == 3
        assert conditions.feedback.max_turns_per_attempt == 1
        assert conditions.search is None
        assert conditions.generation_memory is None
        assert conditions.controller is None
        assert conditions.attacker.provider == "scripted-feedback"
        assert len(store.attempts_for(run.id)) == 1
        event_types = [event.event_type for event in store.events_for(run.id)]
        assert RunEventType.FEEDBACK_DECISION_REQUESTED in event_types
        assert RunEventType.FEEDBACK_DECISION_SELECTED in event_types
        assert RunEventType.FEEDBACK_TARGET_REQUESTED in event_types
        assert RunEventType.TURN_COMPLETED in event_types
    assert (tmp_path / "reports" / run.id / "report.json").exists()
    assert "反馈结束原因" in result.output
    assert "不得作为正式安全结论" in result.output
    html = (tmp_path / "reports" / run.id / "report.html").read_text(encoding="utf-8")
    assert "M1-B development run" in html
    assert "Feedback stop reason" in html


def test_offline_feedback_cli_accepts_native_v2_and_records_tool_schema(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        [*_feedback_args(tmp_path), "--tool-call-protocol", "native-function-calling-v2"],
    )

    assert result.exit_code == ExitCode.CLEAN, result.output
    with RunStore(_db(tmp_path)) as store:
        run = store.list_runs()[0]
        assert run.conditions_fingerprint_verified
        assert run.experiment_conditions.arena.tool_call_protocol_version == (
            "native-function-calling-v2"
        )
        assert run.experiment_conditions.arena.tool_schema_sha256 == (
            SUPPORT_AGENT_ARENA.tool_schema_sha256
        )
        assert len(store.attempts_for(run.id)) == 1


@pytest.mark.parametrize(
    "extra",
    [
        ["--algorithm", "static"],
        ["--search", "random"],
        ["--cross-attempt-memory", "bounded-relevant-v1"],
        ["--cross-attempt-memory", "off"],
        ["--controller-prompt-version", "controller-prompt-v2"],
        ["--controller-prompt-version", "controller-prompt-v1"],
        ["--per-strategy", "1"],
        ["--top-up-abandoned"],
        ["--execution-host-profile", "windows-wakelock-v1"],
        ["--feedback-visibility", "unknown"],
        ["--feedback-visibility", ""],
        ["--max-decision-steps", "0"],
        ["--max-turns-per-attempt", "0"],
    ],
)
def test_feedback_cli_rejects_incompatible_or_invalid_options_before_run(
    tmp_path: Path, extra: list[str]
) -> None:
    result = runner.invoke(app, [*_feedback_args(tmp_path), *extra])

    assert result.exit_code == 2, result.output
    assert not (tmp_path / "feedback.db").exists()


def test_feedback_cli_requires_token_limit_and_explicit_driver(tmp_path: Path) -> None:
    without_tokens = runner.invoke(
        app,
        ["run", "--attack-driver", "feedback", "--budget", "1", "--db", _db(tmp_path)],
    )
    without_driver = runner.invoke(app, ["run", "--max-decision-steps", "3"])
    unknown_driver = runner.invoke(app, ["run", "--attack-driver", "unknown"])

    assert without_tokens.exit_code == 2
    assert without_driver.exit_code == 2
    assert unknown_driver.exit_code == 2
    assert not (tmp_path / "feedback.db").exists()


def test_feedback_resume_is_rejected_before_provider_loading(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    result = runner.invoke(app, _feedback_args(tmp_path))
    assert result.exit_code == ExitCode.CLEAN, result.output
    with RunStore(_db(tmp_path)) as store:
        run = store.list_runs()[0]

    def fail_if_loaded(*args: object, **kwargs: object) -> None:
        raise AssertionError("resume must reject v5 before loading providers")

    monkeypatch.setattr("redcell.cli._providers", fail_if_loaded)
    resumed = runner.invoke(app, ["resume", run.id, "--db", _db(tmp_path)])

    assert resumed.exit_code == ExitCode.BAD_CONFIG, resumed.output
    assert "反馈驱动 Run 当前不支持 resume" in resumed.output


def _fake_online_pair(*, target_reports_cost: bool = False):
    class TargetProvider(ScriptedProvider):
        @property
        def reports_cost(self) -> bool:
            return target_reports_cost

    target = TargetProvider(default="Offline target response", model="target-test")
    attacker = ScriptedProvider(default="unused", model="attacker-test")
    target.timeout_seconds = 30.0
    attacker.timeout_seconds = 30.0
    configuration = {
        "provider": "scripted",
        "base_url": "https://example.invalid",
        "temperature": 0.0,
        "max_tokens": 64,
        "rpm": 0.0,
        "max_concurrency": 1,
        "input_usd_per_mtok": 0.0,
        "output_usd_per_mtok": 0.0,
        "cached_input_usd_per_mtok": 0.0,
        "usage_accounting_mode": UsageAccountingMode.PROMPT_COMPLETION_V1,
        "usage_covers_billed_tokens": True,
    }
    closed: list[bool] = []

    async def aclose() -> None:
        closed.append(True)

    pair = SimpleNamespace(
        target=target,
        attacker=attacker,
        target_configuration=ProviderRunConfiguration(**configuration, model="target-test"),
        attacker_configuration=ProviderRunConfiguration(**configuration, model="attacker-test"),
        attacker_max_tokens=64,
        aclose=aclose,
    )
    return pair, closed


def test_online_feedback_cli_uses_attacker_provider_without_paid_calls(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pair, closed = _fake_online_pair()
    seen: dict[str, object] = {}
    monkeypatch.setattr("redcell.cli.load_providers", lambda env_file=None: pair)

    class CaptureOrchestrator:
        def __init__(self, *, driver, **kwargs) -> None:
            assert isinstance(driver, LLMFeedbackAttackAdapter)
            assert driver._provider is pair.attacker

        async def execute(self, request):
            seen["run"] = request.run
            return RunExecutionResult(
                run=request.run.model_copy(update={"status": RunStatus.COMPLETED}),
                attempts=[],
                findings=[],
            )

    monkeypatch.setattr("redcell.cli.FeedbackRunOrchestrator", CaptureOrchestrator)
    monkeypatch.setattr("redcell.cli._emit", lambda *args: {})
    monkeypatch.setattr("redcell.cli._summarise", lambda *args: None)
    result = runner.invoke(app, [*_feedback_args(tmp_path), "--online"])

    assert result.exit_code == ExitCode.CLEAN, result.output
    run = seen["run"]
    assert run.algorithm == "llm-feedback"
    assert run.experiment_conditions.feedback.driver_name == "llm-feedback"
    assert run.experiment_conditions.attacker.model == "attacker-test"
    assert pair.attacker.call_count == 0
    assert pair.target.call_count == 0
    assert closed == [True]


def test_online_feedback_max_cost_requires_attacker_cost_reporting(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pair, closed = _fake_online_pair(target_reports_cost=True)
    monkeypatch.setattr("redcell.cli.load_providers", lambda env_file=None: pair)
    result = runner.invoke(app, [*_feedback_args(tmp_path), "--online", "--max-cost", "1"])

    assert result.exit_code == ExitCode.BAD_CONFIG, result.output
    assert "Target 与 Attacker 必须都报告成本" in result.output
    assert pair.attacker.call_count == 0
    assert pair.target.call_count == 0
    assert closed == [True]
    assert not (tmp_path / "feedback.db").exists()
