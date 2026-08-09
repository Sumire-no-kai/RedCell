from __future__ import annotations

from typer.testing import CliRunner

from redcell.cli import app
from redcell.controls import ControlOutcome, ControlsReport
from redcell.gate_analysis import GateCondition, token_prefixes_from_events
from redcell.gate_report import build_gate_report
from redcell.storage import RunStore
from redcell.validator import ValidationReport

runner = CliRunner()


def test_empty_store_is_not_a_supported_gate(tmp_path) -> None:
    with RunStore(f"sqlite:///{tmp_path / 'gate.db'}") as store:
        report = build_gate_report(store)

    assert report.prefixes == []
    assert report.analysis.valid_seeds == []
    assert report.protection_failures == [
        "missing_controls",
        "missing_seed_plan",
        "missing_validation",
        "no_phase_0_5_prefixes",
    ]
    assert not report.supported


def test_prefix_projection_reads_a_real_cli_event_stream(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    db = f"sqlite:///{tmp_path / 'gate.db'}"
    result = runner.invoke(app, ["run", "--budget", "1", "--db", db])
    assert result.exit_code == 0, result.output
    with RunStore(db) as store:
        run = store.list_runs()[0]
        prefixes = token_prefixes_from_events(
            run=run, events=store.events_for(run.id), findings=store.findings_for(run.id)
        )

    assert [prefix.condition for prefix in prefixes] == [GateCondition.STATIC_OFF] * 3
    assert [prefix.checkpoint_tokens for prefix in prefixes] == [64000, 160000, 320000]


def test_gate_rejects_an_empty_controls_report(tmp_path) -> None:
    with RunStore(f"sqlite:///{tmp_path / 'gate.db'}") as store:
        report = build_gate_report(
            store, controls=ControlsReport(), validation=ValidationReport(repeats=5)
        )

    assert "controls_shape_invalid" in report.protection_failures


def test_gate_report_cli_loads_protection_evidence(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    controls = ControlsReport(
        positive=[
            ControlOutcome(id=f"positive-{index}", passed=True, detail="ok") for index in range(3)
        ],
        negative=[
            ControlOutcome(
                id=f"negative-{index}", passed=True, detail="ok", runs=5, completed_runs=4
            )
            for index in range(10)
        ],
    )
    controls_path = tmp_path / "controls.json"
    controls_path.write_text(controls.model_dump_json(), encoding="utf-8")
    validation_path = tmp_path / "validation.json"
    validation_path.write_text(ValidationReport(repeats=5).model_dump_json(), encoding="utf-8")
    seed_path = tmp_path / "seed-plan.json"
    seed_path.write_text(
        '{"primary":[100,101,102,103,104,105,106,107,108,109,110,111],'
        '"reserve":[112,113,114,115]}',
        encoding="utf-8",
    )

    result = runner.invoke(
        app,
        [
            "gate-report",
            "--db",
            f"sqlite:///{tmp_path / 'gate.db'}",
            "--controls-json",
            str(controls_path),
            "--validation-json",
            str(validation_path),
            "--seed-plan-json",
            str(seed_path),
        ],
    )

    assert result.exit_code == 0, result.output
    assert "NOT SUPPORTED / INCOMPLETE" in result.output
