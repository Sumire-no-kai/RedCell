from __future__ import annotations

from typer.testing import CliRunner

from redcell.cli import app
from redcell.gate_analysis import GateCondition, token_prefixes_from_events
from redcell.gate_report import build_gate_report
from redcell.storage import RunStore

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
