from __future__ import annotations

from redcell.gate_report import build_gate_report
from redcell.storage import RunStore


def test_empty_store_is_not_a_supported_gate(tmp_path) -> None:
    with RunStore(f"sqlite:///{tmp_path / 'gate.db'}") as store:
        report = build_gate_report(store)

    assert report.prefixes == []
    assert report.analysis.valid_seeds == []
    assert not report.supported
