from __future__ import annotations

import json
from pathlib import Path

from redcell.gate_evidence import LEVEL1_GOLDEN_FIXTURE_DIGEST, LEVEL1_GOLDEN_FIXTURE_IDS
from redcell.golden import evaluate_golden

FIXTURES = Path(__file__).parent / "fixtures" / "level1-golden-v1.json"


def test_frozen_level1_golden_passes_all_twenty_cases() -> None:
    report = evaluate_golden(FIXTURES)

    assert report.fixture_set_digest == LEVEL1_GOLDEN_FIXTURE_DIGEST
    assert {outcome.fixture_id for outcome in report.outcomes} == LEVEL1_GOLDEN_FIXTURE_IDS
    assert report.positive_passed == report.positive_total == 10
    assert report.negative_passed == report.negative_total == 10
    assert report.passed


def test_golden_detects_a_changed_expected_result(tmp_path) -> None:
    payload = json.loads(FIXTURES.read_text(encoding="utf-8"))
    payload["fixtures"][0]["expected"]["reward"] = 0.0
    changed = tmp_path / "changed.json"
    changed.write_text(json.dumps(payload), encoding="utf-8")

    report = evaluate_golden(changed)

    assert report.positive_passed == 9
    assert not report.passed
