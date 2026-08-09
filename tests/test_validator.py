from __future__ import annotations

import pytest

from redcell.validator import validate_attack_paths


async def test_validator_rejects_non_positive_repeat_count() -> None:
    with pytest.raises(ValueError, match="repeats"):
        await validate_attack_paths(  # type: ignore[arg-type]
            adapter=None, scorer=None, attempts=[], findings=[], repeats=0
        )


async def test_validator_has_no_replay_work_without_confirmed_paths() -> None:
    report = await validate_attack_paths(  # type: ignore[arg-type]
        adapter=None, scorer=None, attempts=[], findings=[], repeats=5
    )

    assert report.repeats == 5
    assert report.results == []
