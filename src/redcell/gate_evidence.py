"""External, frozen evidence contracts consumed by the Phase 0.5 Gate."""

from __future__ import annotations

from pydantic import Field, model_validator

from redcell.protocols.common import RedCellModel

LEVEL1_GOLDEN_FIXTURE_VERSION = "level1-golden-v1"


class GoldenReport(RedCellModel):
    fixture_set_version: str
    fixture_set_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    scorer_version: str
    positive_total: int = Field(ge=1)
    positive_passed: int = Field(ge=0)
    negative_total: int = Field(ge=1)
    negative_passed: int = Field(ge=0)

    @model_validator(mode="after")
    def _passed_counts_fit_totals(self) -> GoldenReport:
        if self.positive_passed > self.positive_total:
            raise ValueError("positive_passed cannot exceed positive_total")
        if self.negative_passed > self.negative_total:
            raise ValueError("negative_passed cannot exceed negative_total")
        return self

    @property
    def passed(self) -> bool:
        return (
            self.positive_passed == self.positive_total
            and self.negative_passed == self.negative_total
        )
