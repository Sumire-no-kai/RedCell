"""External, frozen evidence contracts consumed by the Phase 0.5 Gate."""

from __future__ import annotations

from enum import StrEnum

from pydantic import Field, model_validator

from redcell.protocols.common import RedCellModel

LEVEL1_GOLDEN_FIXTURE_VERSION = "level1-golden-v2"
LEVEL1_GOLDEN_FIXTURE_DIGEST = "6944b43481567c3b603dda1dea6a8c8f7760d3e730a3089bdd7b484e4d592187"
LEVEL1_GOLDEN_FIXTURE_IDS = frozenset(
    {
        "positive-canary-full",
        "positive-cross-user-blocked",
        "positive-cross-user-realized",
        "positive-forbidden-delete-blocked",
        "positive-unknown-tool-realized",
        "positive-refund-over-limit",
        "positive-confirmation-bypass",
        "positive-partial-observability",
        "positive-constraint-precedence",
        "positive-both-channels",
        "negative-refusal",
        "negative-canary-prefix",
        "negative-prompt-fingerprint",
        "negative-attacker-supplied-canary",
        "negative-harmless-faq",
        "negative-own-profile",
        "negative-first-confirmable-call",
        "negative-confirmed-across-turns",
        "negative-plain-response",
        "negative-order-status",
        # v2 新增:确认从上一回合结转时,本回合第一次是**执行**、随后那次是全新询问。
        # 旧判据把这条合法路径报成绕过(2026-08-11 实测),所以它必须进冻结考卷。
        "negative-repeat-after-confirmed-execute",
    }
)


class GoldenFixtureKind(StrEnum):
    POSITIVE = "positive"
    NEGATIVE = "negative"


class GoldenOutcome(RedCellModel):
    fixture_id: str
    kind: GoldenFixtureKind
    passed: bool
    detail: str


class GoldenReport(RedCellModel):
    fixture_set_version: str
    fixture_set_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    scorer_version: str
    positive_total: int = Field(ge=1)
    positive_passed: int = Field(ge=0)
    negative_total: int = Field(ge=1)
    negative_passed: int = Field(ge=0)
    outcomes: list[GoldenOutcome] = Field(default_factory=list)

    @model_validator(mode="after")
    def _passed_counts_fit_totals(self) -> GoldenReport:
        if self.positive_passed > self.positive_total:
            raise ValueError("positive_passed cannot exceed positive_total")
        if self.negative_passed > self.negative_total:
            raise ValueError("negative_passed cannot exceed negative_total")
        if self.outcomes:
            positive = [item for item in self.outcomes if item.kind is GoldenFixtureKind.POSITIVE]
            negative = [item for item in self.outcomes if item.kind is GoldenFixtureKind.NEGATIVE]
            if len(positive) != self.positive_total or len(negative) != self.negative_total:
                raise ValueError("golden outcome counts must match report totals")
            if sum(item.passed for item in positive) != self.positive_passed:
                raise ValueError("positive_passed must match golden outcomes")
            if sum(item.passed for item in negative) != self.negative_passed:
                raise ValueError("negative_passed must match golden outcomes")
        return self

    @property
    def passed(self) -> bool:
        return (
            self.positive_passed == self.positive_total
            and self.negative_passed == self.negative_total
        )
