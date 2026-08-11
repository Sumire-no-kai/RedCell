"""Versioned, deterministic Level-1 golden fixture evaluation."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from pydantic import Field, model_validator

from redcell.arena.support_agent import (
    SUPPORT_AGENT_POLICY,
    SYSTEM_PROMPT_CANARY,
    SYSTEM_PROMPT_CANARY_PREFIX,
    SYSTEM_PROMPT_FINGERPRINTS,
)
from redcell.gate_evidence import (
    LEVEL1_GOLDEN_FIXTURE_VERSION,
    GoldenFixtureKind,
    GoldenOutcome,
    GoldenReport,
)
from redcell.protocols.common import (
    ImpactStatus,
    RedCellModel,
    SignalChannel,
    VulnerabilityCategory,
)
from redcell.protocols.trace import Turn
from redcell.scoring.level1 import Level1Scorer
from redcell.versions import LEVEL1_SCORER_VERSION


class GoldenFindingExpectation(RedCellModel):
    category: VulnerabilityCategory
    realized_impact: ImpactStatus
    attempted_action: bool
    defense_in_depth_held: bool


class GoldenExpectation(RedCellModel):
    reward: float = Field(ge=0.0, le=1.0)
    signal_tiers: dict[SignalChannel, str]
    findings: list[GoldenFindingExpectation] = Field(default_factory=list)


class GoldenFixture(RedCellModel):
    id: str
    kind: GoldenFixtureKind
    actor: str = "customer_a"
    strategy_id: str = "golden-fixture"
    turns: list[Turn] = Field(min_length=1)
    expected: GoldenExpectation


class GoldenFixtureSet(RedCellModel):
    version: str
    fixtures: list[GoldenFixture]

    @model_validator(mode="after")
    def _freeze_shape(self) -> GoldenFixtureSet:
        if self.version != LEVEL1_GOLDEN_FIXTURE_VERSION:
            raise ValueError("unknown Level-1 golden fixture version")
        if len({fixture.id for fixture in self.fixtures}) != len(self.fixtures):
            raise ValueError("golden fixture ids must be unique")
        positive = sum(item.kind is GoldenFixtureKind.POSITIVE for item in self.fixtures)
        negative = sum(item.kind is GoldenFixtureKind.NEGATIVE for item in self.fixtures)
        if (positive, negative) != (10, 11):
            # v2 起为 10 正 / 11 负:新增的那条阴性锁住"确认结转后再问一次"这条
            # 被旧判据误报过的合法路径。数量写死是刻意的 —— 冻结考卷少一张纸
            # 必须当场失败,而不是安静地少考一题。
            raise ValueError(
                f"{LEVEL1_GOLDEN_FIXTURE_VERSION} requires exactly 10 positive "
                "and 11 negative fixtures"
            )
        return self


def evaluate_golden(path: Path) -> GoldenReport:
    """Evaluate the frozen fixture file without calling any Provider."""
    raw = json.loads(path.read_text(encoding="utf-8"))
    digest = _canonical_digest(raw)
    fixtures = GoldenFixtureSet.model_validate(_expand_tokens(raw))
    scorer = Level1Scorer(SUPPORT_AGENT_POLICY)
    outcomes: list[GoldenOutcome] = []
    for fixture in fixtures.fixtures:
        result = scorer.score(
            fixture.turns,
            run_id=f"golden:{fixture.id}",
            attempt_id=f"golden:{fixture.id}",
            actor=fixture.actor,
            strategy_id=fixture.strategy_id,
        )
        actual = GoldenExpectation(
            reward=result.reward,
            signal_tiers={signal.channel: signal.tier for signal in result.signals},
            findings=[
                GoldenFindingExpectation(
                    category=finding.category.value,
                    realized_impact=finding.triad.realized_impact,
                    attempted_action=finding.triad.attempted_action,
                    defense_in_depth_held=finding.triad.defense_in_depth_held,
                )
                for finding in result.findings
            ],
        )
        passed = actual == fixture.expected
        outcomes.append(
            GoldenOutcome(
                fixture_id=fixture.id,
                kind=fixture.kind,
                passed=passed,
                detail="matched" if passed else _mismatch(fixture.expected, actual),
            )
        )
    positive = [item for item in outcomes if item.kind is GoldenFixtureKind.POSITIVE]
    negative = [item for item in outcomes if item.kind is GoldenFixtureKind.NEGATIVE]
    return GoldenReport(
        fixture_set_version=fixtures.version,
        fixture_set_digest=digest,
        scorer_version=LEVEL1_SCORER_VERSION,
        positive_total=len(positive),
        positive_passed=sum(item.passed for item in positive),
        negative_total=len(negative),
        negative_passed=sum(item.passed for item in negative),
        outcomes=outcomes,
    )


def _canonical_digest(raw: Any) -> str:
    encoded = json.dumps(raw, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )
    return hashlib.sha256(encoded).hexdigest()


def _expand_tokens(value: Any) -> Any:
    if isinstance(value, str):
        return (
            value.replace("{{SYSTEM_PROMPT_CANARY}}", SYSTEM_PROMPT_CANARY)
            .replace("{{SYSTEM_PROMPT_CANARY_PREFIX}}", SYSTEM_PROMPT_CANARY_PREFIX)
            .replace("{{SYSTEM_PROMPT_FINGERPRINT}}", SYSTEM_PROMPT_FINGERPRINTS[0])
        )
    if isinstance(value, list):
        return [_expand_tokens(item) for item in value]
    if isinstance(value, dict):
        return {key: _expand_tokens(item) for key, item in value.items()}
    return value


def _mismatch(expected: GoldenExpectation, actual: GoldenExpectation) -> str:
    return json.dumps(
        {
            "expected": expected.model_dump(mode="json"),
            "actual": actual.model_dump(mode="json"),
        },
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
