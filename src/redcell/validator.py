"""Finding replay validation without re-running Controller or Generator."""

from __future__ import annotations

from collections import defaultdict

from pydantic import Field

from redcell.finding_identity import attack_path_signature
from redcell.protocols.adapter import AdapterInput, Message, TargetAdapter
from redcell.protocols.common import RedCellModel, Role
from redcell.protocols.finding import Finding
from redcell.protocols.trace import Attempt, Turn
from redcell.scoring.level1 import Level1Scorer


class ReplayValidation(RedCellModel):
    attack_path: str
    runs: int
    reproduced: int

    @property
    def rate(self) -> float:
        return self.reproduced / self.runs if self.runs else 0.0


class ValidationReport(RedCellModel):
    repeats: int
    results: list[ReplayValidation] = Field(default_factory=list)


async def validate_attack_paths(
    *,
    adapter: TargetAdapter,
    scorer: Level1Scorer,
    attempts: list[Attempt],
    findings: list[Finding],
    repeats: int = 5,
) -> ValidationReport:
    if repeats < 1:
        raise ValueError("repeats must be >= 1")
    findings_by_attempt: dict[str, list[Finding]] = defaultdict(list)
    for finding in findings:
        findings_by_attempt[finding.attempt_id].append(finding)
    representatives: dict[str, Attempt] = {}
    for attempt in attempts:
        for finding in findings_by_attempt[attempt.id]:
            representatives.setdefault(attack_path_signature(finding), attempt)
    results: list[ReplayValidation] = []
    for path, attempt in sorted(representatives.items()):
        reproduced = 0
        for _ in range(repeats):
            replay_findings = await _replay(adapter, scorer, attempt)
            if path in {attack_path_signature(finding) for finding in replay_findings}:
                reproduced += 1
        results.append(ReplayValidation(attack_path=path, runs=repeats, reproduced=reproduced))
    return ValidationReport(repeats=repeats, results=results)


async def _replay(adapter: TargetAdapter, scorer: Level1Scorer, attempt: Attempt) -> list[Finding]:
    await adapter.reset()
    conversation: list[Message] = []
    turns: list[Turn] = []
    for source_turn in attempt.turns:
        conversation.append(Message(role=Role.USER, content=source_turn.attacker_message))
        output = await adapter.send(AdapterInput(messages=list(conversation), actor=attempt.actor))
        turns.append(
            Turn(
                index=source_turn.index,
                attacker_message=source_turn.attacker_message,
                output=output,
            )
        )
        conversation.append(Message(role=Role.ASSISTANT, content=output.assistant_message))
    return scorer.score(
        turns,
        run_id=attempt.run_id,
        attempt_id=f"validation:{attempt.id}",
        actor=attempt.actor,
        strategy_id=attempt.strategy_id,
    ).findings
