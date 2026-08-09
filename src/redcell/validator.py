"""Finding replay validation without re-running Controller or Generator."""

from __future__ import annotations

from collections import defaultdict

from pydantic import Field, model_validator

from redcell.finding_identity import attack_path_signature
from redcell.protocols.adapter import AdapterInput, Message, TargetAdapter
from redcell.protocols.common import RedCellModel, Role
from redcell.protocols.finding import Finding
from redcell.protocols.trace import Attempt, CostRecord, Turn
from redcell.scoring.level1 import Level1Scorer


class ReplayValidation(RedCellModel):
    run_id: str
    attack_path: str
    runs: int = Field(ge=1)
    reproduced: int = Field(ge=0)

    @model_validator(mode="after")
    def _reproduced_cannot_exceed_runs(self) -> ReplayValidation:
        if self.reproduced > self.runs:
            raise ValueError("reproduced cannot exceed runs")
        return self

    @property
    def rate(self) -> float:
        return self.reproduced / self.runs if self.runs else 0.0


class ValidationReport(RedCellModel):
    repeats: int = Field(ge=1)
    results: list[ReplayValidation] = Field(default_factory=list)
    target_usage: CostRecord = Field(default_factory=CostRecord)


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
    representatives: dict[tuple[str, str], Attempt] = {}
    for attempt in attempts:
        for finding in findings_by_attempt[attempt.id]:
            path = attack_path_signature(finding)
            representatives.setdefault((attempt.run_id, path), attempt)
    results: list[ReplayValidation] = []
    target_usage = CostRecord()
    for (run_id, path), attempt in sorted(representatives.items()):
        reproduced = 0
        for _ in range(repeats):
            replay_findings, replay_usage = await _replay(adapter, scorer, attempt)
            target_usage = _sum_costs(target_usage, replay_usage)
            if path in {attack_path_signature(finding) for finding in replay_findings}:
                reproduced += 1
        results.append(
            ReplayValidation(
                run_id=run_id,
                attack_path=path,
                runs=repeats,
                reproduced=reproduced,
            )
        )
    return ValidationReport(repeats=repeats, results=results, target_usage=target_usage)


async def _replay(
    adapter: TargetAdapter, scorer: Level1Scorer, attempt: Attempt
) -> tuple[list[Finding], CostRecord]:
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
    findings = scorer.score(
        turns,
        run_id=attempt.run_id,
        attempt_id=f"validation:{attempt.id}",
        actor=attempt.actor,
        strategy_id=attempt.strategy_id,
    ).findings
    usage = CostRecord(
        prompt_tokens=sum(turn.output.trace_metadata.prompt_tokens for turn in turns),
        completion_tokens=sum(turn.output.trace_metadata.completion_tokens for turn in turns),
        cached_input_tokens=sum(turn.output.trace_metadata.cached_input_tokens for turn in turns),
        usage_known=all(turn.output.trace_metadata.usage_known for turn in turns),
        usd=sum(turn.output.trace_metadata.cost_usd for turn in turns),
        wall_ms=sum(turn.output.trace_metadata.latency_ms for turn in turns),
    )
    return findings, usage


def _sum_costs(left: CostRecord, right: CostRecord) -> CostRecord:
    return CostRecord(
        prompt_tokens=left.prompt_tokens + right.prompt_tokens,
        completion_tokens=left.completion_tokens + right.completion_tokens,
        cached_input_tokens=left.cached_input_tokens + right.cached_input_tokens,
        usage_known=left.usage_known and right.usage_known,
        usd=left.usd + right.usd,
        wall_ms=left.wall_ms + right.wall_ms,
    )
