"""Finding replay validation without re-running Controller or Generator."""

from __future__ import annotations

import asyncio
import hashlib
import json
import random
from collections import defaultdict
from collections.abc import Callable
from pathlib import Path

from pydantic import Field, model_validator

from redcell.failures import (
    FailureKind,
    FailureRecord,
    FailureStage,
    RetrySafety,
    safe_error_message,
)
from redcell.finding_identity import attack_path_signature
from redcell.llm.openai_compatible import ProviderRateLimitedError, ProviderTransientError
from redcell.protocols.adapter import AdapterInput, Message, ResetScope, TargetAdapter
from redcell.protocols.common import RedCellModel, Role
from redcell.protocols.finding import Finding
from redcell.protocols.run import ProviderRunConfiguration
from redcell.protocols.trace import Attempt, CostRecord, Turn
from redcell.replay_checkpoint import ReplayPersistenceError, replay_lock, save_replay_json
from redcell.retry import RETRY_AFTER_KEY, RetryPolicy
from redcell.scoring.level1 import Level1Scorer


class ReplayValidation(RedCellModel):
    run_id: str
    attack_path: str
    runs: int = Field(ge=1)
    reproduced: int = Field(ge=0)

    @model_validator(mode="after")
    def _valid_count(self) -> ReplayValidation:
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
    target_configuration: ProviderRunConfiguration | None = None
    gate_context_fingerprint: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    run_ids: list[str] = Field(default_factory=list)
    replay_failures: list[FailureRecord] = Field(default_factory=list)

    @model_validator(mode="after")
    def _binding_is_complete_and_unique(self) -> ValidationReport:
        bound = (
            self.target_configuration is not None,
            self.gate_context_fingerprint is not None,
            bool(self.run_ids),
        )
        if any(bound) and not all(bound):
            raise ValueError("validation binding requires target, Gate context, and run_ids")
        if len(set(self.run_ids)) != len(self.run_ids):
            raise ValueError("validation run_ids must be unique")
        return self


class ReplayCheckpoint(RedCellModel):
    version: int = Field(default=1, ge=1, le=1)
    input_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    completed: list[ReplayValidation] = Field(default_factory=list)
    target_usage: CostRecord = Field(default_factory=CostRecord)
    failures: list[FailureRecord] = Field(default_factory=list)
    active_failures: int = Field(default=0, ge=0)
    in_progress: bool = False
    request_pending: bool = False


class ReplayStoppedError(RuntimeError):
    """The checkpoint is retained, but automatic retries are unsafe or exhausted."""


async def validate_attack_paths(
    *,
    adapter: TargetAdapter,
    scorer: Level1Scorer,
    attempts: list[Attempt],
    findings: list[Finding],
    repeats: int = 5,
    target_configuration: ProviderRunConfiguration | None = None,
    gate_context_fingerprint: str | None = None,
    run_ids: list[str] | None = None,
    checkpoint_path: Path | None = None,
    retry_policy: RetryPolicy | None = None,
    on_progress: Callable[[int, int], None] | None = None,
) -> ValidationReport:
    if repeats < 1:
        raise ValueError("repeats must be at least 1")
    # Reject incomplete bindings before any paid calls rather than at report construction.
    report = ValidationReport(
        repeats=repeats,
        target_configuration=target_configuration,
        gate_context_fingerprint=gate_context_fingerprint,
        run_ids=sorted(run_ids or []),
    )
    findings_by_attempt: dict[str, list[Finding]] = defaultdict(list)
    for finding in findings:
        findings_by_attempt[finding.attempt_id].append(finding)
    representatives: dict[tuple[str, str], Attempt] = {}
    for attempt in attempts:
        for finding in findings_by_attempt[attempt.id]:
            path = attack_path_signature(finding)
            representatives.setdefault((attempt.run_id, path), attempt)
    plan = [
        (key, attempt) for key, attempt in sorted(representatives.items()) for _ in range(repeats)
    ]
    policy = retry_policy or RetryPolicy()
    payload = {
        "version": 1,
        "binding": report.model_dump(mode="json"),
        "attempts": [a.model_dump(mode="json") for a in attempts],
        "findings": [f.model_dump(mode="json") for f in findings],
        "retry_policy": policy.model_dump(mode="json"),
        "adapter_type": adapter.adapter_type if adapter is not None else None,
        "capabilities": (
            adapter.capabilities.model_dump(mode="json") if adapter is not None else None
        ),
    }
    digest = hashlib.sha256(json.dumps(payload, sort_keys=True).encode("utf-8")).hexdigest()
    with replay_lock(checkpoint_path):
        state = ReplayCheckpoint(input_digest=digest)
        if checkpoint_path is not None and checkpoint_path.exists():
            state = ReplayCheckpoint.model_validate_json(
                checkpoint_path.read_text(encoding="utf-8")
            )
            if state.input_digest != digest:
                raise ValueError(
                    "Replay checkpoint does not match the frozen inputs or retry policy"
                )
        if len(state.completed) > len(plan):
            raise ValueError("Replay checkpoint has too many completed trials")
        for index, result in enumerate(state.completed):
            if (result.run_id, result.attack_path) != plan[index][0] or result.runs != 1:
                raise ValueError("Replay checkpoint is not a completed prefix of this replay plan")
        if state.active_failures > len(state.failures):
            raise ValueError("Replay checkpoint has an inconsistent failure count")
        if state.request_pending and not state.in_progress:
            raise ValueError("Replay checkpoint has a pending request outside a trial")
        if len(state.completed) == len(plan) and (state.in_progress or state.active_failures):
            raise ValueError("Replay checkpoint has active work after its final trial")

        def persist() -> None:
            save_replay_json(checkpoint_path, state)

        def record_failure(exc: Exception, *, interrupted: bool = False) -> None:
            transient = isinstance(exc, ProviderTransientError) or interrupted
            rate_limited = isinstance(exc, ProviderRateLimitedError)
            quota_exhausted = rate_limited and exc.daily_quota_exhausted
            can_reset = adapter.capabilities.reset_scope is ResetScope.FULL_STATE
            kind = FailureKind.RATE_LIMITED if rate_limited else FailureKind.NETWORK_TRANSIENT
            if not transient or quota_exhausted:
                kind = FailureKind.INTERNAL
            # An adapter turn may have made several successful HTTP calls before failing.
            # Even a final 429 does not establish zero usage for that whole turn.
            unknown = state.request_pending
            if unknown:
                state.target_usage = _sum_costs(state.target_usage, CostRecord(usage_known=False))
            state.failures.append(
                FailureRecord(
                    kind=kind,
                    stage=FailureStage.TARGET_SEND if unknown else FailureStage.ORCHESTRATION,
                    code="interrupted_replay" if interrupted else type(exc).__name__,
                    message=safe_error_message(exc),
                    cause_type=type(exc).__name__,
                    retry_safety=(
                        RetrySafety.REQUIRES_RESET
                        if transient and can_reset and not quota_exhausted
                        else RetrySafety.UNSAFE
                    ),
                    usage=CostRecord(usage_known=not unknown),
                    details={
                        "trial_index": len(state.completed),
                        "run_id": plan[len(state.completed)][0][0],
                        "attack_path": plan[len(state.completed)][0][1],
                        "retry_number": state.active_failures + 1,
                        RETRY_AFTER_KEY: getattr(exc, "retry_after_seconds", None),
                    },
                )
            )
            state.active_failures += 1
            state.request_pending = False
            state.in_progress = False
            persist()

        # A process crash cannot prove whether its last request was billed. Keep the
        # known subtotal, mark the gap, and charge recovery against the same retry cap.
        if state.in_progress:
            record_failure(
                RuntimeError("Previous replay process stopped during a trial"), interrupted=True
            )
        persist()
        if on_progress is not None:
            on_progress(len(state.completed), len(plan))
        rng = random.Random(0)
        while len(state.completed) < len(plan):
            if state.active_failures:
                failure = state.failures[-1]
                if not failure.retryable or state.active_failures > policy.max_retries_for(failure):
                    raise ReplayStoppedError(
                        f"Replay stopped at trial {len(state.completed) + 1}/{len(plan)}: "
                        f"{failure.code}; automatic retries are unsafe or exhausted. "
                        "Completed trials and failure accounting remain in the checkpoint."
                    )
                await asyncio.sleep(policy.delay_seconds(failure, state.active_failures, rng=rng))
            (run_id, path), attempt = plan[len(state.completed)]
            state.in_progress = True
            persist()

            def before_send() -> None:
                state.request_pending = True
                persist()

            def after_send(usage: CostRecord) -> None:
                state.target_usage = _sum_costs(state.target_usage, usage)
                state.request_pending = False
                persist()

            try:
                replay_findings, _ = await _replay(
                    adapter, scorer, attempt, before_send=before_send, after_send=after_send
                )
            except ReplayPersistenceError:
                raise
            except Exception as exc:
                # Persistence boundary: retain fatal failures too, but never retry them.
                # Cancellation/KeyboardInterrupt leave the durable in-progress marker.
                record_failure(exc)
                if not isinstance(exc, ProviderTransientError):
                    raise
                continue
            reproduced = path in {attack_path_signature(f) for f in replay_findings}
            state.completed.append(
                ReplayValidation(
                    run_id=run_id, attack_path=path, runs=1, reproduced=int(reproduced)
                )
            )
            state.in_progress = False
            state.active_failures = 0
            persist()
            if on_progress is not None:
                on_progress(len(state.completed), len(plan))
        results: dict[tuple[str, str], ReplayValidation] = {}
        for item in state.completed:
            key = (item.run_id, item.attack_path)
            if key not in results:
                results[key] = item.model_copy(deep=True)
            else:
                results[key].runs += 1
                results[key].reproduced += item.reproduced
        report.results = list(results.values())
        report.target_usage = state.target_usage
        report.replay_failures = state.failures
        return report


async def _replay(
    adapter: TargetAdapter,
    scorer: Level1Scorer,
    attempt: Attempt,
    *,
    before_send: Callable[[], None] | None = None,
    after_send: Callable[[CostRecord], None] | None = None,
) -> tuple[list[Finding], CostRecord]:
    await adapter.reset()
    conversation: list[Message] = []
    turns: list[Turn] = []
    total_usage = CostRecord()
    for source_turn in attempt.turns:
        conversation.append(Message(role=Role.USER, content=source_turn.attacker_message))
        if before_send is not None:
            before_send()
        output = await adapter.send(AdapterInput(messages=list(conversation), actor=attempt.actor))
        metadata = output.trace_metadata
        usage = CostRecord(
            prompt_tokens=metadata.prompt_tokens,
            completion_tokens=metadata.completion_tokens,
            cached_input_tokens=metadata.cached_input_tokens,
            usage_known=metadata.usage_known,
            usd=metadata.cost_usd,
            wall_ms=metadata.latency_ms,
        )
        if after_send is not None:
            after_send(usage)
        total_usage = _sum_costs(total_usage, usage)
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
    return findings, total_usage


def _sum_costs(left: CostRecord, right: CostRecord) -> CostRecord:
    return CostRecord(
        prompt_tokens=left.prompt_tokens + right.prompt_tokens,
        completion_tokens=left.completion_tokens + right.completion_tokens,
        cached_input_tokens=left.cached_input_tokens + right.cached_input_tokens,
        usage_known=left.usage_known and right.usage_known,
        usd=left.usd + right.usd,
        wall_ms=left.wall_ms + right.wall_ms,
    )
