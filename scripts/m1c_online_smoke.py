"""One bounded, real Target + Attacker development probe for M1-C.

This intentionally does not create a formal Run or relax its billed-usage preflight.
Raw observations stay in an ignored JSONL file under runs/.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import math
import os
import subprocess
import time
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from redcell._base import CostRecord
from redcell.arena.support_agent import SUPPORT_AGENT_ARENA
from redcell.arena.support_agent.adapter import ArenaAdapter
from redcell.arena.support_agent.codec import ToolCallProtocol
from redcell.arena.support_agent.prompts import DefenseLevel
from redcell.attacker_observation import (
    ATTACKER_OBSERVATION_POLICY_V2,
    ActiveAttemptTrace,
    AttackerVisibility,
    project_attacker_observations,
)
from redcell.budget import BudgetLimit, CallBudgetExhaustedError
from redcell.config import AttackerSettings, TargetSettings, role_settings
from redcell.controls import controls_conditions
from redcell.failures import StructuredExecutionError, safe_error_message
from redcell.feedback_attacker import (
    FEEDBACK_ATTACKER_PROMPT_V2,
    FEEDBACK_ATTACKER_SCHEMA_V2,
    ActiveAttemptView,
    AttackerStrategyView,
    AttackerWorkingState,
    FeedbackActionKind,
    FeedbackAttackDecisionError,
    FeedbackAttackDriver,
    FeedbackAttackRequest,
    FeedbackAttackSelection,
    FeedbackBudgetView,
    LLMFeedbackAttackAdapter,
    feedback_strategy_digest,
)
from redcell.llm.base import LLMMessage, LLMProvider, LLMResponse, LLMToolDefinition
from redcell.protocols.adapter import AdapterInput, Message, TargetAdapter
from redcell.protocols.common import Role
from redcell.protocols.strategy import Strategy, select_applicable
from redcell.protocols.trace import Turn
from redcell.strategies import PHASE_0_STRATEGIES

PROBE_VERSION = "m1c-online-smoke-v1"
REPO_ROOT = Path(__file__).resolve().parents[1]
BASELINE_PATH = REPO_ROOT / "docs/PHASE0_5E_UTILITY_BASELINE.json"
BASELINE_SHA256 = "413324badea8d775e37957ddbad4a0691c214933653316c37022b7c7119661c6"
BASELINE_CONTEXT = "c204b86f311dbdd5cbdf53103a4c7b40f10707f653310b72374ce3b9d98ddfcb"
MAX_DECISIONS = 3
MAX_TURNS = 2
ACTOR = "customer_a"
VISIBILITY = AttackerVisibility.SUPPORT_AGENT_DIAGNOSTICS


class EvidenceJournal:
    """Create-only and fsync each event before another paid call can begin."""

    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        self._file = os.fdopen(descriptor, "w", encoding="utf-8")

    def write(self, event: str, **payload: object) -> None:
        record = {"at": datetime.now(UTC).isoformat(), "event": event, **payload}
        self._file.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")
        self._file.flush()
        os.fsync(self._file.fileno())

    def close(self) -> None:
        self._file.close()


class UsageIndeterminateError(ValueError):
    """A model call may have been billed but cannot be counted reliably."""


class AuditedProvider(LLMProvider):
    """Persist each request and response; stop before a call after model drift."""

    def __init__(
        self, provider: LLMProvider, *, role: str, expected_model: str, max_requests: int
    ) -> None:
        self._provider = provider
        self.role = role
        self.expected_model = expected_model
        self.max_requests = max_requests
        self.requests = 0
        self.model_drifted = False
        self.usage_indeterminate = False
        self.last_cost: CostRecord | None = None
        self.journal: EvidenceJournal | None = None

    @property
    def name(self) -> str:
        return self._provider.name

    @property
    def reports_cost(self) -> bool:
        return self._provider.reports_cost

    @property
    def usage_covers_billed_tokens(self) -> bool:
        return self._provider.usage_covers_billed_tokens

    async def complete(
        self,
        messages: list[LLMMessage],
        *,
        model: str | None = None,
        temperature: float = 0.0,
        max_tokens: int | None = None,
        tools: list[LLMToolDefinition] | None = None,
        tool_choice: str | None = None,
    ) -> LLMResponse:
        journal = self.journal
        if journal is None:
            raise RuntimeError("Provider audit must be bound before any model call")
        if self.model_drifted or self.usage_indeterminate or self.requests >= self.max_requests:
            raise RuntimeError("Provider audit stopped another model call")
        index = self.requests
        self.requests += 1
        journal.write(
            "provider_requested",
            role=self.role,
            request_index=index,
            messages=[message.model_dump(mode="json") for message in messages],
            model=model,
            temperature=temperature,
            max_tokens=max_tokens,
            tools=[tool.model_dump(mode="json") for tool in tools] if tools else None,
            tool_choice=tool_choice,
        )
        try:
            response = await self._provider.complete(
                messages,
                model=model,
                temperature=temperature,
                max_tokens=max_tokens,
                tools=tools,
                tool_choice=tool_choice,
            )
        except Exception as exc:
            self.usage_indeterminate = True
            journal.write(
                "provider_failed",
                role=self.role,
                request_index=index,
                error_type=type(exc).__name__,
                message=safe_error_message(exc),
                usage_indeterminate=True,
            )
            raise
        self.model_drifted = response.model != self.expected_model
        self.usage_indeterminate = not response.usage_known
        self.last_cost = CostRecord(
            prompt_tokens=response.prompt_tokens,
            completion_tokens=response.completion_tokens,
            cached_input_tokens=response.cached_input_tokens,
            usage_known=response.usage_known,
            usd=response.cost_usd,
            wall_ms=response.latency_ms,
        )
        journal.write(
            "provider_responded",
            role=self.role,
            request_index=index,
            response=response.model_dump(mode="json", exclude={"raw"}),
            requested_model=self.expected_model,
            model_drifted=self.model_drifted,
            usage_indeterminate=self.usage_indeterminate,
        )
        return response


def _valid_cost(cost: CostRecord) -> bool:
    return (
        cost.prompt_tokens >= 0
        and cost.completion_tokens >= 0
        and 0 <= cost.cached_input_tokens <= cost.prompt_tokens
        and math.isfinite(cost.usd)
        and cost.usd >= 0
        and math.isfinite(cost.wall_ms)
        and cost.wall_ms >= 0
    )


def _add_cost(left: CostRecord, right: CostRecord) -> CostRecord:
    return CostRecord(
        prompt_tokens=left.prompt_tokens + right.prompt_tokens,
        completion_tokens=left.completion_tokens + right.completion_tokens,
        cached_input_tokens=left.cached_input_tokens + right.cached_input_tokens,
        usage_known=left.usage_known and right.usage_known,
        usd=left.usd + right.usd,
        wall_ms=left.wall_ms + right.wall_ms,
    )


def _reported_target_cost(output) -> CostRecord:
    trace = output.trace_metadata
    return CostRecord(
        prompt_tokens=trace.prompt_tokens,
        completion_tokens=trace.completion_tokens,
        cached_input_tokens=trace.cached_input_tokens,
        usage_known=trace.usage_known,
        usd=trace.cost_usd,
        wall_ms=trace.latency_ms,
    )


def _matched_utility_context(target: TargetSettings) -> str:
    content = BASELINE_PATH.read_bytes()
    if hashlib.sha256(content).hexdigest() != BASELINE_SHA256:
        raise ValueError("Frozen utility baseline file digest changed")
    baseline = json.loads(content)
    if (
        baseline.get("version") != "utility-baseline-v2"
        or baseline.get("context_fingerprint") != BASELINE_CONTEXT
    ):
        raise ValueError("M1-C requires the frozen native-v2 utility baseline")
    fingerprint = controls_conditions(
        target=target.run_configuration(),
        tool_call_protocol_version=ToolCallProtocol.NATIVE_V2.value,
    ).utility_context_fingerprint()
    if fingerprint != BASELINE_CONTEXT:
        raise ValueError("Current Target/protocol differs from the frozen utility baseline")
    return fingerprint


def _public_settings(settings: TargetSettings | AttackerSettings) -> dict:
    snapshot = settings.run_configuration()
    return {
        "provider": snapshot.provider,
        "base_url_sha256": hashlib.sha256(snapshot.base_url.encode()).hexdigest(),
        "model": snapshot.model,
        "temperature": snapshot.temperature,
        "rpm": snapshot.rpm,
        "max_concurrency": snapshot.max_concurrency,
        "request_timeout_seconds": settings.request_timeout_seconds,
        "max_tokens": snapshot.max_tokens,
        "max_tokens_parameter": snapshot.max_tokens_parameter,
        "extra_body": snapshot.extra_body.model_dump(mode="json"),
        "usage_accounting_mode": snapshot.usage_accounting_mode.value,
        "usage_covers_billed_tokens": snapshot.usage_covers_billed_tokens,
        "input_usd_per_mtok": snapshot.input_usd_per_mtok,
        "output_usd_per_mtok": snapshot.output_usd_per_mtok,
        "cached_input_usd_per_mtok": snapshot.cached_input_usd_per_mtok,
    }


def _pricing_configured(settings: TargetSettings | AttackerSettings) -> bool:
    return all(
        rate is not None
        for rate in (
            settings.input_usd_per_mtok,
            settings.output_usd_per_mtok,
            settings.cached_input_usd_per_mtok,
        )
    )


def _source_identity() -> dict:
    head = subprocess.run(
        ["git", "-C", str(REPO_ROOT), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    status = subprocess.run(
        ["git", "-C", str(REPO_ROOT), "status", "--porcelain"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    return {
        "git_head": head,
        "working_tree_dirty": bool(status.strip()),
        "script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
    }


def _configuration_digest(
    target: TargetSettings,
    attacker: AttackerSettings,
    fingerprint: str,
    *,
    max_tokens: int,
    max_cost: float,
    max_seconds: float,
) -> str:
    payload = {
        "probe_version": PROBE_VERSION,
        "source": _source_identity(),
        "target": _public_settings(target),
        "attacker": _public_settings(attacker),
        "utility_context_fingerprint": fingerprint,
        "utility_baseline_sha256": BASELINE_SHA256,
        "arena_version": SUPPORT_AGENT_ARENA.version,
        "tool_schema_sha256": SUPPORT_AGENT_ARENA.tool_schema_sha256,
        "tool_call_protocol_version": ToolCallProtocol.NATIVE_V2.value,
        "actor": ACTOR,
        "visibility": VISIBILITY.value,
        "attacker_prompt_version": FEEDBACK_ATTACKER_PROMPT_V2,
        "attacker_schema_version": FEEDBACK_ATTACKER_SCHEMA_V2,
        "observation_policy_version": ATTACKER_OBSERVATION_POLICY_V2,
        "strategy_views_sha256": feedback_strategy_digest(
            select_applicable(list(PHASE_0_STRATEGIES), SUPPORT_AGENT_ARENA.policy)
        ),
        "budget": {
            "attempts": 1,
            "decisions": MAX_DECISIONS,
            "turns": MAX_TURNS,
            "tokens": max_tokens,
            "reported_cost": max_cost,
            "seconds_between_calls": max_seconds,
        },
    }
    encoded = json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode()).hexdigest()


async def run_smoke(
    *,
    driver: FeedbackAttackDriver,
    adapter: TargetAdapter,
    path: Path,
    target_settings: TargetSettings,
    attacker_settings: AttackerSettings,
    utility_fingerprint: str,
    max_total_tokens: int,
    max_cost_usd: float,
    max_seconds: float,
    approved_configuration_sha256: str | None = None,
    audited_providers: tuple[AuditedProvider, ...] = (),
    clock=time.monotonic,
) -> str:
    """Run one Attempt. A single in-flight call may cross a reported-usage bound."""
    if (
        max_total_tokens < 1
        or not math.isfinite(max_cost_usd)
        or max_cost_usd <= 0
        or not math.isfinite(max_seconds)
        or max_seconds <= 0
    ):
        raise ValueError("All token, cost, and wall limits must be positive")
    if adapter.tool_call_protocol_version != ToolCallProtocol.NATIVE_V2.value:
        raise ValueError("M1-C online smoke requires native function calling v2")
    if adapter.tool_schema_sha256 != SUPPORT_AGENT_ARENA.tool_schema_sha256:
        raise ValueError("Current Target tool schema differs from support-agent")
    if not adapter.capabilities.reports_cost:
        raise ValueError("Target must report estimated cost")
    if not _pricing_configured(target_settings) or not _pricing_configured(attacker_settings):
        raise ValueError("Both model roles need configured token pricing")

    run_id = f"{PROBE_VERSION}-{uuid4().hex}"
    attempt_id = f"{run_id}-attempt-0"
    policy = SUPPORT_AGENT_ARENA.policy
    strategies = select_applicable(list(PHASE_0_STRATEGIES), policy)
    strategy_by_id: dict[str, Strategy] = {strategy.id: strategy for strategy in strategies}
    if not strategies:
        raise ValueError("No applicable support-agent strategies")
    journal = EvidenceJournal(path)
    for audited in audited_providers:
        audited.journal = journal
    started = clock()
    total = CostRecord()
    working_state = AttackerWorkingState()
    active_strategy: Strategy | None = None
    turns: list[Turn] = []
    decisions = 0
    stop = "unstarted"

    def limit(local: CostRecord) -> BudgetLimit | None:
        if not _valid_cost(local) or not local.usage_known:
            raise ValueError("Unknown or invalid usage stops the probe")
        candidate = _add_cost(total, local)
        if candidate.total_tokens >= max_total_tokens:
            return BudgetLimit.TOKENS
        if candidate.usd >= max_cost_usd:
            return BudgetLimit.COST
        if clock() - started >= max_seconds:
            return BudgetLimit.WALL_CLOCK
        return None

    def guard(local: CostRecord) -> None:
        reached = limit(local)
        if reached is not None:
            raise CallBudgetExhaustedError(reached, local)

    def record(role: str, cost: CostRecord) -> None:
        nonlocal total
        journal.write("usage", role=role, cost=cost.model_dump(mode="json"))
        if not _valid_cost(cost):
            total = total.model_copy(update={"usage_known": False})
            raise UsageIndeterminateError(f"{role} usage unknown or invalid")
        total = _add_cost(total, cost)
        if not cost.usage_known:
            raise UsageIndeterminateError(f"{role} usage unknown or invalid")

    try:
        journal.write(
            "probe_started",
            probe_version=PROBE_VERSION,
            run_id=run_id,
            budget={
                "max_attempts": 1,
                "max_decision_steps": MAX_DECISIONS,
                "max_turns_per_attempt": MAX_TURNS,
                "max_total_tokens": max_total_tokens,
                "max_cost_usd_reported_estimate": max_cost_usd,
                "max_wall_seconds_between_calls": max_seconds,
            },
            target=_public_settings(target_settings),
            attacker=_public_settings(attacker_settings),
            arena_version=SUPPORT_AGENT_ARENA.version,
            actor=ACTOR,
            defense=DefenseLevel.STANDARD.value,
            enforce_permissions=True,
            enforce_confirmation=True,
            tool_call_protocol_version=adapter.tool_call_protocol_version,
            tool_schema_sha256=adapter.tool_schema_sha256,
            observation_visibility=VISIBILITY.value,
            observation_policy_version=ATTACKER_OBSERVATION_POLICY_V2,
            attacker_prompt_version=FEEDBACK_ATTACKER_PROMPT_V2,
            attacker_schema_version=FEEDBACK_ATTACKER_SCHEMA_V2,
            strategy_views_sha256=feedback_strategy_digest(strategies),
            utility_context_fingerprint=utility_fingerprint,
            utility_baseline_sha256=BASELINE_SHA256,
            approved_configuration_sha256=approved_configuration_sha256,
            source=_source_identity(),
            provider_request_caps={audit.role: audit.max_requests for audit in audited_providers},
            formal_run=False,
            billed_usage_coverage_proven=False,
        )
        while decisions < MAX_DECISIONS:
            reached = limit(CostRecord())
            if reached is not None:
                stop = reached.value
                break
            if active_strategy is not None and len(turns) >= MAX_TURNS:
                stop = "max_turns"
                break
            active_trace = (
                ActiveAttemptTrace(
                    id=attempt_id,
                    run_id=run_id,
                    attempt_index=0,
                    strategy_id=active_strategy.id,
                    turns=turns,
                )
                if active_strategy is not None
                else None
            )
            observations = project_attacker_observations(
                [], visibility=VISIBILITY, active_attempt=active_trace
            )
            request = FeedbackAttackRequest(
                run_id=run_id,
                target_brief=policy.brief_for(ACTOR),
                strategies=[
                    AttackerStrategyView(
                        id=strategy.id,
                        name=strategy.name,
                        description=strategy.description,
                    )
                    for strategy in strategies
                ],
                observations=observations,
                working_state=working_state,
                budget=FeedbackBudgetView(
                    total_token_limit=max_total_tokens,
                    used_tokens=total.total_tokens,
                    remaining_tokens=max(max_total_tokens - total.total_tokens, 0),
                    step_limit=MAX_DECISIONS,
                    steps_used=decisions,
                    remaining_steps=MAX_DECISIONS - decisions,
                ),
                active_attempt=(
                    ActiveAttemptView(
                        ref=f"attempt:{attempt_id}",
                        strategy_id=active_strategy.id,
                        turns_used=len(turns),
                        max_turns=MAX_TURNS,
                    )
                    if active_strategy is not None
                    else None
                ),
            )
            journal.write(
                "decision_requested",
                step=decisions,
                request=request.model_dump(mode="json"),
                request_digest=request.digest(),
            )
            decisions += 1
            try:
                selection = await driver.decide_with_budget(request, guard)
            except (FeedbackAttackDecisionError, CallBudgetExhaustedError) as exc:
                record("attacker", exc.cost)
                stop = (
                    exc.limit.value
                    if isinstance(exc, CallBudgetExhaustedError)
                    else "attacker_decision_failed"
                )
                journal.write("decision_failed", step=decisions - 1, reason=stop)
                break
            if not isinstance(selection, FeedbackAttackSelection):
                raise TypeError("Feedback driver returned no auditable selection")
            record("attacker", selection.cost)
            if (
                selection.request_digest != request.digest()
                or selection.prompt_version != FEEDBACK_ATTACKER_PROMPT_V2
                or selection.schema_version != FEEDBACK_ATTACKER_SCHEMA_V2
            ):
                raise ValueError("Feedback selection is not bound to the current request")
            action = selection.choice.action
            journal.write(
                "decision_selected",
                step=decisions - 1,
                selection=selection.model_dump(mode="json"),
            )
            if any(audit.model_drifted for audit in audited_providers):
                stop = "provider_model_drift"
                break
            working_state = selection.choice.working_state
            reached = limit(CostRecord())
            if reached is not None:
                stop = reached.value
                break
            if action.kind is FeedbackActionKind.STOP_RUN:
                stop = "driver_stop"
                break
            if action.kind is FeedbackActionKind.END_ATTEMPT:
                stop = "driver_end"
                break
            if action.kind is FeedbackActionKind.START_ATTEMPT:
                if active_strategy is not None or action.strategy_id not in strategy_by_id:
                    raise ValueError("Invalid attempt start")
                active_strategy = strategy_by_id[action.strategy_id]
                await adapter.reset()
            elif action.kind is not FeedbackActionKind.CONTINUE_ATTEMPT or active_strategy is None:
                raise ValueError("Invalid continuation")
            if len(turns) >= MAX_TURNS or action.message is None:
                raise ValueError("Target turn cap or message contract violated")
            conversation: list[Message] = []
            for turn in turns:
                conversation.extend(
                    [
                        Message(role=Role.USER, content=turn.attacker_message),
                        Message(role=Role.ASSISTANT, content=turn.output.assistant_message),
                    ]
                )
            conversation.append(Message(role=Role.USER, content=action.message))
            target_request = AdapterInput(
                messages=conversation,
                actor=ACTOR,
                request_id=f"{attempt_id}:turn:{len(turns)}",
                idempotency_key=f"{attempt_id}:turn:{len(turns)}",
                metadata={
                    "run_id": run_id,
                    "attempt_id": attempt_id,
                    "attempt_index": 0,
                    "strategy_id": active_strategy.id,
                    "turn_index": len(turns),
                },
            )
            journal.write(
                "target_requested",
                turn_index=len(turns),
                request=target_request.model_dump(mode="json"),
            )
            try:
                output = await adapter.send_with_budget(target_request, guard)
            except CallBudgetExhaustedError as exc:
                record("target", exc.cost)
                stop = exc.limit.value
                journal.write("target_blocked", reason=stop)
                break
            except StructuredExecutionError as exc:
                journal.write("target_failed", failure=exc.failure.model_dump(mode="json"))
                drifted_target = next(
                    (
                        audit
                        for audit in audited_providers
                        if audit.role == "target" and audit.model_drifted
                    ),
                    None,
                )
                if (
                    drifted_target is not None
                    and drifted_target.last_cost is not None
                    and not drifted_target.usage_indeterminate
                ):
                    # ArenaAdapter includes every completed subcall in failure.usage. Its
                    # final unknown flag comes from our guard rejecting the next call
                    # before it reaches the Provider, so no additional usage is possible.
                    known_prior = exc.failure.usage.model_copy(update={"usage_known": True})
                    record("target", known_prior)
                    stop = "provider_model_drift"
                    break
                record("target", exc.failure.usage)
                stop = "target_failed"
                break
            target_cost = _reported_target_cost(output)
            journal.write(
                "target_returned",
                turn_index=len(turns),
                output=output.model_dump(mode="json"),
                usage_known=target_cost.usage_known,
            )
            record("target", target_cost)
            turns.append(
                Turn(
                    index=len(turns),
                    attacker_message=action.message,
                    output=output,
                    attacker_cost=selection.cost,
                )
            )
            journal.write("turn_completed", turn=turns[-1].model_dump(mode="json"))
            if any(audit.model_drifted for audit in audited_providers):
                stop = "provider_model_drift"
                break
            reached = limit(CostRecord())
            if reached is not None:
                stop = reached.value
                break
            if len(turns) >= MAX_TURNS:
                stop = "max_turns"
                break
        else:
            stop = "max_decision_steps"
    except UsageIndeterminateError as exc:
        stop = (
            "provider_model_drift"
            if any(audit.model_drifted for audit in audited_providers)
            else "usage_indeterminate"
        )
        journal.write("probe_error", error_type=type(exc).__name__, message=str(exc))
    except Exception as exc:
        stop = "probe_failed"
        journal.write(
            "probe_error",
            error_type=type(exc).__name__,
            message=safe_error_message(exc),
        )
    finally:
        journal.write(
            "probe_stopped",
            reason=stop,
            decisions=decisions,
            turns=len(turns),
            usage=total.model_dump(mode="json"),
            provider_requests={audit.role: audit.requests for audit in audited_providers},
            elapsed_seconds=clock() - started,
            estimated_cost_only=True,
        )
        journal.close()
        for audited in audited_providers:
            audited.journal = None
    return stop


def _ignored_output_path(path: Path) -> Path:
    runs_path = REPO_ROOT / "runs"
    if runs_path.is_symlink():
        raise ValueError("The ignored runs/ directory must not be a symlink")
    runs = runs_path.resolve()
    resolved = path.resolve()
    if resolved.parent != runs or resolved.suffix != ".jsonl":
        raise ValueError("--out must be a new .jsonl file directly under ignored runs/")
    return resolved


async def _online(
    *,
    path: Path,
    target_settings: TargetSettings,
    attacker_settings: AttackerSettings,
    fingerprint: str,
    max_tokens: int,
    max_cost: float,
    max_seconds: float,
    approved_configuration_sha256: str,
) -> str:
    target_provider = target_settings.build(name="target")
    attacker_provider = None
    try:
        attacker_provider = attacker_settings.build(name="attacker")
        audited_target = AuditedProvider(
            target_provider, role="target", expected_model=target_settings.model, max_requests=10
        )
        audited_attacker = AuditedProvider(
            attacker_provider,
            role="attacker",
            expected_model=attacker_settings.model,
            max_requests=6,
        )
        adapter = ArenaAdapter(
            audited_target,
            arena=SUPPORT_AGENT_ARENA,
            defense=DefenseLevel.STANDARD,
            enforce_permissions=True,
            enforce_confirmation=True,
            tool_call_protocol=ToolCallProtocol.NATIVE_V2,
            max_tool_iterations=5,
            model=target_settings.model,
            temperature=target_settings.temperature,
            max_tokens=target_settings.max_tokens,
        )
        driver = LLMFeedbackAttackAdapter(
            provider=audited_attacker,
            model=attacker_settings.model,
            temperature=attacker_settings.temperature,
            max_tokens=attacker_settings.max_tokens,
        )
        return await run_smoke(
            driver=driver,
            adapter=adapter,
            path=path,
            target_settings=target_settings,
            attacker_settings=attacker_settings,
            utility_fingerprint=fingerprint,
            max_total_tokens=max_tokens,
            max_cost_usd=max_cost,
            max_seconds=max_seconds,
            approved_configuration_sha256=approved_configuration_sha256,
            audited_providers=(audited_target, audited_attacker),
        )
    finally:
        try:
            await target_provider.aclose()
        finally:
            if attacker_provider is not None:
                await attacker_provider.aclose()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--online", action="store_true", help="Enable paid model calls")
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--budget", type=int, required=True, help="Must be exactly one Attempt")
    parser.add_argument("--max-tokens", type=int, required=True)
    parser.add_argument("--max-cost", type=float, required=True)
    parser.add_argument("--max-seconds", type=float, required=True)
    parser.add_argument("--expected-config-sha256")
    arguments = parser.parse_args()
    if arguments.budget != 1:
        parser.error("M1-C online smoke allows exactly --budget 1")
    if (
        arguments.max_tokens < 1
        or not math.isfinite(arguments.max_cost)
        or arguments.max_cost <= 0
        or not math.isfinite(arguments.max_seconds)
        or arguments.max_seconds <= 0
    ):
        parser.error("Token, cost and wall bounds must be positive")
    path = _ignored_output_path(arguments.out)
    target_settings = role_settings(TargetSettings)
    attacker_settings = role_settings(AttackerSettings)
    fingerprint = _matched_utility_context(target_settings)
    configuration_sha256 = _configuration_digest(
        target_settings,
        attacker_settings,
        fingerprint,
        max_tokens=arguments.max_tokens,
        max_cost=arguments.max_cost,
        max_seconds=arguments.max_seconds,
    )
    if not target_settings.is_configured() or not attacker_settings.is_configured():
        parser.error("Both configured model roles are required")
    if not _pricing_configured(target_settings) or not _pricing_configured(attacker_settings):
        parser.error("Both model roles need configured token pricing")
    if path.exists():
        parser.error("Evidence file already exists; choose a new path")
    if arguments.online and arguments.expected_config_sha256 != configuration_sha256:
        parser.error("Online execution needs the exact digest from a matching dry-run")
    if arguments.online and _source_identity()["working_tree_dirty"]:
        parser.error("Commit repository changes before a frozen online probe")
    if not arguments.online:
        print(
            json.dumps(
                {
                    "mode": "dry-run",
                    "target": _public_settings(target_settings),
                    "attacker": _public_settings(attacker_settings),
                    "budget": 1,
                    "max_decisions": MAX_DECISIONS,
                    "max_turns": MAX_TURNS,
                    "max_tokens": arguments.max_tokens,
                    "max_cost_reported_estimate": arguments.max_cost,
                    "max_seconds_between_calls": arguments.max_seconds,
                    "utility_context_fingerprint": fingerprint,
                    "utility_baseline_sha256": BASELINE_SHA256,
                    "configuration_sha256": configuration_sha256,
                    "out": str(path),
                },
                sort_keys=True,
            )
        )
        return
    stop = asyncio.run(
        _online(
            path=path,
            target_settings=target_settings,
            attacker_settings=attacker_settings,
            fingerprint=fingerprint,
            max_tokens=arguments.max_tokens,
            max_cost=arguments.max_cost,
            max_seconds=arguments.max_seconds,
            approved_configuration_sha256=configuration_sha256,
        )
    )
    print(json.dumps({"stop_reason": stop, "evidence": str(path)}, sort_keys=True))
    if stop in {
        "attacker_decision_failed",
        "target_failed",
        "usage_indeterminate",
        "provider_model_drift",
        "probe_failed",
    }:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
