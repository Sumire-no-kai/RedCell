"""持续攻击者可以看到的、确定性投影后的运行证据。

旧 Phase 0.5d 的 ``history.py`` 是冻结实验实现，不能通过修补渲染逻辑改变其
历史条件。本模块定义新的版本化 seam：调用方只得到目标真实产生且威胁模型允许
暴露的观察，不会碰到 Policy、Finding、Signal、reward 或私有工具结果正文。
"""

from __future__ import annotations

import hashlib
import json
from enum import StrEnum
from typing import Any

from pydantic import Field, model_validator

from redcell.protocols.adapter import ToolResult
from redcell.protocols.common import ObservabilityLevel, RedCellModel
from redcell.protocols.trace import Attempt, Turn

ATTACKER_OBSERVATION_POLICY_V1 = "attacker-observation-v1"


class ObservationProjectionError(ValueError):
    """Trace 自相矛盾，不能安全投影成攻击者证据。"""


class ObservedToolOutcome(StrEnum):
    """工具调用对攻击者可见的四种不同结果。"""

    PERFORMED = "performed"
    AWAITING_CONFIRMATION = "awaiting_confirmation"
    REJECTED = "rejected"
    UNKNOWN = "unknown"


class ObservedToolAction(RedCellModel):
    ref: str
    name: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    outcome: ObservedToolOutcome
    side_effect_kinds: list[str] = Field(default_factory=list)


class AttackerTurnObservation(RedCellModel):
    ref: str
    turn_index: int = Field(ge=0)
    observability: ObservabilityLevel
    attacker_message: str
    target_message: str
    malformed_tool_calls: int = Field(ge=0)
    tool_actions: list[ObservedToolAction] = Field(default_factory=list)
    unbound_side_effect_kinds: list[str] = Field(default_factory=list)


class ActiveAttemptTrace(RedCellModel):
    """尚未形成完整 Attempt 时，投影当前会话所需的最小公开源数据。"""

    id: str
    run_id: str
    attempt_index: int = Field(ge=0)
    strategy_id: str
    turns: list[Turn] = Field(default_factory=list)


class AttackerAttemptObservation(RedCellModel):
    ref: str
    attempt_index: int = Field(ge=0)
    strategy_id: str
    active: bool
    turns: list[AttackerTurnObservation] = Field(default_factory=list)


def _observation_digest(
    policy_version: str,
    run_id: str | None,
    attempts: list[AttackerAttemptObservation],
) -> str:
    payload = {
        "policy_version": policy_version,
        "run_id": run_id,
        "attempts": [item.model_dump(mode="json") for item in attempts],
    }
    return hashlib.sha256(
        json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


class AttackerObservationLedger(RedCellModel):
    """一次 Run 内可交给持续攻击者的观察账本。"""

    policy_version: str = ATTACKER_OBSERVATION_POLICY_V1
    run_id: str | None = Field(default=None, min_length=1)
    attempts: list[AttackerAttemptObservation] = Field(default_factory=list)
    digest: str

    @model_validator(mode="after")
    def _identity_matches_contents(self) -> AttackerObservationLedger:
        if self.policy_version != ATTACKER_OBSERVATION_POLICY_V1:
            raise ValueError("攻击者观察账本使用了未知投影版本")
        if bool(self.attempts) != bool(self.run_id):
            raise ValueError("非空攻击者观察账本必须绑定且只能绑定一个 Run")
        if self.digest != _observation_digest(
            self.policy_version,
            self.run_id,
            self.attempts,
        ):
            raise ValueError("攻击者观察账本 digest 与内容不一致")
        return self

    @property
    def evidence_refs(self) -> set[str]:
        refs: set[str] = set()
        for attempt in self.attempts:
            refs.add(attempt.ref)
            for turn in attempt.turns:
                refs.add(turn.ref)
                refs.update(action.ref for action in turn.tool_actions)
        return refs


def project_attacker_observations(
    attempts: list[Attempt],
    *,
    active_attempt: ActiveAttemptTrace | None = None,
) -> AttackerObservationLedger:
    """投影已提交历史及可选的进行中会话，并为内容生成稳定摘要。"""

    run_ids = {attempt.run_id for attempt in attempts}
    if active_attempt is not None:
        run_ids.add(active_attempt.run_id)
    if len(run_ids) > 1:
        raise ObservationProjectionError("攻击者观察账本不得跨 Run 混合历史")
    attempt_ids = [attempt.id for attempt in attempts]
    if active_attempt is not None:
        attempt_ids.append(active_attempt.id)
    if len(attempt_ids) != len(set(attempt_ids)):
        raise ObservationProjectionError("攻击者观察账本包含重复 Attempt")
    attempt_indexes = [attempt.attempt_index for attempt in attempts]
    if active_attempt is not None:
        attempt_indexes.append(active_attempt.attempt_index)
    if any(index is None for index in attempt_indexes):
        raise ObservationProjectionError("持续攻击者只能读取带权威 attempt_index 的新记录")
    if attempt_indexes != sorted(set(attempt_indexes)):
        raise ObservationProjectionError("攻击者观察账本的 Attempt 序号必须严格递增")
    if any(attempt.stop_reason is None for attempt in attempts):
        raise ObservationProjectionError("已提交历史不得包含尚未结束的 Attempt")

    projected = [
        _project_attempt(
            attempt_id=attempt.id,
            attempt_index=attempt.attempt_index,
            strategy_id=attempt.strategy_id,
            turns=attempt.turns,
            active=False,
        )
        for attempt in attempts
    ]
    if active_attempt is not None:
        projected.append(
            _project_attempt(
                attempt_id=active_attempt.id,
                attempt_index=active_attempt.attempt_index,
                strategy_id=active_attempt.strategy_id,
                turns=active_attempt.turns,
                active=True,
            )
        )
    run_id = next(iter(run_ids), None)
    digest = _observation_digest(ATTACKER_OBSERVATION_POLICY_V1, run_id, projected)
    return AttackerObservationLedger(run_id=run_id, attempts=projected, digest=digest)


def _project_attempt(
    *,
    attempt_id: str,
    attempt_index: int | None,
    strategy_id: str,
    turns: list[Turn],
    active: bool,
) -> AttackerAttemptObservation:
    if attempt_index is None:  # guarded by project_attacker_observations
        raise ObservationProjectionError("Attempt 缺少权威 attempt_index")
    attempt_ref = f"attempt:{attempt_id}"
    turn_indexes = [turn.index for turn in turns]
    if turn_indexes != list(range(len(turn_indexes))):
        raise ObservationProjectionError(f"Attempt {attempt_id} 的 Turn 序号不连续")
    return AttackerAttemptObservation(
        ref=attempt_ref,
        attempt_index=attempt_index,
        strategy_id=strategy_id,
        active=active,
        turns=[_project_turn(attempt_ref, turn) for turn in turns],
    )


def _project_turn(attempt_ref: str, turn: Turn) -> AttackerTurnObservation:
    turn_ref = f"{attempt_ref}/turn:{turn.index}"
    results_by_call: dict[str, ToolResult] = {}
    call_id_list = [call.id for call in turn.output.tool_calls]
    if len(call_id_list) != len(set(call_id_list)):
        raise ObservationProjectionError(f"{turn_ref} 包含重复工具调用 ID")
    call_ids = set(call_id_list)

    for result in turn.output.tool_results:
        if result.tool_call_id not in call_ids:
            raise ObservationProjectionError(
                f"工具结果 {result.tool_call_id} 没有对应的可观察工具调用"
            )
        if result.tool_call_id in results_by_call:
            raise ObservationProjectionError(f"工具调用 {result.tool_call_id} 有重复结果")
        results_by_call[result.tool_call_id] = result

    effects_by_call: dict[str, list[str]] = {}
    unbound_effects: list[str] = []
    for effect in turn.output.side_effects:
        if effect.tool_call_id is None:
            unbound_effects.append(effect.kind)
            continue
        if effect.tool_call_id not in call_ids:
            raise ObservationProjectionError(
                f"副作用 {effect.kind} 指向未知工具调用 {effect.tool_call_id}"
            )
        effects_by_call.setdefault(effect.tool_call_id, []).append(effect.kind)

    actions: list[ObservedToolAction] = []
    visible_calls = (
        turn.output.tool_calls if turn.output.observability.can_observe_tool_calls else []
    )
    for call in visible_calls:
        result = results_by_call.get(call.id)
        effect_kinds = effects_by_call.get(call.id, [])
        outcome = _tool_outcome(result)
        if effect_kinds and outcome is not ObservedToolOutcome.PERFORMED:
            raise ObservationProjectionError(
                f"工具调用 {call.id} 标记为 {outcome.value}，却记录了真实副作用"
            )
        if result is not None and result.name != call.name:
            raise ObservationProjectionError(f"工具调用 {call.id} 的调用名与结果名不一致")
        if not turn.output.observability.can_observe_side_effects:
            outcome = ObservedToolOutcome.UNKNOWN
            effect_kinds = []
        actions.append(
            ObservedToolAction(
                ref=f"{turn_ref}/tool:{call.id}",
                name=call.name,
                arguments=call.arguments,
                outcome=outcome,
                side_effect_kinds=effect_kinds,
            )
        )

    return AttackerTurnObservation(
        ref=turn_ref,
        turn_index=turn.index,
        observability=turn.output.observability,
        attacker_message=turn.attacker_message,
        target_message=turn.output.assistant_message,
        malformed_tool_calls=(
            turn.output.malformed_tool_calls
            if turn.output.observability.can_observe_tool_calls
            else 0
        ),
        tool_actions=actions,
        unbound_side_effect_kinds=(
            unbound_effects if turn.output.observability.can_observe_side_effects else []
        ),
    )


def _tool_outcome(result: ToolResult | None) -> ObservedToolOutcome:
    if result is None:
        return ObservedToolOutcome.UNKNOWN
    if result.awaiting_confirmation:
        if result.error is not None:
            raise ObservationProjectionError("工具结果不能同时等待确认和被拒绝")
        return ObservedToolOutcome.AWAITING_CONFIRMATION
    if result.rejected:
        return ObservedToolOutcome.REJECTED
    return ObservedToolOutcome.PERFORMED
