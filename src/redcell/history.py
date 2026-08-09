"""Phase 0.5 的确定性、受限历史投影。

这里是原始 Attempt/Trace 到 LLM 可见上下文的唯一 seam。它不接受 Policy、Finding 或
Scorer；所有选择、排序、聚合、裁剪和 digest 都由代码决定，不能用 LLM summary 偷渡。
"""

from __future__ import annotations

import hashlib
from collections import defaultdict

from redcell.generation import GenerationMemory
from redcell.protocols.run import GenerationMemoryLimits
from redcell.protocols.trace import Attempt


def build_generation_memory(
    attempts: list[Attempt],
    *,
    current_strategy_id: str,
    policy_version: str = "bounded-relevant-v1",
    limits: GenerationMemoryLimits | None = None,
) -> GenerationMemory:
    """生成 Generator 专用 bounded-relevant-v1 memory。

    选择规则冻结为：最近完成的两场、当前 Strategy 最高 reward 的一场、当前 Strategy
    最近的一场；按 Attempt 身份去重后按执行顺序渲染。输入须是已提交的完成 Attempt，
    因而 caller 不会把 partial trace 当作学习材料。
    """
    active_limits = limits or GenerationMemoryLimits()
    indexed = list(enumerate(attempts))
    recent = indexed[-2:]
    current = [
        (index, attempt) for index, attempt in indexed if attempt.strategy_id == current_strategy_id
    ]
    best_current = max(current, key=lambda pair: (pair[1].reward, pair[0]), default=None)
    latest_current = current[-1] if current else None
    selected: dict[str, tuple[int, Attempt]] = {}
    for pair in [*recent, best_current, latest_current]:
        if pair is not None:
            selected[pair[1].id] = pair
    ordered = sorted(selected.values(), key=lambda pair: pair[0])[
        -active_limits.max_detailed_attempts :
    ]

    entries = [_render_attempt(index, attempt, active_limits) for index, attempt in ordered]
    rendered = "\n\n".join(entries)
    truncated = any("[TRUNCATED]" in entry for entry in entries)
    if len(rendered) > active_limits.max_history_chars:
        rendered = _truncate(rendered, active_limits.max_history_chars)
        truncated = True
    digest = hashlib.sha256(rendered.encode("utf-8")).hexdigest()
    return GenerationMemory(
        policy_version=policy_version,
        selected_attempt_refs=[attempt.id for _, attempt in ordered],
        rendered_history=rendered,
        digest=digest,
        truncated=truncated,
        rendered_chars=len(rendered),
    )


def strategy_aggregates(attempts: list[Attempt]) -> list[dict[str, int | float | str | None]]:
    """供 ControllerEvidence 使用的稳定聚合；按 Strategy ID 排序且不携带原始文本。"""
    grouped: dict[str, list[Attempt]] = defaultdict(list)
    for attempt in attempts:
        grouped[attempt.strategy_id].append(attempt)
    summaries: list[dict[str, int | float | str | None]] = []
    for strategy_id in sorted(grouped):
        records = grouped[strategy_id]
        summaries.append(
            {
                "strategy_id": strategy_id,
                "attempted": len(records),
                "completed": len(records),
                "abandoned": 0,
                "mean_reward": round(sum(item.reward for item in records) / len(records), 3),
                "best_reward": round(max(item.reward for item in records), 3),
                "latest_reward": round(records[-1].reward, 3),
                "last_used_at": records[-1].created_at.isoformat(),
                "mean_total_tokens": round(
                    sum(item.cost.total_tokens for item in records) / len(records), 3
                ),
                "latest_total_tokens": records[-1].cost.total_tokens,
            }
        )
    return summaries


def _render_attempt(index: int, attempt: Attempt, limits: GenerationMemoryLimits) -> str:
    lines = [
        (
            f"Attempt {index + 1} ref={attempt.id} strategy={attempt.strategy_id} "
            f"reward={attempt.reward:.3f}"
        ),
        f"stop_reason={attempt.stop_reason.value if attempt.stop_reason else 'unknown'}",
    ]
    for turn in attempt.turns:
        lines.append(f"attacker: {_truncate(turn.attacker_message, limits.max_message_chars)}")
        lines.append(
            f"target: {_truncate(turn.output.assistant_message, limits.max_message_chars)}"
        )
        for call in turn.output.tool_calls:
            lines.append(f"tool_call: {call.name} arguments={call.arguments}")
        for result in turn.output.tool_results:
            outcome = "error" if result.error else "success"
            lines.append(f"tool_result: {result.name} status={outcome}")
        for effect in turn.output.side_effects:
            lines.append(f"side_effect: {effect.kind}")
    return _truncate("\n".join(lines), limits.max_attempt_chars)


def _truncate(text: str, maximum: int) -> str:
    if len(text) <= maximum:
        return text
    marker = "[TRUNCATED]"
    if maximum <= len(marker):
        return marker[:maximum]
    available = maximum - len(marker)
    start = available // 2
    end = available - start
    return f"{text[:start]}{marker}{text[-end:]}"
