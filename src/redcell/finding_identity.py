"""Phase 0.5 的确定性 Finding 身份层。

主指标不数自然语言标题或重复命中；它数可复核的结构漏洞及其冻结 Strategy 组合。
"""

from __future__ import annotations

import hashlib
import json

from redcell.protocols.finding import Finding

FINDING_SIGNATURE_VERSION = "finding-signature-v1"
ATTACK_PATH_SIGNATURE_VERSION = "attack-path-signature-v1"


def finding_signature(finding: Finding) -> str:
    """返回不含 canary 明文、具体参数值或标题的结构身份。"""
    objects = _objects(finding)
    structure = _structure(finding)
    payload = {
        "version": FINDING_SIGNATURE_VERSION,
        "category": finding.category.value,
        "objects": objects,
        "structure": structure,
    }
    return _digest(payload)


def attack_path_signature(finding: Finding) -> str:
    """结构漏洞加冻结 strategy_id；同一路径重复命中不增加 Gate 主指标。"""
    return _digest(
        {
            "version": ATTACK_PATH_SIGNATURE_VERSION,
            "finding_signature": finding_signature(finding),
            "strategy_id": finding.strategy_id,
        }
    )


def _objects(finding: Finding) -> list[str]:
    values: set[str] = set()
    for evidence in finding.evidence:
        if evidence.tool_call is not None:
            values.add(f"tool:{evidence.tool_call.name}")
        if evidence.side_effect is not None:
            values.add(f"side_effect:{evidence.side_effect.kind}")
    return sorted(values) or ["response"]


def _structure(finding: Finding) -> str:
    triad = finding.triad
    if triad.fully_compromised:
        return "attempted+realized"
    if triad.defense_in_depth_held:
        return "attempted+blocked"
    if triad.attempted_action:
        return "attempted+unknown"
    return "observed"


def _digest(payload: dict[str, object]) -> str:
    encoded = json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )
    return hashlib.sha256(encoded).hexdigest()
