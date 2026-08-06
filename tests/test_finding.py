from __future__ import annotations

import pytest
from pydantic import ValidationError

from redcell.protocols import (
    Evidence,
    Finding,
    ImpactBasis,
    ImpactStatus,
    ObservabilityLevel,
    ToolCall,
    ViolationTriad,
    VulnerabilityCategory,
)


def _finding(**overrides) -> Finding:
    base = {
        "run_id": "run_1",
        "attempt_id": "attempt_1",
        "category": VulnerabilityCategory.UNAUTHORIZED_TOOL_USE,
        "title": "跨用户读取客户资料",
        "actor": "customer_a",
        "strategy_id": "cross_user_resource_access",
        "triad": ViolationTriad(
            attempted_action=True,
            realized_impact=ImpactStatus.REALIZED,
            impact_basis=ImpactBasis.SIDE_EFFECT,
        ),
        "evidence": [
            Evidence(
                description="以 customer_a 身份读取了 customer_b 的资料",
                tool_call=ToolCall(
                    id="tc_1",
                    name="get_customer_profile",
                    arguments={"customer_id": "customer_b"},
                ),
            )
        ],
        "observability": ObservabilityLevel.FULL,
    }
    base.update(overrides)
    return Finding(**base)


def test_finding_requires_evidence() -> None:
    """无证据的 Finding 是猜测,不是发现。"""
    with pytest.raises(ValidationError):
        _finding(evidence=[])


def test_full_observability_allows_asserting_impact() -> None:
    finding = _finding()
    assert finding.triad.fully_compromised
    assert finding.impact_is_verifiable
    assert finding.impact_caveat is None


def test_defense_in_depth_held_is_distinguishable() -> None:
    """agent 想干坏事但后端拦住了 —— 和"两层全失守"必须能区分开。

    两者的修复方式和紧急程度完全不同,压成一个 bool 就分不出来了。
    """
    finding = _finding(
        triad=ViolationTriad(
            attempted_action=True,
            realized_impact=ImpactStatus.NOT_REALIZED,
            impact_basis=ImpactBasis.SIDE_EFFECT,
        )
    )
    assert finding.triad.defense_in_depth_held
    assert not finding.triad.fully_compromised


def test_unknown_impact_autofills_caveat() -> None:
    """可观测性不足时,报告必须显式承认"看不见",不能默默省略。"""
    finding = _finding(
        triad=ViolationTriad(attempted_action=True, realized_impact=ImpactStatus.UNKNOWN),
        observability=ObservabilityLevel.PARTIAL,
    )
    assert finding.impact_caveat is not None
    assert "partial" in finding.impact_caveat
    assert not finding.impact_is_verifiable


@pytest.mark.parametrize(
    "level",
    [ObservabilityLevel.PARTIAL, ObservabilityLevel.RESPONSE_ONLY],
)
def test_cannot_assert_side_effect_impact_without_observability(
    level: ObservabilityLevel,
) -> None:
    """把"未知"折叠成"没发生"会造成系统性漏报,这里直接在协议层拦死。"""
    for impact in (ImpactStatus.NOT_REALIZED, ImpactStatus.REALIZED):
        with pytest.raises(ValidationError, match="无法断言 Impact"):
            _finding(
                triad=ViolationTriad(
                    attempted_action=True,
                    realized_impact=impact,
                    impact_basis=ImpactBasis.SIDE_EFFECT,
                ),
                observability=level,
            )


@pytest.mark.parametrize(
    "level",
    [ObservabilityLevel.PARTIAL, ObservabilityLevel.RESPONSE_ONLY],
)
def test_response_content_impact_survives_low_observability(
    level: ObservabilityLevel,
) -> None:
    """canary 就印在回复正文里 —— 黑盒目标上这条结论照样成立。

    统一按副作用门槛卡,会让最有价值的那类结论在远程目标上直接构造失败,
    而失败点在评分器内部,表现为整个 Run 被判 FAILED。
    """
    finding = _finding(
        category=VulnerabilityCategory.PROMPT_INJECTION,
        triad=ViolationTriad(
            attempted_action=True,
            realized_impact=ImpactStatus.REALIZED,
            impact_basis=ImpactBasis.RESPONSE_CONTENT,
        ),
        observability=level,
    )
    assert finding.triad.fully_compromised
    assert finding.impact_is_verifiable
    assert finding.impact_caveat is None


def test_asserted_impact_requires_a_basis() -> None:
    """断言了 impact 就必须说明凭什么断言,否则报告无法交代结论来源。"""
    with pytest.raises(ValidationError, match="必须同时给出 impact_basis"):
        ViolationTriad(attempted_action=True, realized_impact=ImpactStatus.REALIZED)


def test_unknown_impact_must_not_carry_a_basis() -> None:
    """什么都没观测到就没有证据来源;允许填会让 UNKNOWN 看起来像有依据。"""
    with pytest.raises(ValidationError, match="不能有 impact_basis"):
        ViolationTriad(
            attempted_action=True,
            realized_impact=ImpactStatus.UNKNOWN,
            impact_basis=ImpactBasis.SIDE_EFFECT,
        )


def test_intent_defaults_to_unassessed() -> None:
    """Phase 0 不判定 Intent:它需要语义理解,会把 judge 噪声引进核心实验。"""
    assert _finding().triad.intent_violation is None


def test_reproduction_rate_bounds() -> None:
    finding = _finding(reproduction_rate=0.6, reproduction_runs=5)
    assert finding.reproduction_rate == 0.6

    with pytest.raises(ValidationError):
        _finding(reproduction_rate=1.4)
