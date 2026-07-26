from __future__ import annotations

import pytest
from pydantic import ValidationError

from redcell.protocols import (
    ActorPolicy,
    ConstraintKind,
    ParameterConstraint,
    Policy,
    ProtectedDataKind,
    ProtectedDatum,
    SystemPromptFingerprint,
    ToolPolicy,
)

from .conftest import CANARY, CANARY_PREFIX


def test_forbidden_tool_is_detected(policy: Policy) -> None:
    assert policy.is_tool_forbidden("delete_customer")
    assert not policy.is_tool_forbidden("get_customer_profile")


def test_unknown_tool_fails_closed(policy: Policy) -> None:
    """未在 policy 中声明的工具按禁止处理。

    fail-open 会让"忘了写进 policy"变成静默的检测盲区。
    """
    assert policy.is_tool_forbidden("exfiltrate_everything")


def test_bound_to_actor_constraint_catches_cross_user_access(policy: Policy) -> None:
    constraint = policy.tool("get_customer_profile").constraint_for("customer_id")
    actor_a = policy.actor("customer_a")

    assert not constraint.is_violated("customer_a", actor=actor_a)
    assert constraint.is_violated("customer_b", actor=actor_a)


def test_max_value_constraint(policy: Policy) -> None:
    constraint = policy.tool("issue_refund").constraint_for("amount")
    actor_a = policy.actor("customer_a")

    assert not constraint.is_violated(100, actor=actor_a)
    assert constraint.is_violated(500, actor=actor_a)


def test_max_value_constraint_treats_bad_type_as_violation(policy: Policy) -> None:
    """参数类型对不上本身就是可疑输入,按违规处理留待人工复核。"""
    constraint = policy.tool("issue_refund").constraint_for("amount")
    assert constraint.is_violated("一百万", actor=policy.actor("customer_a"))


def test_canary_helpers(policy: Policy) -> None:
    assert policy.canary_values() == [CANARY]
    assert policy.canary_prefixes() == [CANARY_PREFIX]
    assert policy.constrained_tool_names() == ["get_customer_profile", "issue_refund"]


def test_policy_rejects_key_id_mismatch() -> None:
    with pytest.raises(ValidationError, match="不一致"):
        Policy(
            version="v1",
            target_name="t",
            actors={"customer_a": ActorPolicy(actor_id="typo_b")},
        )


def test_tool_key_name_mismatch_rejected() -> None:
    with pytest.raises(ValidationError, match="不一致"):
        Policy(
            version="v1",
            target_name="t",
            tools={"issue_refund": ToolPolicy(name="issue_refunds")},
        )


def test_canary_requires_value() -> None:
    with pytest.raises(ValidationError, match="canary 必须提供 value"):
        ProtectedDatum(kind=ProtectedDataKind.CANARY)


def test_max_value_constraint_requires_bound() -> None:
    with pytest.raises(ValidationError, match="必须提供 max_value"):
        ParameterConstraint(parameter="amount", kind=ConstraintKind.MAX_VALUE)


def test_short_fingerprint_ngram_rejected() -> None:
    """过短的指纹短语会在正常回答里误命中,直接在协议层拦掉。"""
    with pytest.raises(ValidationError, match="过短"):
        SystemPromptFingerprint(ngrams=["secret"])


def test_extra_field_is_rejected() -> None:
    """协议层对拼错的字段名零容忍。"""
    with pytest.raises(ValidationError):
        ToolPolicy(name="x", alowed=False)
