"""native-function-calling-v2:PRD Phase 0.5e 预注册第 3 条的零成本契约(2026-09-25)。

第 3 条要求原生协议在任何 Provider 调用之前,用离线测试证明:缺调用 ID、未知工具、非 schema
参数、不匹配的 tool result 一律 fail-closed;完整工具 schema 与 codec 版本进入 Gate context 指纹。
缺 ID / 重复 ID 在 Provider 层已有测试(`test_openai_compatible.py`),这里覆盖其余几条,
并锁住 v1 的旧语义不变。
"""

from __future__ import annotations

import json

import pytest
from pydantic import ValidationError
from typer.testing import CliRunner

from redcell.arena.execution import tool_schema_digest
from redcell.arena.ops_console import OPS_CONSOLE_ARENA
from redcell.arena.registry import ARENAS
from redcell.arena.support_agent import (
    SUPPORT_AGENT_ARENA,
    ArenaAdapter,
    DefenseLevel,
    SupportAgentTools,
)
from redcell.arena.support_agent.codec import (
    NATIVE_V2_TOOL_CALL_CODEC_VERSION,
    NativeToolCallCodec,
    ToolCallProtocol,
)
from redcell.cli import ExitCode, _experiment_conditions, app
from redcell.controls import UTILITY_CONTEXT_VERSION, ControlsReport, controls_conditions
from redcell.gate_analysis import SeedPlan
from redcell.gate_plan import build_gate_plan
from redcell.gate_preflight import run_preflight
from redcell.llm import LLMResponse, LLMToolCall
from redcell.protocols import AdapterInput, Message, Role
from redcell.protocols.run import ArenaRunConfiguration
from redcell.storage import RunStore
from redcell.utility_baseline import UtilityBaseline

from .test_arena_adapter import _NativeProvider
from .test_gate_preflight import PHASE_0_5D_SEED_PLAN, _billing_evidence, _check, _db, _roles

SPECS = SupportAgentTools().specs()
V2 = ToolCallProtocol.NATIVE_V2


def _native(call_id: str, name: str, arguments: object) -> LLMToolCall:
    raw = arguments if isinstance(arguments, str) else json.dumps(arguments)
    return LLMToolCall(id=call_id, name=name, arguments_json=raw)


def _decode(codec: NativeToolCallCodec, *calls: LLMToolCall):
    return codec.decode(LLMResponse(content="", tool_calls=list(calls)))


# ── codec ────────────────────────────────────────────────────────────────


def test_protocol_value_matches_the_literal_used_by_the_conditions_validator() -> None:
    assert V2.value == NATIVE_V2_TOOL_CALL_CODEC_VERSION == "native-function-calling-v2"
    assert NativeToolCallCodec(specs=SPECS).version == V2.value
    assert NativeToolCallCodec().version == ToolCallProtocol.NATIVE_V1.value


def test_v1_keeps_passing_undeclared_tools_and_off_schema_arguments_to_the_arena() -> None:
    """v1 已被开发测量用过;它的解码语义不能被 v2 顺手改掉。"""
    decoded = _decode(
        NativeToolCallCodec(),
        _native("c1", "exfiltrate_everything", {}),
        _native("c2", "issue_refund", {"order_id": "ORD-1001", "amount_usd": "79"}),
    )
    assert [call.id for call in decoded.calls] == ["c1", "c2"]
    assert decoded.malformed == 0


@pytest.mark.parametrize(
    ("name", "arguments"),
    [
        ("exfiltrate_everything", {}),  # 本轮没有声明的工具
        ("issue_refund", {"order_id": "ORD-1001"}),  # 缺必填
        ("issue_refund", {"order_id": "ORD-1001", "amount_usd": "79"}),  # 数字写成字符串
        ("issue_refund", {"order_id": "ORD-1001", "amount_usd": True}),  # 布尔不算数字
        ("get_customer_profile", {"customer_id": 7}),  # 字符串写成数字
        ("search_faq", "not-json"),  # v1 就有的那条
        ("search_faq", "[1, 2]"),  # JSON 但不是对象
    ],
)
def test_v2_treats_interface_violations_as_malformed(name: str, arguments: object) -> None:
    decoded = _decode(NativeToolCallCodec(specs=SPECS), _native("c1", name, arguments))
    assert decoded.calls == []
    assert decoded.malformed == 1


def test_v2_accepts_schema_valid_calls_and_undeclared_extra_keys() -> None:
    """声明没有 `additionalProperties: false`,多出来的键按 JSON Schema 默认语义放行。"""
    decoded = _decode(
        NativeToolCallCodec(specs=SPECS),
        _native("c1", "issue_refund", {"order_id": "ORD-1001", "amount_usd": 79}),
        _native("c2", "search_faq", {"topic": "refund", "note": "extra"}),
        _native("c3", "list_my_orders", {}),
    )
    assert [call.id for call in decoded.calls] == ["c1", "c2", "c3"]
    assert decoded.malformed == 0


def test_v2_refuses_a_schema_it_does_not_understand() -> None:
    """看不懂的约束不能在"已校验"的名义下被悄悄跳过。"""
    spec = {
        "name": "t",
        "description": "d",
        "parameters": {
            "type": "object",
            "properties": {"n": {"type": "number", "maximum": 5}},
            "required": [],
        },
    }
    with pytest.raises(ValueError, match="超出支持范围"):
        NativeToolCallCodec(specs=[spec])


def test_every_registered_arena_is_expressible_under_v2() -> None:
    for arena in ARENAS.values():
        NativeToolCallCodec(specs=arena.make_tools().specs())


async def test_v2_does_not_execute_invalid_calls_but_answers_every_call_id() -> None:
    provider = _NativeProvider(
        [
            LLMResponse(
                content="",
                tool_calls=[
                    _native("c1", "search_faq", {"topic": "refund"}),
                    _native("c2", "delete_everything", {}),
                    _native("c3", "issue_refund", {"order_id": "ORD-1001", "amount_usd": "9"}),
                ],
            ),
            LLMResponse(content="Done."),
        ]
    )
    adapter = ArenaAdapter(provider, tool_call_protocol=V2)
    result = await adapter.send(
        AdapterInput(messages=[Message(role=Role.USER, content="hi")], actor="customer_a")
    )

    replies = [m for m in provider.requests[1] if m.role is Role.TOOL]
    assert [reply.tool_call_id for reply in replies] == ["c1", "c2", "c3"]
    assert [json.loads(reply.content)["status"] for reply in replies] == [
        "ok",
        "invalid_call",
        "invalid_arguments",
    ]
    # 只有合法调用进入靶场与 trace;接口错误单独计数,不会变成 Scorer 眼里的越权。
    assert [call.id for call in result.tool_calls] == ["c1"]
    assert result.malformed_tool_calls == 2
    assert result.side_effects == []
    assert adapter.tool_call_protocol_version == V2.value


def test_v2_followup_rejects_results_that_do_not_match_the_calls() -> None:
    codec = NativeToolCallCodec(specs=SPECS)
    response = LLMResponse(content="", tool_calls=[_native("c1", "search_faq", {"topic": "x"})])
    with pytest.raises(ValueError, match="do not match"):
        codec.followup_messages(response, [])


# ── 工具声明摘要进入实验条件 ─────────────────────────────────────────────


def test_schema_digest_is_recorded_for_v2_and_only_v2() -> None:
    base = {"defense": "standard", "enforce_permissions": True, "enforce_confirmation": True}
    digest = SUPPORT_AGENT_ARENA.tool_schema_sha256
    ArenaRunConfiguration(**base, tool_call_protocol_version=V2.value, tool_schema_sha256=digest)
    with pytest.raises(ValidationError, match="必须且只有它"):
        ArenaRunConfiguration(**base, tool_call_protocol_version=V2.value)
    with pytest.raises(ValidationError, match="必须且只有它"):
        ArenaRunConfiguration(
            **base,
            tool_call_protocol_version="native-function-calling-v1",
            tool_schema_sha256=digest,
        )
    unset = ArenaRunConfiguration(**base, tool_call_protocol_version="native-function-calling-v1")
    assert "tool_schema_sha256" not in unset.model_dump(mode="json")


def test_digest_tracks_the_declarations_actually_sent() -> None:
    assert SUPPORT_AGENT_ARENA.tool_schema_sha256 == tool_schema_digest(SPECS)
    assert SUPPORT_AGENT_ARENA.tool_schema_sha256 != OPS_CONSOLE_ARENA.tool_schema_sha256
    changed = [dict(spec) for spec in SPECS]
    changed[0] = {**changed[0], "description": changed[0]["description"] + " "}
    assert tool_schema_digest(changed) != tool_schema_digest(SPECS)


def _conditions(protocol: ToolCallProtocol, arena_id: str | None = None):
    return _experiment_conditions(
        online=False,
        providers=None,
        actor="customer_a" if arena_id is None else "agent_l1",
        defense=DefenseLevel.STANDARD,
        enforce_permissions=True,
        enforce_confirmation=True,
        tool_call_protocol_version=protocol.value,
        arena_id=arena_id,
        arena_version=None if arena_id is None else OPS_CONSOLE_ARENA.version,
    )


def test_run_conditions_bind_the_schema_of_the_arena_they_run_on() -> None:
    support = _conditions(V2)
    ops = _conditions(V2, "ops-console")
    assert support.arena.tool_schema_sha256 == SUPPORT_AGENT_ARENA.tool_schema_sha256
    assert ops.arena.tool_schema_sha256 == OPS_CONSOLE_ARENA.tool_schema_sha256
    assert _conditions(ToolCallProtocol.NATIVE_V1).arena.tool_schema_sha256 is None
    assert support.fingerprint() != _conditions(ToolCallProtocol.NATIVE_V1).fingerprint()


def test_resume_recomputes_the_digest_so_schema_drift_breaks_the_fingerprint(monkeypatch) -> None:
    """摘要由 `_experiment_conditions` 现算,不照抄落盘值:声明一变,重算的指纹就对不上。"""
    before = _conditions(V2)
    monkeypatch.setattr(
        type(SUPPORT_AGENT_ARENA), "tool_schema_sha256", property(lambda _self: "e" * 64)
    )
    assert _conditions(V2).fingerprint() != before.fingerprint()


def test_offline_v2_run_persists_the_digest(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    db = f"sqlite:///{tmp_path / 'cli.db'}"
    result = CliRunner().invoke(
        app, ["run", "--budget", "1", "--tool-call-protocol", V2.value, "--db", db]
    )
    assert result.exit_code in (ExitCode.CLEAN, ExitCode.FINDINGS), result.output
    with RunStore(db) as store:
        stored = store.list_runs()[0]
    assert stored.experiment_conditions.arena.tool_schema_sha256 == (
        SUPPORT_AGENT_ARENA.tool_schema_sha256
    )
    assert stored.conditions_fingerprint_verified


# ── controls 与 preflight ─────────────────────────────────────────────────


def test_v2_controls_bind_the_schema_into_the_utility_context() -> None:
    target = _roles()[0][1].run_configuration()
    v1 = controls_conditions(target=target, tool_call_protocol_version="native-function-calling-v1")
    v2 = controls_conditions(target=target, tool_call_protocol_version=V2.value)
    assert v1.negative_arena.tool_schema_sha256 is None
    assert v2.negative_arena.tool_schema_sha256 == SUPPORT_AGENT_ARENA.tool_schema_sha256
    assert v1.utility_context_fingerprint() != v2.utility_context_fingerprint()


def _v2_preflight(tmp_path, *, controls_schema: str):
    roles = _roles()
    target = next(settings for name, settings in roles if name == "target")
    conditions = controls_conditions(
        target=target.run_configuration(), tool_call_protocol_version=V2.value
    )
    conditions = conditions.model_copy(
        update={
            "negative_arena": conditions.negative_arena.model_copy(
                update={"tool_schema_sha256": controls_schema}
            )
        }
    )
    seed_plan = SeedPlan.model_validate_json(PHASE_0_5D_SEED_PLAN.read_text(encoding="utf-8"))
    return run_preflight(
        seed_plan_json=PHASE_0_5D_SEED_PLAN,
        database_url=_db(tmp_path),
        roles=roles,
        shared_rate_limit_db=f"sqlite:///{tmp_path / 'shared-rate-limit.db'}",
        billing_evidence=_billing_evidence(roles),
        controls=ControlsReport(
            conditions=conditions,
            utility_context_fingerprint=conditions.utility_context_fingerprint(),
            utility_context_version=UTILITY_CONTEXT_VERSION,
        ),
        utility_baseline=UtilityBaseline(
            context_fingerprint=conditions.utility_context_fingerprint(),
            negative_repeats=20,
            per_task={"task": 20},
        ),
        gate_plan=build_gate_plan(
            seed_plan,
            max_attempts=500,
            database_url="sqlite:///runs/phase-0-5d.db",
            report_directory="runs/phase-0-5d",
            tool_call_protocol=V2,
        ),
    )


def test_preflight_rejects_controls_measured_on_another_tool_interface(tmp_path) -> None:
    stale = _v2_preflight(tmp_path, controls_schema="e" * 64)
    assert not _check(stale, "controls_tool_schema_mismatch").passed
    current = _v2_preflight(tmp_path, controls_schema=SUPPORT_AGENT_ARENA.tool_schema_sha256)
    assert "controls_tool_schema_mismatch" not in {check.name for check in current.checks}


def test_gate_plan_freezes_v2_into_every_cell() -> None:
    seed_plan = SeedPlan.model_validate_json(PHASE_0_5D_SEED_PLAN.read_text(encoding="utf-8"))
    plan = build_gate_plan(
        seed_plan,
        max_attempts=500,
        database_url="sqlite:///runs/x.db",
        report_directory="runs/x",
        tool_call_protocol=V2,
    )
    assert plan.tool_call_protocol_version == V2.value
    assert all(
        cell.argv[cell.argv.index("--tool-call-protocol") + 1] == V2.value for cell in plan.cells
    )
