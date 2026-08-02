from __future__ import annotations

import json

import pytest
from typer.testing import CliRunner

from redcell.budget import BudgetLimits
from redcell.cli import OFFLINE_NOTICE, ExitCode, app
from redcell.config import ProviderConfigError
from redcell.llm.scripted import ScriptedProvider
from redcell.protocols import (
    AdapterOutput,
    Evidence,
    Finding,
    ImpactBasis,
    ImpactStatus,
    ObservabilityLevel,
    ReproductionContext,
    SignalChannel,
    SignalScore,
    ToolCall,
    Turn,
    ViolationTriad,
    VulnerabilityCategory,
    build_attempt,
)
from redcell.protocols.run import Run, RunStatus
from redcell.storage import RunStore

runner = CliRunner()


@pytest.fixture
def workspace(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    return tmp_path


def _db(path) -> str:
    return f"sqlite:///{path / 'cli.db'}"


# ── run ──────────────────────────────────────────────────────────────────


def test_run_completes_end_to_end_and_writes_both_reports(workspace) -> None:
    result = runner.invoke(
        app,
        ["run", "--budget", "3", "--db", _db(workspace), "--out", "runs"],
    )

    assert result.exit_code == ExitCode.CLEAN, result.output
    assert "status  completed" in result.output

    run_dirs = list((workspace / "runs").iterdir())
    assert len(run_dirs) == 1
    assert (run_dirs[0] / "report.json").exists()
    assert (run_dirs[0] / "report.html").exists()


def test_offline_run_is_labelled_as_not_a_security_assessment(workspace) -> None:
    """0 Finding 的报告最容易被读成"扫过了,是安全的"。

    离线 provider 下目标模型根本没参与决策,不标注就是在制造这个误解。
    """
    result = runner.invoke(app, ["run", "--budget", "1", "--db", _db(workspace)])
    assert "不构成对任何 agent 的安全评估" in result.output

    payload = json.loads(
        next((workspace / "runs").rglob("report.json")).read_text(encoding="utf-8")
    )
    assert payload["run"]["notes"] == OFFLINE_NOTICE


def test_run_is_reproducible_under_the_same_seed(workspace) -> None:
    """同一 seed 必须给出同一条策略序列,否则"可复现"是空话。"""
    common = ["run", "--budget", "4", "--seed", "7", "--algorithm", "random"]
    for name in ("a", "b"):
        (workspace / name).mkdir()
    first = runner.invoke(app, [*common, "--db", _db(workspace / "a")])
    second = runner.invoke(app, [*common, "--db", _db(workspace / "b")])

    assert first.exit_code == ExitCode.CLEAN
    assert second.exit_code == ExitCode.CLEAN

    def order(db_path: str) -> list[str]:
        with RunStore(db_path) as store:
            run_id = store.list_runs()[0].id
            return [a.strategy_id for a in store.attempts_for(run_id)]

    assert order(_db(workspace / "a")) == order(_db(workspace / "b"))


def test_budget_is_respected(workspace) -> None:
    runner.invoke(app, ["run", "--budget", "2", "--db", _db(workspace)])
    with RunStore(_db(workspace)) as store:
        stored = store.list_runs()[0]
        assert stored.usage.attempts <= 2
        assert stored.stopped_by is not None


def test_unknown_algorithm_is_a_usage_error_not_a_run_failure(workspace) -> None:
    """Click 用 2 表示用法错误 —— 我们的退出码刻意避开它。

    否则 CI 分不出"参数拼错了"和"run 真的失败了",而两者的处置完全不同。
    """
    result = runner.invoke(app, ["run", "--algorithm", "bogus", "--db", _db(workspace)])
    assert result.exit_code == 2
    assert result.exit_code not in (ExitCode.RUN_FAILED, ExitCode.BAD_CONFIG)


def test_cost_budget_is_not_exposed_while_provider_reports_no_cost(workspace) -> None:
    """当前 provider 不报成本,`--max-cost` 会是个永不触发的假安全网。"""
    result = runner.invoke(app, ["run", "--max-cost", "1.0", "--db", _db(workspace)])
    assert result.exit_code == 2  # no such option


# ── report ───────────────────────────────────────────────────────────────


def test_report_rebuilds_from_storage(workspace) -> None:
    runner.invoke(app, ["run", "--budget", "2", "--db", _db(workspace), "--out", "runs"])
    with RunStore(_db(workspace)) as store:
        run_id = store.list_runs()[0].id

    result = runner.invoke(app, ["report", run_id, "--db", _db(workspace), "--out", "again"])

    assert result.exit_code == ExitCode.CLEAN
    assert (workspace / "again" / run_id / "report.json").exists()

    first = (workspace / "runs" / run_id / "report.json").read_text(encoding="utf-8")
    second = (workspace / "again" / run_id / "report.json").read_text(encoding="utf-8")
    # 报告从存储重建,而不是执行时缓存 —— 两次导出的数字必须一致。
    assert json.loads(first)["total_attempts"] == json.loads(second)["total_attempts"]


def test_report_on_missing_run_is_bad_config(workspace) -> None:
    result = runner.invoke(app, ["report", "no-such-run", "--db", _db(workspace)])
    assert result.exit_code == ExitCode.BAD_CONFIG


def test_findings_produce_a_nonzero_exit(workspace) -> None:
    """有发现即非零,和主流扫描器一致 —— CI 可以直接拿它当门禁。"""
    run_record = Run(
        target_name="support-agent",
        policy_version="v1",
        adapter_type="arena/support-agent",
        algorithm="static",
        limits=BudgetLimits(max_attempts=1),
        status=RunStatus.COMPLETED,
    )
    attempt = build_attempt(
        run_id=run_record.id,
        strategy_id="cross_user_resource_access",
        actor="customer_a",
        attack_prompt="...",
        reproduction=ReproductionContext(
            policy_version="v1",
            target_name="support-agent",
            adapter_type="arena/support-agent",
            strategy_id="cross_user_resource_access",
        ),
        turns=[
            Turn(
                index=0,
                attacker_message="hi",
                output=AdapterOutput(observability=ObservabilityLevel.FULL),
            )
        ],
        signals=[SignalScore(channel=SignalChannel.TOOL, score=1.0, tier="t", evidence="e")],
    )
    finding = Finding(
        run_id=run_record.id,
        attempt_id=attempt.id,
        category=VulnerabilityCategory.UNAUTHORIZED_TOOL_USE,
        title="跨用户读取",
        actor="customer_a",
        strategy_id="cross_user_resource_access",
        triad=ViolationTriad(
            attempted_action=True,
            realized_impact=ImpactStatus.REALIZED,
            impact_basis=ImpactBasis.SIDE_EFFECT,
        ),
        evidence=[
            Evidence(
                description="以 customer_a 身份读取了 customer_b",
                tool_call=ToolCall(id="t1", name="get_customer_profile", arguments={}),
            )
        ],
        observability=ObservabilityLevel.FULL,
    )

    with RunStore(_db(workspace)) as store:
        store.save_run(run_record)
        store.save_attempt(attempt)
        store.save_finding(finding)

    result = runner.invoke(app, ["report", run_record.id, "--db", _db(workspace)])
    assert result.exit_code == ExitCode.FINDINGS


def test_incomplete_run_is_flagged_in_the_summary(workspace) -> None:
    """中断的 run 会系统性低估发现数,不能和完整 run 放在一起比。"""
    run_record = Run(
        target_name="support-agent",
        policy_version="v1",
        adapter_type="arena/support-agent",
        algorithm="static",
        limits=BudgetLimits(max_attempts=1),
        status=RunStatus.ABORTED,
    )
    with RunStore(_db(workspace)) as store:
        store.save_run(run_record)

    result = runner.invoke(app, ["report", run_record.id, "--db", _db(workspace)])
    assert "未正常完成" in result.output


# ── attacker-control ─────────────────────────────────────────────────────


class _FakeAttacker(ScriptedProvider):
    """带 `model` / `aclose()` 的脚本 provider —— 对齐 OpenAICompatibleProvider 的接口。

    `LLMProvider` 基类没有这两样(它们属于真实的 HTTP provider),
    而 CLI 会用到,所以这里补齐。
    """

    def __init__(self, *, per_call: list[str]) -> None:
        super().__init__(per_call, model="fake-attacker")
        self.closed = False

    @property
    def model(self) -> str:
        return "fake-attacker"

    async def aclose(self) -> None:
        self.closed = True


def _install_attacker(monkeypatch, provider: _FakeAttacker) -> _FakeAttacker:
    monkeypatch.setattr("redcell.cli.load_attacker", lambda: provider)
    return provider


def _clustered_messages(per_strategy: int, strategies: int = 7) -> list[str]:
    """攻击方正常工作时的形状:同一策略内部用词相近,不同策略之间几乎不重合。

    `run_attacker_control` 逐策略连续取样,所以按 call 顺序排成六段即可。
    """
    return [
        f"topic{g} alpha{g} beta{g} gamma{g} delta{g} variant{i}"
        for g in range(strategies)
        for i in range(per_strategy)
    ]


def test_attacker_control_passes_when_strategies_produce_different_wording(
    workspace, monkeypatch
) -> None:
    attacker = _install_attacker(monkeypatch, _FakeAttacker(per_call=_clustered_messages(3)))

    result = runner.invoke(app, ["attacker-control", "--samples", "3", "--out", "control"])

    assert result.exit_code == ExitCode.CLEAN, result.output
    assert "攻击方不是瓶颈" in result.output
    assert attacker.closed


def test_attacker_control_writes_every_generated_message_for_manual_review(
    workspace, monkeypatch
) -> None:
    """结论只有两个小数,人工复核靠的是这份明细 —— 不落盘等于不可复核。"""
    _install_attacker(monkeypatch, _FakeAttacker(per_call=_clustered_messages(5)))

    runner.invoke(app, ["attacker-control", "--samples", "2", "--seed", "9", "--out", "control"])

    detail = json.loads((workspace / "control" / "attacker-control-seed9.json").read_text("utf-8"))
    assert len(detail["samples"]) == 7
    assert all(len(group["messages"]) == 2 for group in detail["samples"])


def test_attacker_control_fails_when_every_strategy_yields_the_same_wording(
    workspace, monkeypatch
) -> None:
    """所有策略产出同一句话 = 策略标签没改变输出,攻击方是瓶颈。"""
    _install_attacker(monkeypatch, _FakeAttacker(per_call=["the same sentence every time"] * 60))

    result = runner.invoke(app, ["attacker-control", "--samples", "3", "--out", "control"])

    assert result.exit_code == ExitCode.CONTROL_FAILED, result.output
    assert "瓶颈" in result.output
    assert "靶场一个字都别动" in result.output


def test_control_failure_is_not_confused_with_findings_or_usage_errors() -> None:
    """ "对照没过"和"扫出漏洞了"方向相反,不能共用一个退出码。"""
    assert ExitCode.CONTROL_FAILED not in (ExitCode.FINDINGS, ExitCode.CLEAN)
    assert ExitCode.CONTROL_FAILED != 2  # Click 的用法错误


def test_attacker_control_has_no_offline_mode(workspace) -> None:
    """离线用模板生成器,会稳定地报告"攻击方没问题"——一个永远说 OK 的对照。"""
    assert runner.invoke(app, ["attacker-control", "--offline"]).exit_code == 2


def test_attacker_control_reports_missing_attacker_config_as_bad_config(
    workspace, monkeypatch
) -> None:
    def _reject() -> None:
        raise ProviderConfigError("attacker provider 配置不完整")

    monkeypatch.setattr("redcell.cli.load_attacker", _reject)

    result = runner.invoke(app, ["attacker-control"])
    assert result.exit_code == ExitCode.BAD_CONFIG
    assert "配置被拒绝" in result.output


def test_attacker_control_rejects_unknown_actor_before_spending_any_quota(
    workspace, monkeypatch
) -> None:
    attacker = _install_attacker(monkeypatch, _FakeAttacker(per_call=_clustered_messages(5)))

    result = runner.invoke(app, ["attacker-control", "--actor", "nobody"])

    assert result.exit_code == ExitCode.BAD_CONFIG
    assert attacker.call_count == 0


def test_attacker_control_rejects_a_sample_size_that_cannot_measure_within_similarity(
    workspace, monkeypatch
) -> None:
    _install_attacker(monkeypatch, _FakeAttacker(per_call=_clustered_messages(5)))

    result = runner.invoke(app, ["attacker-control", "--samples", "1"])
    assert result.exit_code == ExitCode.BAD_CONFIG
