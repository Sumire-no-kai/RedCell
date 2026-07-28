from __future__ import annotations

import json

import pytest

from redcell.budget import BudgetLimit, BudgetLimits
from redcell.protocols import (
    AdapterOutput,
    Evidence,
    Finding,
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
from redcell.report import DISCLAIMER, ReportData, to_html, to_json, write_report
from redcell.storage import RunStore


@pytest.fixture
def store(tmp_path) -> RunStore:
    with RunStore(f"sqlite:///{tmp_path / 'test.db'}") as s:
        yield s


@pytest.fixture
def run() -> Run:
    return Run(
        target_name="support-agent",
        policy_version="v1",
        adapter_type="arena/support-agent",
        algorithm="thompson",
        limits=BudgetLimits(max_attempts=100),
        seed=7,
        status=RunStatus.COMPLETED,
        stopped_by=BudgetLimit.ATTEMPTS,
    )


def _attempt(run_id: str, strategy_id: str, reward: float, *, turns: int = 1):
    signals = [SignalScore(channel=SignalChannel.TOOL, score=reward, tier="t", evidence="e")]
    return build_attempt(
        run_id=run_id,
        strategy_id=strategy_id,
        actor="customer_a",
        attack_prompt="...",
        reproduction=ReproductionContext(
            policy_version="v1",
            target_name="support-agent",
            adapter_type="arena/support-agent",
            strategy_id=strategy_id,
        ),
        turns=[
            Turn(
                index=i,
                attacker_message="hi",
                output=AdapterOutput(observability=ObservabilityLevel.FULL),
            )
            for i in range(turns)
        ],
        signals=signals,
    )


def _finding(run_id: str, attempt_id: str, impact: ImpactStatus, **kwargs) -> Finding:
    observability = kwargs.pop(
        "observability",
        (
            ObservabilityLevel.FULL
            if impact is not ImpactStatus.UNKNOWN
            else ObservabilityLevel.PARTIAL
        ),
    )
    return Finding(
        run_id=run_id,
        attempt_id=attempt_id,
        category=VulnerabilityCategory.UNAUTHORIZED_TOOL_USE,
        title="跨用户读取",
        actor="customer_a",
        strategy_id="cross_user_resource_access",
        triad=ViolationTriad(attempted_action=True, realized_impact=impact),
        evidence=[
            Evidence(
                description="以 customer_a 身份读取了 customer_b",
                tool_call=ToolCall(id="t1", name="get_customer_profile", arguments={}),
            )
        ],
        observability=observability,
        **kwargs,
    )


# ── 存储 ─────────────────────────────────────────────────────────────────


def test_run_round_trips_without_loss(store: RunStore, run: Run) -> None:
    store.save_run(run)
    loaded = store.get_run(run.id)

    assert loaded is not None
    assert loaded.model_dump(mode="json") == run.model_dump(mode="json")


def test_attempt_round_trips_with_nested_trace(store: RunStore, run: Run) -> None:
    """嵌套结构必须零损失 —— 复现依赖完整 trace。"""
    store.save_run(run)
    attempt = _attempt(run.id, "s1", 1.0, turns=3)
    store.save_attempt(attempt)

    loaded = store.attempts_for(run.id)
    assert len(loaded) == 1
    assert loaded[0].model_dump(mode="json") == attempt.model_dump(mode="json")
    assert loaded[0].turn_count == 3


def test_finding_round_trips(store: RunStore, run: Run) -> None:
    store.save_run(run)
    finding = _finding(run.id, "a1", ImpactStatus.REALIZED)
    store.save_finding(finding)

    loaded = store.findings_for(run.id)
    assert loaded[0].model_dump(mode="json") == finding.model_dump(mode="json")


def test_save_is_idempotent(store: RunStore, run: Run) -> None:
    """Run 会随执行推进多次落盘,重复写不能变成重复行。"""
    store.save_run(run)
    store.save_run(run.model_copy(update={"status": RunStatus.COMPLETED}))
    assert len(store.list_runs()) == 1


def test_list_runs_filters_by_algorithm(store: RunStore, run: Run) -> None:
    store.save_run(run)
    store.save_run(run.model_copy(update={"id": "other", "algorithm": "random"}))

    assert len(store.list_runs()) == 2
    assert [r.algorithm for r in store.list_runs(algorithm="random")] == ["random"]


def test_attempts_per_strategy_shows_allocation(store: RunStore, run: Run) -> None:
    """bandit 把预算分给了谁 —— 自适应是否真在分配的直接证据。"""
    store.save_run(run)
    store.save_attempts(
        [_attempt(run.id, "s1", 0.0) for _ in range(3)] + [_attempt(run.id, "s2", 0.0)]
    )
    assert store.attempts_per_strategy(run.id) == {"s1": 3, "s2": 1}


def test_attack_success_rate_by_strategy(store: RunStore, run: Run) -> None:
    store.save_run(run)
    store.save_attempts(
        [
            _attempt(run.id, "s1", 1.0),
            _attempt(run.id, "s1", 0.0),
            _attempt(run.id, "s2", 0.0),
        ]
    )
    rates = store.attack_success_rate(run.id)
    assert rates["s1"] == pytest.approx(0.5)
    assert rates["s2"] == 0.0


def test_queries_to_first_success_returns_none_when_never_successful(
    store: RunStore, run: Run
) -> None:
    """⚠️ 未成功时返回 None,不返回预算值。

    用预算值顶替会把删失观测混进普通观测,均值被系统性拉低。
    """
    store.save_run(run)
    store.save_attempts([_attempt(run.id, "s1", 0.0) for _ in range(5)])
    assert store.queries_to_first_success(run.id) is None


def test_queries_to_first_success_counts_position(store: RunStore, run: Run) -> None:
    store.save_run(run)
    store.save_attempts(
        [_attempt(run.id, "s1", 0.0), _attempt(run.id, "s1", 0.0), _attempt(run.id, "s1", 1.0)]
    )
    assert store.queries_to_first_success(run.id) == 3


# ── 报告 ─────────────────────────────────────────────────────────────────


def _report(run: Run) -> ReportData:
    attempts = [
        _attempt(run.id, "s1", 0.0),
        _attempt(run.id, "s1", 1.0),
        _attempt(run.id, "s2", 0.5),
    ]
    findings = [
        _finding(run.id, attempts[1].id, ImpactStatus.REALIZED),
        _finding(run.id, attempts[1].id, ImpactStatus.NOT_REALIZED),
        _finding(run.id, attempts[2].id, ImpactStatus.UNKNOWN),
    ]
    return ReportData.build(run, attempts, findings)


def test_report_separates_the_three_impact_states(run: Run) -> None:
    """合并成一个数字会把"我们不知道"伪装成"确认发生"或"确认没有"。"""
    data = _report(run)
    assert data.impact.realized == 1
    assert data.impact.not_realized == 1
    assert data.impact.unknown == 1
    assert data.unverifiable_impact_count == 1


def test_report_computes_allocation_and_success(run: Run) -> None:
    data = _report(run)
    by_id = {s.strategy_id: s for s in data.strategy_stats}

    assert by_id["s1"].attempts == 2
    assert by_id["s1"].hits == 1
    assert by_id["s1"].success_rate == pytest.approx(0.5)
    assert data.budget_share["s1"] == pytest.approx(2 / 3)
    assert data.queries_to_first_success == 2


def test_report_reports_never_succeeded_as_null(run: Run) -> None:
    data = ReportData.build(run, [_attempt(run.id, "s1", 0.0)], [])
    assert data.queries_to_first_success is None


def test_report_always_carries_the_disclaimer(run: Run) -> None:
    """安全报告最容易造成的伤害,是让读者以为"扫过了 = 安全了"。"""
    data = _report(run)
    assert data.disclaimer == DISCLAIMER
    assert "不能证明系统是安全的" in to_html(data)
    assert "不能证明系统是安全的" in to_json(data)


def test_html_surfaces_the_unverifiable_impact_warning(run: Run) -> None:
    html = to_html(_report(run))
    assert "unverifiable impact" in html
    assert "Impact 无法验证" in html  # 来自 Finding 自动填充的 caveat


def test_html_warns_when_the_run_did_not_complete(run: Run) -> None:
    """中断的 run 会系统性低估发现数,不能和完整 run 放在一起比。"""
    aborted = run.model_copy(update={"status": RunStatus.ABORTED})
    assert not aborted.is_conclusive
    assert "did not complete" in to_html(_report(aborted))
    assert "did not complete" not in to_html(_report(run))


def test_json_and_html_come_from_the_same_data(run: Run) -> None:
    """两种格式共用一份聚合结果,免得改了模板而漏了 JSON,数字对不上。"""
    data = _report(run)
    payload = json.loads(to_json(data))
    assert payload["impact"]["unknown"] == data.impact.unknown
    assert payload["total_attempts"] == data.total_attempts


def test_write_report_emits_both_formats(run: Run, tmp_path) -> None:
    paths = write_report(_report(run), tmp_path)
    assert paths["json"].exists()
    assert paths["html"].exists()
    # 自包含:无外部资源,离线打开样式不丢。
    html = paths["html"].read_text(encoding="utf-8")
    assert "<link" not in html
    assert "src=" not in html
