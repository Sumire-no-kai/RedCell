from __future__ import annotations

import json

import pytest

from redcell.budget import BudgetLimit, BudgetLimits
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
from redcell.protocols.run import Run, RunEvent, RunEventType, RunStatus
from redcell.report import DISCLAIMER, ReportData, to_html, to_json, write_report
from redcell.search import ControllerDecision, ControllerDecisionOutcome
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


def _basis_for(impact: ImpactStatus) -> ImpactBasis | None:
    """协议要求:断言了 impact 必须给证据来源,UNKNOWN 则必须没有。"""
    if impact is ImpactStatus.UNKNOWN:
        return None
    return ImpactBasis.SIDE_EFFECT


def _finding(attempt, impact: ImpactStatus, **kwargs) -> Finding:
    observability = kwargs.pop(
        "observability",
        (
            ObservabilityLevel.FULL
            if impact is not ImpactStatus.UNKNOWN
            else ObservabilityLevel.PARTIAL
        ),
    )
    return Finding(
        run_id=attempt.run_id,
        attempt_id=attempt.id,
        category=VulnerabilityCategory.UNAUTHORIZED_TOOL_USE,
        title="跨用户读取",
        actor="customer_a",
        strategy_id=attempt.strategy_id,
        triad=ViolationTriad(
            attempted_action=True,
            realized_impact=impact,
            impact_basis=_basis_for(impact),
        ),
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
    attempt = _attempt(run.id, "s1", 1.0)
    finding = _finding(attempt, ImpactStatus.REALIZED)
    store.save_finding(finding)

    loaded = store.findings_for(run.id)
    assert loaded[0].model_dump(mode="json") == finding.model_dump(mode="json")


def test_save_is_idempotent(store: RunStore, run: Run) -> None:
    """Run 会随执行推进多次落盘,重复写不能变成重复行。"""
    store.save_run(run)
    store.save_run(run.model_copy(update={"status": RunStatus.COMPLETED}))
    assert len(store.list_runs()) == 1


def _completed_decision(strategy_id: str = "s1") -> ControllerDecision:
    return ControllerDecision(
        attempt_index=0,
        controller="static",
        available_strategy_ids=[strategy_id],
        selected_strategy_id=strategy_id,
        observed_score=1.0,
        outcome=ControllerDecisionOutcome.COMPLETED,
    )


def test_atomic_attempt_commit_is_idempotent(store: RunStore, run: Run) -> None:
    store.save_run(run)
    attempt = _attempt(run.id, "s1", 1.0)
    finding = _finding(attempt, ImpactStatus.REALIZED)
    event = RunEvent(
        run_id=run.id,
        attempt_id=attempt.id,
        event_type=RunEventType.ATTEMPT_COMMITTED,
        sequence=0,
    )

    for _ in range(2):
        store.commit_attempt_outcome(
            run=run,
            attempt=attempt,
            findings=[finding],
            decision=_completed_decision(),
            run_event=event,
        )

    assert len(store.attempts_for(run.id)) == 1
    assert len(store.findings_for(run.id)) == 1
    assert len(store.decisions_for(run.id)) == 1
    assert len(store.events_for(run.id)) == 1


def test_atomic_attempt_commit_rolls_back_every_row(
    store: RunStore,
    run: Run,
    monkeypatch,
) -> None:
    store.save_run(run)
    attempt = _attempt(run.id, "s1", 1.0)
    finding = _finding(attempt, ImpactStatus.REALIZED)
    event = RunEvent(
        run_id=run.id,
        attempt_id=attempt.id,
        event_type=RunEventType.ATTEMPT_COMMITTED,
        sequence=0,
    )

    def fail_after_attempt_merge(_session, _finding) -> None:
        raise RuntimeError("simulated disk failure")

    monkeypatch.setattr(store, "_merge_finding", fail_after_attempt_merge)

    with pytest.raises(RuntimeError, match="simulated disk failure"):
        store.commit_attempt_outcome(
            run=run,
            attempt=attempt,
            findings=[finding],
            decision=_completed_decision(),
            run_event=event,
        )

    assert store.attempts_for(run.id) == []
    assert store.findings_for(run.id) == []
    assert store.decisions_for(run.id) == []
    assert store.events_for(run.id) == []


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


def test_success_rates_come_from_triad_not_numeric_score(store: RunStore, run: Run) -> None:
    store.save_run(run)
    blocked = _attempt(run.id, "s1", 0.7)
    realized = _attempt(run.id, "s1", 1.0)
    numeric_only = _attempt(run.id, "s2", 1.0)
    unknown = _attempt(run.id, "s2", 0.4)
    store.save_attempts([blocked, realized, numeric_only, unknown])
    store.save_findings(
        [
            _finding(blocked, ImpactStatus.NOT_REALIZED),
            _finding(realized, ImpactStatus.REALIZED),
            _finding(unknown, ImpactStatus.UNKNOWN),
        ]
    )

    assert store.attempt_success_rate(run.id) == {"s1": 1.0, "s2": 0.5}
    assert store.impact_success_rate(run.id) == {"s1": 0.5, "s2": 0.0}


def test_queries_to_first_successes_return_none_when_never_successful(
    store: RunStore, run: Run
) -> None:
    """⚠️ 未成功时返回 None,不返回预算值。

    用预算值顶替会把删失观测混进普通观测,均值被系统性拉低。
    """
    store.save_run(run)
    # 即使数字是 1.0,没有 triad 证据也不是成功。
    store.save_attempts([_attempt(run.id, "s1", 1.0) for _ in range(5)])
    assert store.queries_to_first_attempt_success(run.id) is None
    assert store.queries_to_first_impact_success(run.id) is None


def test_queries_to_first_successes_have_explicit_semantics(store: RunStore, run: Run) -> None:
    store.save_run(run)
    none = _attempt(run.id, "s1", 1.0)
    blocked = _attempt(run.id, "s1", 0.7)
    realized = _attempt(run.id, "s1", 0.2)
    store.save_attempts([none, blocked, realized])
    store.save_findings(
        [
            _finding(blocked, ImpactStatus.NOT_REALIZED),
            _finding(realized, ImpactStatus.REALIZED),
        ]
    )

    assert store.queries_to_first_attempt_success(run.id) == 2
    assert store.queries_to_first_impact_success(run.id) == 3


# ── 报告 ─────────────────────────────────────────────────────────────────


def _report(run: Run) -> ReportData:
    attempts = [
        _attempt(run.id, "s1", 1.0),
        _attempt(run.id, "s1", 0.7),
        _attempt(run.id, "s2", 0.4),
    ]
    findings = [
        _finding(attempts[1], ImpactStatus.REALIZED),
        # 同一个 attempt 的多个 Finding 不能重复抬高 ASR。
        _finding(attempts[1], ImpactStatus.NOT_REALIZED),
        _finding(attempts[2], ImpactStatus.UNKNOWN),
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
    assert by_id["s1"].attempt_hits == 1
    assert by_id["s1"].impact_hits == 1
    assert by_id["s1"].attempt_success_rate == pytest.approx(0.5)
    assert by_id["s1"].impact_success_rate == pytest.approx(0.5)
    assert by_id["s2"].attempt_success_rate == 1.0
    assert by_id["s2"].impact_success_rate == 0.0
    assert data.budget_share["s1"] == pytest.approx(2 / 3)
    assert data.queries_to_first_attempt_success == 2
    assert data.queries_to_first_impact_success == 2
    assert data.logical_attempts == data.total_attempts == 3
    assert data.abandoned_attempts == 0
    assert data.execution_retries == 0


def test_report_surfaces_operational_failures(run: Run) -> None:
    run_with_failures = run.model_copy(
        update={
            "usage": run.usage.model_copy(
                update={
                    "attempts": 4,
                    "completed_attempts": 3,
                    "abandoned_attempts": 1,
                    "retries": 2,
                }
            )
        }
    )
    data = _report(run_with_failures)

    assert data.logical_attempts == 4
    assert data.total_attempts == 3
    assert data.abandoned_attempts == 1
    assert data.execution_retries == 2
    assert "excluded from ASR" in to_html(data)


def test_report_reports_never_succeeded_as_null(run: Run) -> None:
    data = ReportData.build(run, [_attempt(run.id, "s1", 1.0)], [])
    assert data.queries_to_first_attempt_success is None
    assert data.queries_to_first_impact_success is None


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
    assert payload["strategy_stats"][0]["attempt_hits"] == 1
    assert payload["strategy_stats"][0]["impact_hits"] == 1
    assert payload["strategy_stats"][0]["attempt_success_rate"] == pytest.approx(0.5)
    assert payload["strategy_stats"][0]["impact_success_rate"] == pytest.approx(0.5)
    assert "hits" not in payload["strategy_stats"][0]
    assert "Attempt ASR" in to_html(data)
    assert "Impact ASR" in to_html(data)


def test_write_report_emits_both_formats(run: Run, tmp_path) -> None:
    paths = write_report(_report(run), tmp_path)
    assert paths["json"].exists()
    assert paths["html"].exists()
    # 自包含:无外部资源,离线打开样式不丢。
    html = paths["html"].read_text(encoding="utf-8")
    assert "<link" not in html
    assert "src=" not in html
