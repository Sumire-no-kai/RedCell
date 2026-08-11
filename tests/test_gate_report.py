from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path

from typer.testing import CliRunner

from redcell._base import CostRecord
from redcell.arena.support_agent import SUPPORT_AGENT_POLICY
from redcell.arena.support_agent.benign import BENIGN_TASKS
from redcell.attacker_control import (
    AttackerControlConditions,
    AttackerControlReport,
    StrategySamples,
)
from redcell.budget import BudgetLimit, BudgetLimits, BudgetUsage
from redcell.cli import app
from redcell.controller import ControllerInvocation, ControllerInvocationStatus, UsageStatus
from redcell.controller_controls import (
    ControllerContractOutcome,
    ControllerContractReport,
    controller_contract_cases,
)
from redcell.controls import (
    DEFAULT_POSITIVE_REPEATS,
    POSITIVE_CASES,
    BenignViolation,
    BenignViolationDisposition,
    ControlOutcome,
    ControlsReport,
    build_controls_adjudication_template,
    controls_conditions,
)
from redcell.gate_analysis import GateCondition, SeedPlan, TokenPrefix, token_prefixes_from_events
from redcell.gate_report import GateVerdict, build_gate_report
from redcell.golden import evaluate_golden
from redcell.protocols import (
    ArenaRunConfiguration,
    ControllerRunConfiguration,
    ExperimentConditions,
    GenerationMemoryConfiguration,
    GenerationMemoryLimits,
    GenerationMemoryMode,
    ProviderRunConfiguration,
    Run,
    RunEvent,
    RunEventType,
    RunStatus,
    SearchConfiguration,
    SearchSelector,
    StrategyCatalogue,
)
from redcell.search import ControllerDecision, ControllerDecisionOutcome
from redcell.storage import RunStore
from redcell.strategies import PHASE_0_STRATEGIES
from redcell.validator import ReplayValidation, ValidationReport

runner = CliRunner()
FROZEN_PLAN = SeedPlan.model_validate_json(
    (Path(__file__).parents[1] / "docs" / "PHASE0_5_SEED_PLAN.json").read_text(encoding="utf-8")
)


def _provider(name: str) -> ProviderRunConfiguration:
    return ProviderRunConfiguration(
        provider=name,
        base_url=f"https://{name}.example.invalid/v1",
        model=f"{name}-model",
        temperature=0.0,
        max_tokens=512,
        rpm=60,
        max_concurrency=1,
        input_usd_per_mtok=0,
        output_usd_per_mtok=0,
    )


def _controller_configuration() -> ControllerRunConfiguration:
    return ControllerRunConfiguration(
        provider=_provider("controller"),
        connection_id="controller-frozen",
        connection_fingerprint="sha256:controller-frozen",
        prompt_version="controller-prompt-v1",
        evidence_policy_version="controller-evidence-v1",
        thinking_disabled=True,
    )


def _treatment(condition: GateCondition) -> tuple[SearchSelector, bool]:
    return {
        GateCondition.STATIC_OFF: (SearchSelector.STATIC, False),
        GateCondition.STATIC_MEMORY: (SearchSelector.STATIC, True),
        GateCondition.LLM_MEMORY: (SearchSelector.LLM, True),
        GateCondition.LLM_OFF: (SearchSelector.LLM, False),
        GateCondition.RANDOM_OFF: (SearchSelector.RANDOM, False),
        GateCondition.THOMPSON_OFF: (SearchSelector.THOMPSON, False),
    }[condition]


def _formal_run(seed: int, condition: GateCondition) -> Run:
    selector, memory_enabled = _treatment(condition)
    catalogue = StrategyCatalogue(
        version="phase0.5-v1", strategies=list(PHASE_0_STRATEGIES)
    ).condition_summary()
    memory = (
        GenerationMemoryConfiguration(
            mode=GenerationMemoryMode.BOUNDED_RELEVANT_V1,
            policy_version="bounded-relevant-v1",
            limits=GenerationMemoryLimits(),
        )
        if memory_enabled
        else GenerationMemoryConfiguration(mode=GenerationMemoryMode.OFF)
    )
    conditions = ExperimentConditions(
        online=True,
        actor="customer_a",
        target=_provider("target"),
        attacker=_provider("attacker"),
        arena=ArenaRunConfiguration(
            defense="standard",
            enforce_permissions=True,
            enforce_confirmation=True,
        ),
        strategy_catalogue=catalogue,
        search=SearchConfiguration(selector=selector),
        generation_memory=memory,
        controller=_controller_configuration() if selector is SearchSelector.LLM else None,
    )
    return Run(
        id=f"run-{seed}-{condition.value}",
        target_name=SUPPORT_AGENT_POLICY.target_name,
        policy_version=SUPPORT_AGENT_POLICY.version,
        adapter_type="support-agent-arena",
        algorithm=selector.value,
        limits=BudgetLimits(max_attempts=500, max_total_tokens=320000),
        usage=BudgetUsage(
            attempts=30,
            completed_attempts=30,
            successful_selections=7,
            prompt_tokens=200000,
            completion_tokens=120000,
            generator_prompt_tokens=100000,
            generator_completion_tokens=60000,
            target_prompt_tokens=100000,
            target_completion_tokens=60000,
        ),
        status=RunStatus.COMPLETED,
        stopped_by=BudgetLimit.TOKENS,
        seed=seed,
        strategy_ids=[strategy.id for strategy in PHASE_0_STRATEGIES],
        experiment_conditions=conditions,
    )


def _formal_prefixes(run: Run, checkpoints: Iterable[int]) -> list[TokenPrefix]:
    assert run.experiment_conditions is not None
    assert run.experiment_conditions.search is not None
    assert run.experiment_conditions.generation_memory is not None
    condition = next(
        item
        for item in GateCondition
        if _treatment(item)
        == (
            run.experiment_conditions.search.selector,
            run.experiment_conditions.generation_memory.mode
            is GenerationMemoryMode.BOUNDED_RELEVANT_V1,
        )
    )
    count = {
        GateCondition.STATIC_OFF: 1,
        GateCondition.STATIC_MEMORY: 2,
        GateCondition.LLM_MEMORY: 5,
        GateCondition.LLM_OFF: 2,
        GateCondition.RANDOM_OFF: 1,
        GateCondition.THOMPSON_OFF: 1,
    }[condition]
    attempts = {}
    successes = {}
    if condition is GateCondition.STATIC_OFF:
        attempts = {
            "multi_turn_trust_building": 10,
            "direct_instruction_override": 10,
            "encoding_obfuscation": 10,
        }
        successes = {strategy: 4 for strategy in attempts}
    selections = (
        {strategy.id: 1 for strategy in PHASE_0_STRATEGIES}
        if condition is GateCondition.LLM_MEMORY
        else {}
    )
    return [
        TokenPrefix(
            run_id=run.id,
            seed=run.seed or 0,
            condition=condition,
            checkpoint_tokens=checkpoint,
            committed_tokens=checkpoint,
            checkpoint_reached=True,
            attack_path_signatures={f"{run.id}:path-{index}" for index in range(count)},
            finding_categories={"prompt_injection", "unauthorized_tool_use"},
            attempts_by_strategy=attempts,
            successful_attempts_by_strategy=successes,
            selections_by_strategy=selections,
            valid=True,
        )
        for checkpoint in checkpoints
    ]


class _FormalStore:
    def __init__(self, runs: list[Run]) -> None:
        self._runs = runs
        self._invocations: dict[str, list[ControllerInvocation]] = {}
        self._decisions: dict[str, list[ControllerDecision]] = {}
        for run in runs:
            conditions = run.experiment_conditions
            if (
                conditions is None
                or conditions.search is None
                or conditions.search.selector is not SearchSelector.LLM
            ):
                continue
            invocations = []
            decisions = []
            for index, strategy in enumerate(run.strategy_ids):
                evidence_digest = f"evidence-{run.id}-{index}"
                invocation = ControllerInvocation(
                    id=f"invocation-{run.id}-{index}",
                    run_id=run.id,
                    logical_selection_index=index,
                    retry_index=0,
                    status=ControllerInvocationStatus.SUCCEEDED,
                    usage_status=UsageStatus.KNOWN,
                    evidence_digest=evidence_digest,
                    prompt_version="controller-prompt-v1",
                    response_digest=f"response-{run.id}-{index}",
                )
                invocations.append(invocation)
                decisions.append(
                    ControllerDecision(
                        attempt_index=index,
                        controller="llm",
                        available_strategy_ids=run.strategy_ids,
                        selected_strategy_id=strategy,
                        invocation_id=invocation.id,
                        decision_state={"evidence_digest": evidence_digest},
                        observed_score=0.5,
                        outcome=ControllerDecisionOutcome.COMPLETED,
                    )
                )
            self._invocations[run.id] = invocations
            self._decisions[run.id] = decisions

    def list_runs(self) -> list[Run]:
        return self._runs

    def events_for(self, _run_id: str) -> list:
        return []

    def findings_for(self, _run_id: str) -> list:
        return []

    def attempts_for(self, _run_id: str) -> list:
        return []

    def controller_invocations_for(self, run_id: str) -> list[ControllerInvocation]:
        return self._invocations.get(run_id, [])

    def decisions_for(self, run_id: str) -> list[ControllerDecision]:
        return self._decisions.get(run_id, [])


def test_empty_store_is_not_a_supported_gate(tmp_path) -> None:
    with RunStore(f"sqlite:///{tmp_path / 'gate.db'}") as store:
        report = build_gate_report(store)

    assert report.prefixes == []
    assert report.analysis.valid_seeds == []
    assert report.protection_failures == [
        "missing_attacker_control",
        "missing_controller_controls",
        "missing_controls",
        "missing_level1_golden",
        "missing_seed_plan",
        "missing_validation",
        "no_phase_0_5_prefixes",
    ]
    assert not report.supported
    assert report.verdict is GateVerdict.INCOMPLETE


def test_prefix_projection_reads_a_real_cli_event_stream(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    db = f"sqlite:///{tmp_path / 'gate.db'}"
    result = runner.invoke(app, ["run", "--budget", "1", "--db", db])
    assert result.exit_code == 0, result.output
    with RunStore(db) as store:
        run = store.list_runs()[0]
        prefixes = token_prefixes_from_events(
            run=run, events=store.events_for(run.id), findings=store.findings_for(run.id)
        )

    assert [prefix.condition for prefix in prefixes] == [GateCondition.STATIC_OFF] * 3
    assert [prefix.checkpoint_tokens for prefix in prefixes] == [64000, 160000, 320000]


def test_prefix_cost_includes_usage_that_did_not_form_an_attempt() -> None:
    run = _formal_run(0, GateCondition.LLM_MEMORY)
    events = [
        RunEvent(
            run_id=run.id,
            event_type=RunEventType.DECISION_SELECTED,
            attempt_id="attempt-over-checkpoint",
            sequence=0,
            payload={
                "decision": {"selected_strategy_id": run.strategy_ids[0]},
                "usage": {"prompt_tokens": 70000, "completion_tokens": 30000},
            },
        ),
        RunEvent(
            run_id=run.id,
            event_type=RunEventType.SELECTION_ABANDONED,
            sequence=1,
            payload={"usage": {"prompt_tokens": 100000, "completion_tokens": 50000}},
        ),
        RunEvent(
            run_id=run.id,
            event_type=RunEventType.ATTEMPT_COMMITTED,
            attempt_id="attempt-over-checkpoint",
            sequence=2,
            payload={
                "finding_ids": [],
                "usage": {"prompt_tokens": 110000, "completion_tokens": 60000},
            },
        ),
        RunEvent(
            run_id=run.id,
            event_type=RunEventType.RUN_COMPLETED,
            sequence=3,
            payload={"usage": run.usage.model_dump(mode="json")},
        ),
    ]

    prefix = token_prefixes_from_events(run=run, events=events, findings=[], checkpoints=(160000,))[
        0
    ]

    assert prefix.committed_tokens == 150000
    assert prefix.selections_by_strategy == {run.strategy_ids[0]: 1}


def test_prefix_projection_fails_closed_when_a_usage_event_has_no_snapshot() -> None:
    run = _formal_run(0, GateCondition.STATIC_OFF)
    events = [
        RunEvent(
            run_id=run.id,
            event_type=RunEventType.ATTEMPT_COMMITTED,
            attempt_id="attempt-without-usage",
            sequence=0,
            payload={"finding_ids": []},
        ),
        RunEvent(
            run_id=run.id,
            event_type=RunEventType.RUN_COMPLETED,
            sequence=1,
            payload={"usage": run.usage.model_dump(mode="json")},
        ),
    ]

    prefix = token_prefixes_from_events(run=run, events=events, findings=[], checkpoints=(160000,))[
        0
    ]

    assert not prefix.valid


def test_gate_rejects_an_empty_controls_report(tmp_path) -> None:
    with RunStore(f"sqlite:///{tmp_path / 'gate.db'}") as store:
        report = build_gate_report(
            store, controls=ControlsReport(), validation=ValidationReport(repeats=5)
        )

    assert "controls_shape_invalid" in report.protection_failures


def test_gate_report_cli_loads_protection_evidence(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    controls = ControlsReport(
        positive=[
            ControlOutcome(id=f"positive-{index}", passed=True, detail="ok") for index in range(3)
        ],
        negative=[
            ControlOutcome(
                id=f"negative-{index}", passed=True, detail="ok", runs=5, completed_runs=4
            )
            for index in range(10)
        ],
    )
    controls_path = tmp_path / "controls.json"
    controls_path.write_text(controls.model_dump_json(), encoding="utf-8")
    validation_path = tmp_path / "validation.json"
    validation_path.write_text(ValidationReport(repeats=5).model_dump_json(), encoding="utf-8")
    seed_path = tmp_path / "seed-plan.json"
    seed_path.write_text(
        '{"primary":[100,101,102,103,104,105,106,107,108,109,110,111],"reserve":[112,113,114,115,116,117,118,119]}',
        encoding="utf-8",
    )

    result = runner.invoke(
        app,
        [
            "gate-report",
            "--db",
            f"sqlite:///{tmp_path / 'gate.db'}",
            "--controls-json",
            str(controls_path),
            "--validation-json",
            str(validation_path),
            "--seed-plan-json",
            str(seed_path),
        ],
    )

    assert result.exit_code == 0, result.output
    assert "INCOMPLETE" in result.output


def test_complete_formal_evidence_can_support_the_gate(monkeypatch) -> None:
    runs = [
        _formal_run(seed, condition) for seed in FROZEN_PLAN.primary for condition in GateCondition
    ]
    store = _FormalStore(runs)
    monkeypatch.setattr(
        "redcell.gate_report.token_prefixes_from_events",
        lambda *, run, events, findings, checkpoints: _formal_prefixes(run, checkpoints),
    )
    reference = runs[0].experiment_conditions
    assert reference is not None
    assert reference.strategy_catalogue is not None
    controller = next(
        run.experiment_conditions.controller
        for run in runs
        if run.experiment_conditions is not None
        and run.experiment_conditions.controller is not None
    )
    conditions = controls_conditions(target=reference.target)
    utility_context_fingerprint = conditions.utility_context_fingerprint()
    monkeypatch.setattr(
        "redcell.gate_report.PHASE0_UTILITY_BASELINE_CONTEXT_FINGERPRINT",
        utility_context_fingerprint,
    )
    controls = ControlsReport(
        positive=[
            ControlOutcome(id=case.id, passed=True, detail="passed", runs=DEFAULT_POSITIVE_REPEATS)
            for case in POSITIVE_CASES
        ],
        negative=[
            ControlOutcome(
                id=task.id,
                passed=True,
                detail="passed",
                runs=5,
                completed_runs=4,
            )
            for task in BENIGN_TASKS
        ],
        conditions=conditions,
        utility_context_fingerprint=utility_context_fingerprint,
    )
    brief = SUPPORT_AGENT_POLICY.brief_for(reference.actor)
    attacker_conditions = AttackerControlConditions.build(
        attacker=reference.attacker,
        strategy_catalogue=reference.strategy_catalogue,
        brief=brief,
        samples_per_strategy=5,
        seed=99,
    )
    attacker_control = AttackerControlReport(
        samples=[
            StrategySamples(
                strategy_id=strategy.id,
                messages=[f"{strategy.id} sample {index}" for index in range(5)],
            )
            for strategy in reference.strategy_catalogue.strategies
        ],
        within_similarity=0.8,
        between_similarity=0.1,
        conditions=attacker_conditions,
    )
    controller_controls = ControllerContractReport(
        outcomes=[
            ControllerContractOutcome(
                id=case.id,
                passed=True,
                first_pass=True,
                known_usage=True,
                repaired=False,
            )
            for case in controller_contract_cases()
        ],
        controller=controller,
    )
    prefixes_320 = [prefix for run in runs for prefix in _formal_prefixes(run, [320000])]
    validation = ValidationReport(
        repeats=5,
        results=[
            ReplayValidation(
                run_id=prefix.run_id,
                attack_path=path,
                runs=5,
                reproduced=4,
            )
            for prefix in prefixes_320
            for path in sorted(prefix.attack_path_signatures)
        ],
        target_usage=CostRecord(prompt_tokens=1, usage_known=True),
        target_configuration=reference.target,
        gate_context_fingerprint=runs[0].gate_context_fingerprint(),
        run_ids=sorted(run.id for run in runs),
    )

    golden = evaluate_golden(Path(__file__).parent / "fixtures" / "level1-golden-v2.json")
    seed_plan = FROZEN_PLAN
    report = build_gate_report(  # type: ignore[arg-type]
        store,
        controls=controls,
        golden=golden,
        attacker_control=attacker_control,
        controller_controls=controller_controls,
        validation=validation,
        seed_plan=seed_plan,
    )

    assert report.analysis.valid_seeds == FROZEN_PLAN.primary
    assert report.analysis.mechanism is not None
    assert report.analysis.mechanism.selector_main_effect.passed
    assert report.analysis.mechanism.memory_main_effect.passed
    assert report.protection_failures == []
    assert any("strategy_id" in limitation for limitation in report.limitations)
    assert report.supported
    assert report.verdict is GateVerdict.SUPPORTED

    missing_utility_context = build_gate_report(  # type: ignore[arg-type]
        store,
        controls=controls.model_copy(update={"utility_context_fingerprint": None}),
        golden=golden,
        attacker_control=attacker_control,
        controller_controls=controller_controls,
        validation=validation,
        seed_plan=seed_plan,
    )
    assert "controls_utility_context_missing" in missing_utility_context.protection_failures
    assert missing_utility_context.verdict is GateVerdict.INCOMPLETE

    monkeypatch.setattr("redcell.gate_report.PHASE0_UTILITY_BASELINE_CONTEXT_FINGERPRINT", "f" * 64)
    changed_utility_context = build_gate_report(  # type: ignore[arg-type]
        store,
        controls=controls,
        golden=golden,
        attacker_control=attacker_control,
        controller_controls=controller_controls,
        validation=validation,
        seed_plan=seed_plan,
    )
    assert "utility_baseline_context_mismatch" in changed_utility_context.protection_failures
    assert changed_utility_context.verdict is GateVerdict.EXPERIMENT_INVALID
    monkeypatch.setattr(
        "redcell.gate_report.PHASE0_UTILITY_BASELINE_CONTEXT_FINGERPRINT",
        utility_context_fingerprint,
    )

    negative_with_raw = list(controls.negative)
    negative_with_raw[0] = negative_with_raw[0].model_copy(
        update={
            "passed": False,
            "detail": "raw Finding; independent adjudication required",
            "violations": [
                BenignViolation(
                    category="unauthorized_tool_use",
                    signature="a" * 64,
                    title="Repeated a gated call before a new user turn",
                    attempted=True,
                    realized_impact="not_realized",
                    turn_index=0,
                    repeat_index=0,
                )
            ],
        }
    )
    controls_with_raw = controls.model_copy(update={"negative": negative_with_raw})
    template = build_controls_adjudication_template(controls_with_raw)

    missing_adjudication_report = build_gate_report(  # type: ignore[arg-type]
        store,
        controls=controls_with_raw,
        golden=golden,
        attacker_control=attacker_control,
        controller_controls=controller_controls,
        validation=validation,
        seed_plan=seed_plan,
    )
    assert "controls_adjudication_missing" in missing_adjudication_report.protection_failures
    assert missing_adjudication_report.verdict is GateVerdict.INCOMPLETE

    unresolved_report = build_gate_report(  # type: ignore[arg-type]
        store,
        controls=controls_with_raw,
        controls_adjudication=template,
        golden=golden,
        attacker_control=attacker_control,
        controller_controls=controller_controls,
        validation=validation,
        seed_plan=seed_plan,
    )
    assert "controls_adjudication_unresolved" in unresolved_report.protection_failures
    assert unresolved_report.verdict is GateVerdict.INCOMPLETE

    mismatched_occurrence = template.items[0].occurrence.model_copy(update={"signature": "b" * 64})
    mismatched_item = template.items[0].model_copy(update={"occurrence": mismatched_occurrence})
    mismatched_adjudication_report = build_gate_report(  # type: ignore[arg-type]
        store,
        controls=controls_with_raw,
        controls_adjudication=template.model_copy(update={"items": [mismatched_item]}),
        golden=golden,
        attacker_control=attacker_control,
        controller_controls=controller_controls,
        validation=validation,
        seed_plan=seed_plan,
    )
    assert "controls_adjudication_mismatch" in mismatched_adjudication_report.protection_failures
    assert mismatched_adjudication_report.verdict is GateVerdict.EXPERIMENT_INVALID

    target_item = template.items[0].model_copy(
        update={
            "disposition": BenignViolationDisposition.TARGET_SPONTANEOUS_VIOLATION,
            "rationale": "Independent Trace review confirms a same-turn repeat.",
            "evidence_summary": "Two same-argument calls in turn 0; second rejected.",
        }
    )
    target_adjudication = template.model_copy(update={"items": [target_item]})
    target_report = build_gate_report(  # type: ignore[arg-type]
        store,
        controls=controls_with_raw,
        controls_adjudication=target_adjudication,
        golden=golden,
        attacker_control=attacker_control,
        controller_controls=controller_controls,
        validation=validation,
        seed_plan=seed_plan,
    )
    assert target_report.metrics.controls is not None
    assert target_report.metrics.controls.target_spontaneous_violations == 1
    assert not any(failure.startswith("controls_") for failure in target_report.protection_failures)
    assert target_report.supported

    false_positive_item = target_item.model_copy(
        update={"disposition": BenignViolationDisposition.DETECTOR_FALSE_POSITIVE}
    )
    false_positive_report = build_gate_report(  # type: ignore[arg-type]
        store,
        controls=controls_with_raw,
        controls_adjudication=template.model_copy(update={"items": [false_positive_item]}),
        golden=golden,
        attacker_control=attacker_control,
        controller_controls=controller_controls,
        validation=validation,
        seed_plan=seed_plan,
    )
    assert "controls_detector_false_positive" in false_positive_report.protection_failures
    assert false_positive_report.verdict is GateVerdict.EXPERIMENT_INVALID

    mismatched_validation = validation.model_copy(update={"gate_context_fingerprint": "f" * 64})
    mismatched = build_gate_report(  # type: ignore[arg-type]
        store,
        controls=controls,
        golden=golden,
        attacker_control=attacker_control,
        controller_controls=controller_controls,
        validation=mismatched_validation,
        seed_plan=seed_plan,
    )
    assert "validation_environment_mismatch" in mismatched.protection_failures
    assert mismatched.verdict is GateVerdict.EXPERIMENT_INVALID

    missing_golden_outcomes = build_gate_report(  # type: ignore[arg-type]
        store,
        controls=controls,
        golden=golden.model_copy(update={"outcomes": []}),
        attacker_control=attacker_control,
        controller_controls=controller_controls,
        validation=validation,
        seed_plan=seed_plan,
    )
    assert "level1_golden_outcomes_shape_invalid" in missing_golden_outcomes.protection_failures

    unsupported_analysis = report.analysis.model_copy(
        update={
            "comparisons": [
                comparison.model_copy(update={"mean_difference": 0.0})
                for comparison in report.analysis.comparisons
            ]
        }
    )
    assert (
        report.model_copy(update={"analysis": unsupported_analysis}).verdict
        is GateVerdict.NOT_SUPPORTED
    )
    assert (
        report.model_copy(update={"protection_failures": ["static_off_asr_drift"]}).verdict
        is GateVerdict.EXPERIMENT_INVALID
    )
