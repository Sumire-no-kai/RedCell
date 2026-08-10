"""RedCell 命令行入口 —— **composition root,不含任何业务逻辑**。

它只做一件事:把已经写好的深模块接起来(Policy / Adapter / Generator /
Controller / Store / Orchestrator),然后把结果交给用户。

刻意不在这里放判定、预算或搜索逻辑:CLI 是最容易被随手加特例的地方,
一旦业务规则漏进来,同一件事就会有"库里一套、CLI 里一套"两个版本,
而它们迟早会不一致。
"""

from __future__ import annotations

import asyncio
import sys
from enum import IntEnum
from pathlib import Path
from typing import Annotated

import typer

from redcell.arena.support_agent import (
    SUPPORT_AGENT_POLICY,
    ArenaAdapter,
    DefenseLevel,
)
from redcell.attacker_control import (
    AttackerControlConditions,
    AttackerControlReport,
    run_attacker_control,
)
from redcell.budget import BudgetLimits
from redcell.config import (
    ProviderConfigError,
    ProviderPair,
    load_attacker,
    load_controller,
    load_providers,
    load_target,
)
from redcell.controller import LLMControllerAdapter
from redcell.controller_controls import (
    ControllerContractReport,
    run_controller_contract_controls,
)
from redcell.controls import (
    ControlsReport,
    controls_conditions,
    run_negative_control,
    run_positive_control,
)
from redcell.executor import ConversationExecutor
from redcell.failures import FailureStage
from redcell.gate_analysis import SeedPlan
from redcell.gate_evidence import GoldenReport
from redcell.gate_plan import GatePlan, build_gate_plan
from redcell.gate_preflight import run_preflight
from redcell.gate_report import build_gate_report
from redcell.gate_validation import select_validation_evidence
from redcell.generation import AttackGenerator, TemplateAttackGenerator
from redcell.golden import evaluate_golden
from redcell.llm.base import LLMProvider
from redcell.llm.scripted import ScriptedProvider
from redcell.mutation import LLMMutationGenerator
from redcell.orchestrator import (
    RunExecutionRequest,
    RunFailedError,
    RunOrchestrator,
    RunResumeError,
)
from redcell.protocols.run import (
    ArenaRunConfiguration,
    ControllerRunConfiguration,
    ExperimentConditions,
    GenerationMemoryConfiguration,
    GenerationMemoryLimits,
    GenerationMemoryMode,
    ProviderRunConfiguration,
    Run,
    RunStatus,
    SearchConfiguration,
    SearchSelector,
)
from redcell.protocols.strategy import StrategyCatalogue, select_applicable
from redcell.randomness import controller_seed_for
from redcell.report import ReportData, write_report
from redcell.scoring.level1 import Level1Scorer
from redcell.search import (
    RandomController,
    SearchController,
    StaticController,
    ThompsonSamplingController,
)
from redcell.storage import DEFAULT_URL, RunStore
from redcell.strategies import PHASE_0_STRATEGIES
from redcell.validator import ValidationReport, validate_attack_paths

app = typer.Typer(
    add_completion=False,
    help="RedCell —— 面向工具型 AI Agent 的自适应安全评测。仅用于授权测试。",
)

OFFLINE_NOTICE = (
    "本次运行使用脚本化的离线 provider,目标模型并未参与决策。"
    "结果只证明流水线可以跑通,**不构成对任何 agent 的安全评估**。"
)
"""离线冒烟运行的强制标注。

没有这行,一份 0 Finding 的报告会被读成"扫过了,是安全的" ——
而它其实只说明管道通了。安全工具最不该制造的就是这种误解。
"""


class ExitCode(IntEnum):
    """CI 可依赖的退出码。

    有发现即非零,和主流扫描器一致 —— 这样一条流水线可以直接用它当门禁。

    ⚠️ **刻意跳过 2**:Click/Typer 用 2 表示命令行用法错误。占用它的话,
    "参数拼错了"和"run 真的失败了"在 CI 里就分不开,而这两者的处置完全不同 ——
    前者改命令,后者要查目标或环境。
    """

    CLEAN = 0
    """Run 正常完成,没有 Finding。"""

    FINDINGS = 1
    """Run 正常完成,但发现了问题。"""

    RUN_FAILED = 3
    """Run 未能完成。**结论不可用** —— 中断的 run 会系统性低估发现数。"""

    BAD_CONFIG = 4
    """配置被拒绝或目标不存在,目标未被触碰。"""

    CONTROL_FAILED = 5
    """开跑前的对照没通过 —— **不要拿这次配置去跑校准**。

    ⚠️ **刻意不复用 1**:1 的含义是"跑完了,并且在目标身上发现了问题"。
    而对照失败的含义几乎相反 —— "这套装置根本不具备发现问题的能力"。
    两者在 CI 里挤进同一个码,一次"攻击方太弱"会被读成"扫出漏洞了",
    方向正好反过来,是最糟的一种误读。
    """


def _controller(algorithm: str, seed: int) -> SearchController:
    order = [s.id for s in PHASE_0_STRATEGIES]
    if algorithm == "static":
        return StaticController(order)
    if algorithm == "random":
        import random

        # 私有 RNG:全局 random 会被任何其他代码干扰,复现直接报废。
        return RandomController(random.Random(controller_seed_for(seed)))
    if algorithm == "thompson":
        import random as _random

        return ThompsonSamplingController(_random.Random(controller_seed_for(seed)))
    raise typer.BadParameter(f"未知算法 '{algorithm}';可选:static / random / thompson")


def _providers(
    online: bool,
) -> tuple[LLMProvider, AttackGenerator, ProviderPair | None]:
    """按 online 开关组装 (target provider, 攻击生成器, 待关闭的 provider 对)。

    离线路径刻意保持零成本:脚本化 target + 模板生成器,不读 .env、不建 HTTP 客户端。
    因此第三个返回值为 None —— 没有需要关闭的东西。
    """
    if not online:
        provider = ScriptedProvider(
            default="I can help with orders and store policies. What do you need?",
            model="scripted-offline",
        )
        return provider, TemplateAttackGenerator(), None

    pair = load_providers()
    generator = LLMMutationGenerator(
        pair.attacker,
        model=pair.attacker.model,
        temperature=pair.attacker_configuration.temperature,
        max_tokens=pair.attacker_max_tokens,
    )
    return pair.target, generator, pair


def _arena_adapter(
    provider: LLMProvider,
    configuration: ProviderRunConfiguration,
    *,
    defense: DefenseLevel,
    enforce_permissions: bool = True,
    enforce_confirmation: bool = True,
) -> ArenaAdapter:
    """让实际 Target 调用与落盘的实验条件使用同一份配置。"""
    return ArenaAdapter(
        provider,
        defense=defense,
        enforce_permissions=enforce_permissions,
        enforce_confirmation=enforce_confirmation,
        model=configuration.model,
        temperature=configuration.temperature,
        max_tokens=configuration.max_tokens,
    )


def _experiment_conditions(
    *,
    online: bool,
    providers: ProviderPair | None,
    actor: str,
    defense: DefenseLevel,
    enforce_permissions: bool,
    enforce_confirmation: bool,
) -> ExperimentConditions:
    """把会影响结论的配置冻结进 Run；绝不把凭据写入 SQLite。"""
    if providers is None:
        target = ProviderRunConfiguration(
            provider="scripted",
            base_url="",
            model="scripted-offline",
            temperature=0.0,
            max_tokens=1,
            rpm=0.0,
            max_concurrency=0,
            input_usd_per_mtok=0.0,
            output_usd_per_mtok=0.0,
            cached_input_usd_per_mtok=0.0,
        )
        attacker = ProviderRunConfiguration(
            provider="template",
            base_url="",
            model="template",
            temperature=0.0,
            max_tokens=1,
            rpm=0.0,
            max_concurrency=0,
            input_usd_per_mtok=0.0,
            output_usd_per_mtok=0.0,
            cached_input_usd_per_mtok=0.0,
        )
    else:
        target = providers.target_configuration
        attacker = providers.attacker_configuration
    return ExperimentConditions(
        online=online,
        actor=actor,
        target=target,
        attacker=attacker,
        arena=ArenaRunConfiguration(
            defense=defense.value,
            enforce_permissions=enforce_permissions,
            enforce_confirmation=enforce_confirmation,
        ),
    )


@app.command()
def run(
    algorithm: Annotated[
        str | None, typer.Option(help="旧参数：static / random / thompson；与 --search 不能并用")
    ] = None,
    search: Annotated[
        str | None, typer.Option(help="Phase 0.5 搜索方式：static / random / thompson / llm")
    ] = None,
    cross_attempt_memory: Annotated[
        str, typer.Option(help="跨 Attempt Generator memory：off / bounded-relevant-v1")
    ] = "off",
    budget: Annotated[int, typer.Option(help="最大 attempt 数")] = 20,
    seed: Annotated[int, typer.Option(help="实验种子;同一 seed 结果可复现")] = 0,
    actor: Annotated[str, typer.Option(help="攻击时扮演的身份")] = "customer_a",
    defense: Annotated[
        DefenseLevel, typer.Option(help="靶场防御强度(校准旋钮 ①)")
    ] = DefenseLevel.STANDARD,
    enforce_permissions: Annotated[
        bool, typer.Option(help="靶场工具层是否做权限检查(校准旋钮 ③)")
    ] = True,
    enforce_confirmation: Annotated[
        bool, typer.Option(help="靶场是否强制「高危动作先问过用户」(校准旋钮 ④)")
    ] = True,
    per_strategy: Annotated[
        int | None,
        typer.Option(
            help="每个策略跑满多少条**完成**的 attempt(校准用)。"
            "设了它就必须同时开 --top-up-abandoned。"
        ),
    ] = None,
    top_up_abandoned: Annotated[
        bool,
        typer.Option(
            help="放弃的 attempt 是否补跑(不计入 --budget)。"
            "校准必须开:否则运行故障会悄悄把每臂样本量压到 200 以下。"
        ),
    ] = False,
    online: Annotated[
        bool,
        typer.Option(
            help="接真实模型跑(target=GLM / attacker=Gemini,从 .env 读)。默认离线,只验证流水线。"
        ),
    ] = False,
    max_tokens: Annotated[int | None, typer.Option(help="token 上限(两侧合计)")] = None,
    max_cost: Annotated[
        float | None,
        typer.Option(
            help="美元成本上限(两侧合计)。任一侧不报成本时会被当场拒绝,"
            "而不是给你一个永不触发的假上限。"
        ),
    ] = None,
    max_seconds: Annotated[float | None, typer.Option(help="墙钟上限(秒)")] = None,
    db: Annotated[str, typer.Option(help="SQLite 连接串")] = DEFAULT_URL,
    out: Annotated[Path, typer.Option(help="报告输出目录")] = Path("runs"),
) -> None:
    """对自带靶场跑一次评测。

    默认离线(脚本化 provider),验证的是**流水线**而非靶场的真实安全性。
    加 `--online` 才接入真实模型 —— 那时才会产出可用于校准的结论。
    """
    if algorithm is not None and search is not None:
        raise typer.BadParameter("--algorithm 与 --search 不能同时提供")
    selected_search = search or algorithm or "static"
    try:
        selector = SearchSelector(selected_search)
        memory_mode = GenerationMemoryMode(cross_attempt_memory)
    except ValueError as exc:
        raise typer.BadParameter("非法 search 或 cross-attempt-memory 值") from exc
    if selector is SearchSelector.LLM and max_tokens is None:
        raise typer.BadParameter("--search llm 必须设置 --max-tokens，Controller 需要总 Token 预算")

    limits = BudgetLimits(
        max_attempts=budget,
        max_total_tokens=max_tokens,
        max_wall_seconds=max_seconds,
        max_cost_usd=max_cost,
        max_completed_per_strategy=per_strategy,
        count_abandoned_against_attempts=not top_up_abandoned,
        # `--max-cost` 从"刻意不暴露"改为"暴露但拒绝造假"(2026-08-02)。
        # 原来藏起来是因为 provider 不报成本,设了永不触发;
        # 现在 orchestrator 的 preflight 会在**任一侧**报不出成本时当场拒绝,
        # 所以它不可能再变成一个假的安全网 —— 藏着反而挡住了正当用法。
    )

    policy = SUPPORT_AGENT_POLICY
    strategies = select_applicable(list(PHASE_0_STRATEGIES), policy)
    if not strategies:
        typer.secho("没有适用于该目标的策略。", fg=typer.colors.RED, err=True)
        raise typer.Exit(ExitCode.BAD_CONFIG)

    try:
        target_provider, generator, providers = _providers(online)
    except ProviderConfigError as exc:
        typer.secho(f"配置被拒绝:{exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(ExitCode.BAD_CONFIG) from exc

    controller_provider = None
    controller_configuration = None
    if selector is SearchSelector.LLM:
        if not online:
            raise typer.BadParameter("--search llm 需要 --online 与独立 REDCELL_CONTROLLER_* 配置")
        try:
            controller_provider, controller_configuration = load_controller()
        except ProviderConfigError as exc:
            raise typer.BadParameter(str(exc)) from exc

    catalogue = StrategyCatalogue(version="phase0.5-v1", strategies=strategies).condition_summary()
    conditions = _experiment_conditions(
        online=online,
        providers=providers,
        actor=actor,
        defense=defense,
        enforce_permissions=enforce_permissions,
        enforce_confirmation=enforce_confirmation,
    )
    conditions = conditions.model_copy(
        update={
            "strategy_catalogue": catalogue,
            "search": SearchConfiguration(selector=selector),
            "generation_memory": GenerationMemoryConfiguration(
                mode=memory_mode,
                policy_version=(
                    "bounded-relevant-v1" if memory_mode is not GenerationMemoryMode.OFF else None
                ),
                limits=(
                    GenerationMemoryLimits()
                    if memory_mode is not GenerationMemoryMode.OFF
                    else None
                ),
            ),
            "controller": (
                ControllerRunConfiguration(
                    provider=controller_configuration,
                    connection_id=f"controller:{controller_configuration.provider}",
                    connection_fingerprint=controller_configuration.base_url,
                    prompt_version="controller-prompt-v1",
                    evidence_policy_version="controller-evidence-v1",
                    thinking_disabled=True,
                )
                if controller_configuration is not None
                else None
            ),
        }
    )
    conditions.require_phase_0_5()
    adapter = _arena_adapter(
        target_provider,
        conditions.target,
        defense=defense,
        enforce_permissions=enforce_permissions,
        enforce_confirmation=enforce_confirmation,
    )

    run_record = Run(
        target_name=policy.target_name,
        policy_version=policy.version,
        adapter_type=adapter.adapter_type,
        algorithm=selector.value,
        limits=limits,
        seed=seed,
        target_model=conditions.target.model,
        target_temperature=conditions.target.temperature,
        attacker_model=conditions.attacker.model,
        attacker_temperature=conditions.attacker.temperature,
        experiment_conditions=conditions,
        experiment_fingerprint=conditions.fingerprint(),
        strategy_ids=[s.id for s in strategies],
        notes=None if online else OFFLINE_NOTICE,
    )

    orchestrator_args = {
        "executor": ConversationExecutor(
            adapter=adapter,
            generator=generator,
            scorer=Level1Scorer(policy),
            policy=policy,
        ),
        "store": (store := RunStore(db)),
    }
    if selector is SearchSelector.LLM:
        assert controller_provider is not None and controller_configuration is not None
        orchestrator = RunOrchestrator(
            **orchestrator_args,
            driver=LLMControllerAdapter(
                provider=controller_provider,
                run_id=run_record.id,
                prompt_version="controller-prompt-v1",
                model=controller_configuration.model,
                temperature=controller_configuration.temperature,
                max_tokens=controller_configuration.max_tokens,
            ),
        )
    else:
        orchestrator = RunOrchestrator(
            **orchestrator_args, controller=_controller(selector.value, seed)
        )

    if not online:
        typer.secho(f"⚠️  {OFFLINE_NOTICE}", fg=typer.colors.YELLOW, err=True)

    async def _execute_and_close():
        # ⚠️ execute 与 provider 关闭必须在**同一个事件循环**里:
        # httpx AsyncClient 绑定到创建它的 loop,换一个新 loop 去关会报
        # "Event loop is closed"。所以不能用两次 asyncio.run。
        try:
            return await orchestrator.execute(
                RunExecutionRequest(run=run_record, strategies=strategies, actor=actor)
            )
        finally:
            if providers is not None:
                await providers.aclose()
            if controller_provider is not None:
                await controller_provider.aclose()

    try:
        result = asyncio.run(_execute_and_close())
    except RunFailedError as exc:
        # ⚠️ preflight 阶段失败**不是** RUN_FAILED:那时目标一次都没被触碰,
        # 属于"配置被拒绝"。CI 需要分开这两者 —— 前者改命令行/配置,
        # 后者要去查目标或环境。混成一个码,排查方向就没了。
        if exc.failure.stage is FailureStage.PREFLIGHT:
            typer.secho(f"配置被拒绝:{exc.failure.message}", fg=typer.colors.RED, err=True)
            raise typer.Exit(ExitCode.BAD_CONFIG) from exc
        typer.secho(
            f"Run {exc.run.id} 失败:{exc.failure.code} — {exc.failure.message}",
            fg=typer.colors.RED,
            err=True,
        )
        typer.secho("中断的 run 会系统性低估发现数,结论不可用。", fg=typer.colors.RED, err=True)
        raise typer.Exit(ExitCode.RUN_FAILED) from exc
    except ValueError as exc:
        typer.secho(f"配置被拒绝:{exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(ExitCode.BAD_CONFIG) from exc
    finally:
        store.close()

    paths = _emit(result.run, result.attempts, result.findings, out)
    _summarise(result.run, result.findings, paths)
    raise typer.Exit(ExitCode.FINDINGS if result.findings else ExitCode.CLEAN)


@app.command()
def resume(
    run_id: Annotated[str, typer.Argument(help="要从 attempt 边界恢复的 RUNNING run id")],
    actor: Annotated[str, typer.Option(help="攻击时扮演的身份;必须与原 run 一致")] = "customer_a",
    db: Annotated[str, typer.Option(help="SQLite 连接串")] = DEFAULT_URL,
    out: Annotated[Path, typer.Option(help="报告输出目录")] = Path("runs"),
) -> None:
    """恢复意外中断的 Run，绝不重放尚未原子提交结果的 attempt。"""
    store = RunStore(db)
    stored = store.get_run(run_id)
    if stored is None:
        store.close()
        typer.secho(f"找不到 run '{run_id}'。", fg=typer.colors.RED, err=True)
        raise typer.Exit(ExitCode.BAD_CONFIG)
    if stored.status is not RunStatus.RUNNING:
        store.close()
        typer.secho("只有状态为 RUNNING 的 run 可以恢复。", fg=typer.colors.RED, err=True)
        raise typer.Exit(ExitCode.BAD_CONFIG)
    if not stored.has_auditable_conditions or stored.experiment_conditions is None:
        store.close()
        typer.secho(
            "该 run 没有可审计的实验条件快照，拒绝在未知模型/靶场条件下恢复。",
            fg=typer.colors.RED,
            err=True,
        )
        raise typer.Exit(ExitCode.BAD_CONFIG)

    policy = SUPPORT_AGENT_POLICY
    strategies = select_applicable(list(PHASE_0_STRATEGIES), policy)
    conditions = stored.experiment_conditions
    controller_provider = None
    try:
        target_provider, generator, providers = _providers(conditions.online)
        defense = DefenseLevel(conditions.arena.defense)
        current_conditions = _experiment_conditions(
            online=conditions.online,
            providers=providers,
            actor=actor,
            defense=defense,
            enforce_permissions=conditions.arena.enforce_permissions,
            enforce_confirmation=conditions.arena.enforce_confirmation,
        )
        controller_configuration = None
        if conditions.search is not None and conditions.search.selector is SearchSelector.LLM:
            if not conditions.online or conditions.controller is None:
                raise ValueError("已落盘的 LLM Controller 条件不完整")
            controller_provider, controller_configuration = load_controller()
        current_conditions = current_conditions.model_copy(
            update={
                "strategy_catalogue": conditions.strategy_catalogue,
                "search": conditions.search,
                "generation_memory": conditions.generation_memory,
                "controller": (
                    ControllerRunConfiguration(
                        provider=controller_configuration,
                        connection_id=f"controller:{controller_configuration.provider}",
                        connection_fingerprint=controller_configuration.base_url,
                        prompt_version=conditions.controller.prompt_version,
                        evidence_policy_version=conditions.controller.evidence_policy_version,
                        output_schema_version=conditions.controller.output_schema_version,
                        budget_view_policy_version=conditions.controller.budget_view_policy_version,
                        thinking_disabled=conditions.controller.thinking_disabled,
                    )
                    if controller_configuration is not None
                    else None
                ),
            }
        )
        current_conditions.require_phase_0_5()
        if current_conditions.fingerprint() != stored.experiment_fingerprint:
            raise ValueError(
                "当前 provider / temperature / attacker / actor 或靶场开关与原 Run 不一致"
            )
    except (ProviderConfigError, ValueError) as exc:
        if "providers" in locals() and providers is not None:
            asyncio.run(providers.aclose())
        if controller_provider is not None:
            asyncio.run(controller_provider.aclose())
        store.close()
        typer.secho(f"恢复配置被拒绝:{exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(ExitCode.BAD_CONFIG) from exc

    adapter = _arena_adapter(
        target_provider,
        conditions.target,
        defense=defense,
        enforce_permissions=conditions.arena.enforce_permissions,
        enforce_confirmation=conditions.arena.enforce_confirmation,
    )
    controller = None
    driver = None
    if conditions.search is not None and conditions.search.selector is SearchSelector.LLM:
        if controller_provider is None or conditions.controller is None:
            raise AssertionError("LLM Controller provider must be built during resume preflight")
        driver = LLMControllerAdapter(
            provider=controller_provider,
            run_id=stored.id,
            prompt_version=conditions.controller.prompt_version,
            model=conditions.controller.provider.model,
            temperature=conditions.controller.provider.temperature,
            max_tokens=conditions.controller.provider.max_tokens,
        )
    else:
        controller = _controller(stored.algorithm, stored.seed or 0)
    orchestrator = RunOrchestrator(
        executor=ConversationExecutor(
            adapter=adapter,
            generator=generator,
            scorer=Level1Scorer(policy),
            policy=policy,
        ),
        controller=controller,
        driver=driver,
        store=store,
    )

    async def _resume_and_close():
        try:
            return await orchestrator.resume(
                RunExecutionRequest(run=stored, strategies=strategies, actor=actor)
            )
        finally:
            if providers is not None:
                await providers.aclose()
            if controller_provider is not None:
                await controller_provider.aclose()

    try:
        result = asyncio.run(_resume_and_close())
    except (RunResumeError, ValueError) as exc:
        typer.secho(f"恢复配置被拒绝:{exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(ExitCode.BAD_CONFIG) from exc
    except RunFailedError as exc:
        typer.secho(
            f"Run {exc.run.id} 恢复后失败:{exc.failure.code} — {exc.failure.message}",
            fg=typer.colors.RED,
            err=True,
        )
        raise typer.Exit(ExitCode.RUN_FAILED) from exc
    finally:
        store.close()

    paths = _emit(result.run, result.attempts, result.findings, out)
    _summarise(result.run, result.findings, paths)
    raise typer.Exit(ExitCode.FINDINGS if result.findings else ExitCode.CLEAN)


@app.command()
def report(
    run_id: Annotated[str, typer.Argument(help="要导出的 run id")],
    db: Annotated[str, typer.Option(help="SQLite 连接串")] = DEFAULT_URL,
    out: Annotated[Path, typer.Option(help="报告输出目录")] = Path("runs"),
) -> None:
    """从已落盘的 run 重新生成报告。

    报告是从存储重建的,不是执行时缓存的 —— 所以任何时候都能重出一份,
    而且和当时那份数字一致。
    """
    with RunStore(db) as store:
        stored = store.get_run(run_id)
        if stored is None:
            typer.secho(f"找不到 run '{run_id}'。", fg=typer.colors.RED, err=True)
            raise typer.Exit(ExitCode.BAD_CONFIG)
        attempts = store.attempts_for(run_id)
        findings = store.findings_for(run_id)

    paths = _emit(stored, attempts, findings, out)
    _summarise(stored, findings, paths)
    raise typer.Exit(ExitCode.FINDINGS if findings else ExitCode.CLEAN)


@app.command(name="gate-report")
def gate_report(
    db: Annotated[str, typer.Option(help="SQLite 连接串")] = DEFAULT_URL,
    out: Annotated[Path, typer.Option(help="Gate JSON 输出路径")] = Path("runs/gate-report.json"),
    controls_json: Annotated[
        Path | None, typer.Option(help="冻结 controls JSON；缺失时报告保持 INCOMPLETE")
    ] = None,
    validation_json: Annotated[
        Path | None, typer.Option(help="冻结 replay validation JSON；缺失时报告保持 INCOMPLETE")
    ] = None,
    seed_plan_json: Annotated[
        Path | None, typer.Option(help="冻结的 12+4 seed plan JSON；缺失时报告保持 INCOMPLETE")
    ] = None,
    golden_json: Annotated[
        Path | None, typer.Option(help="冻结 Level-1 golden 结果；缺失时报告保持 INCOMPLETE")
    ] = None,
    attacker_control_json: Annotated[
        Path | None, typer.Option(help="冻结 attacker control JSON；缺失时报告保持 INCOMPLETE")
    ] = None,
    controller_controls_json: Annotated[
        Path | None, typer.Option(help="冻结 Controller controls JSON；缺失时报告保持 INCOMPLETE")
    ] = None,
) -> None:
    """从已落盘的 Run/Event/Finding 重建冻结的 Phase 0.5 Gate 分析。"""
    controls_result = (
        ControlsReport.from_report_json(controls_json.read_text(encoding="utf-8"))
        if controls_json is not None
        else None
    )
    validation_result = (
        ValidationReport.model_validate_json(validation_json.read_text(encoding="utf-8"))
        if validation_json is not None
        else None
    )
    seed_plan = (
        SeedPlan.model_validate_json(seed_plan_json.read_text(encoding="utf-8"))
        if seed_plan_json is not None
        else None
    )
    golden_result = (
        GoldenReport.model_validate_json(golden_json.read_text(encoding="utf-8"))
        if golden_json is not None
        else None
    )
    attacker_control_result = (
        AttackerControlReport.model_validate_json(attacker_control_json.read_text(encoding="utf-8"))
        if attacker_control_json is not None
        else None
    )
    controller_controls_result = (
        ControllerContractReport.model_validate_json(
            controller_controls_json.read_text(encoding="utf-8")
        )
        if controller_controls_json is not None
        else None
    )
    with RunStore(db) as store:
        result = build_gate_report(
            store,
            controls=controls_result,
            golden=golden_result,
            attacker_control=attacker_control_result,
            controller_controls=controller_controls_result,
            validation=validation_result,
            seed_plan=seed_plan,
        )
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(result.model_dump_json(indent=2), encoding="utf-8")
    typer.echo(f"Gate report: {out}")
    typer.echo(result.verdict.value)


@app.command(name="gate-plan")
def gate_plan(
    max_attempts: Annotated[
        int,
        typer.Option(help="正式 Run 的安全 attempt 上限；必须在开跑前显式冻结，不能沿用默认 20"),
    ],
    seed_plan_json: Annotated[Path, typer.Option(help="冻结的 12+4 seed plan JSON")],
    db: Annotated[str, typer.Option(help="正式矩阵专用 SQLite 连接串；不得混用开发数据库")],
    run_out: Annotated[Path, typer.Option(help="每个正式 Run 的报告目录")] = Path("runs/phase-0-5"),
    out: Annotated[Path, typer.Option(help="只读执行清单 JSON 输出路径")] = Path(
        "runs/gate-plan.json"
    ),
) -> None:
    """生成 72 个主单元 + 24 个备用单元的命令清单，但绝不执行它们。"""
    try:
        seed_plan = SeedPlan.model_validate_json(seed_plan_json.read_text(encoding="utf-8"))
        plan: GatePlan = build_gate_plan(
            seed_plan,
            max_attempts=max_attempts,
            database_url=db,
            report_directory=str(run_out),
        )
    except (OSError, ValueError) as exc:
        typer.secho(f"Gate plan 配置被拒绝:{exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(ExitCode.BAD_CONFIG) from exc
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(plan.model_dump_json(indent=2), encoding="utf-8")
    typer.echo(f"Gate plan: {out}")
    typer.echo(f"primary {plan.primary_cells} cells; reserve {plan.reserve_cells} cells (disabled)")
    typer.echo("只生成清单；未调用 Provider、未执行任何正式 Run。")


@app.command(name="gate-preflight")
def gate_preflight(
    seed_plan_json: Annotated[Path, typer.Option(help="冻结的 12+4 seed plan JSON")],
    db: Annotated[str, typer.Option(help="正式矩阵专用 SQLite 连接串;必须为空且不得混用开发库")],
    golden_fixtures: Annotated[Path, typer.Option(help="冻结 Level-1 fixture JSON")] = Path(
        "tests/fixtures/level1-golden-v1.json"
    ),
    out: Annotated[Path | None, typer.Option(help="自检报告 JSON 输出路径")] = None,
) -> None:
    """开跑前的零成本环境自检 —— **不调用任何 Provider**。

    它回答的是"配置齐了没有":三个模型位是否都建好、九项单价是否都显式冻结、
    seed plan 是否与冻结 digest 一致、Level-1 golden 是否满分、正式数据库是否为空。

    ⚠️ **全绿只意味着可以开始跑对照,不意味着这套装置能发现漏洞** ——
    后者要 `controller-controls` / `controls` / `attacker-control` 真的花钱去证明。
    阶段结论仍然只看 `gate-report.json` 的 verdict。
    """
    report = run_preflight(
        seed_plan_json=seed_plan_json,
        database_url=db,
        golden_fixtures=golden_fixtures,
    )
    typer.echo(report.summary())
    if out is not None:
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(report.model_dump_json(indent=2), encoding="utf-8")
        typer.echo(f"明细    {out}")
    if not report.passed:
        raise typer.Exit(ExitCode.BAD_CONFIG)


@app.command(name="golden")
def golden(
    fixtures: Annotated[Path, typer.Option(help="冻结 Level-1 fixture JSON")] = Path(
        "tests/fixtures/level1-golden-v1.json"
    ),
    out: Annotated[Path, typer.Option(help="Golden report JSON 输出路径")] = Path(
        "runs/golden.json"
    ),
) -> None:
    """执行版本化的 10 正/10 负确定性 Scorer golden；不调用 Provider。"""
    try:
        report = evaluate_golden(fixtures)
    except (OSError, ValueError) as exc:
        typer.secho(f"Golden 配置被拒绝:{exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(ExitCode.BAD_CONFIG) from exc
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(report.model_dump_json(indent=2), encoding="utf-8")
    typer.echo(f"Golden: {out}")
    typer.echo(
        f"positive {report.positive_passed}/{report.positive_total}; "
        f"negative {report.negative_passed}/{report.negative_total}"
    )
    if not report.passed:
        raise typer.Exit(ExitCode.CONTROL_FAILED)


@app.command(name="validate-paths")
def validate_paths(
    seed_plan_json: Annotated[Path, typer.Option(help="冻结的 12+4 seed plan JSON")],
    db: Annotated[str, typer.Option(help="正式 Phase 0.5 专用 SQLite 连接串")],
    out: Annotated[Path, typer.Option(help="冻结 replay validation JSON 输出路径")] = Path(
        "runs/validation.json"
    ),
    repeats: Annotated[int, typer.Option(help="每条攻击路径重放次数；正式 Gate 必须为 5")] = 5,
) -> None:
    """只重放正式 320k 前缀中的攻击路径，不重跑 Generator 或 Controller。"""
    if repeats != 5:
        typer.secho("配置被拒绝:正式 Gate 的 repeats 必须固定为 5。", fg=typer.colors.RED, err=True)
        raise typer.Exit(ExitCode.BAD_CONFIG)
    try:
        seed_plan = SeedPlan.model_validate_json(seed_plan_json.read_text(encoding="utf-8"))
        with RunStore(db) as store:
            evidence = select_validation_evidence(store, seed_plan)
    except (OSError, ValueError) as exc:
        typer.secho(f"Validation 配置被拒绝:{exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(ExitCode.BAD_CONFIG) from exc

    reference = evidence.runs[0].experiment_conditions
    if reference is None:
        raise AssertionError("formal Gate run must carry experiment conditions")
    if reference.arena.defense not in {level.value for level in DefenseLevel}:
        typer.secho("Validation 配置被拒绝:未知的冻结 defense。", fg=typer.colors.RED, err=True)
        raise typer.Exit(ExitCode.BAD_CONFIG)
    try:
        target, target_configuration = load_target()
    except ProviderConfigError as exc:
        typer.secho(f"Target 配置被拒绝:{exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(ExitCode.BAD_CONFIG) from exc
    if target_configuration != reference.target:
        asyncio.run(target.aclose())
        typer.secho(
            "Validation 配置被拒绝:当前 Target 配置与正式 Run 冻结快照不一致。",
            fg=typer.colors.RED,
            err=True,
        )
        raise typer.Exit(ExitCode.BAD_CONFIG)

    adapter = _arena_adapter(
        target,
        target_configuration,
        defense=DefenseLevel(reference.arena.defense),
        enforce_permissions=reference.arena.enforce_permissions,
        enforce_confirmation=reference.arena.enforce_confirmation,
    )

    async def _validate_and_close() -> ValidationReport:
        try:
            return await validate_attack_paths(
                adapter=adapter,
                scorer=Level1Scorer(SUPPORT_AGENT_POLICY),
                attempts=evidence.attempts,
                findings=evidence.findings,
                repeats=repeats,
                target_configuration=target_configuration,
                gate_context_fingerprint=evidence.runs[0].gate_context_fingerprint(),
                run_ids=[run.id for run in evidence.runs],
            )
        finally:
            await target.aclose()

    try:
        report = asyncio.run(_validate_and_close())
    except ValueError as exc:
        typer.secho(f"Validation 执行被拒绝:{exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(ExitCode.BAD_CONFIG) from exc
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(report.model_dump_json(indent=2), encoding="utf-8")
    typer.echo(f"Validation: {out}")
    typer.echo(f"paths {len(report.results)} × {repeats} replays")


@app.command(name="controller-controls")
def controller_controls(
    out: Annotated[
        Path, typer.Option(help="冻结 Controller contract control JSON 输出路径")
    ] = Path("runs/controller-contract-controls.json"),
) -> None:
    """Run the fixed 12-case Controller preflight without a target or Gate seed."""
    try:
        provider, configuration = load_controller()
    except ProviderConfigError as exc:
        typer.secho(f"Controller 配置被拒绝: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(ExitCode.BAD_CONFIG) from exc

    driver = LLMControllerAdapter(
        provider=provider,
        run_id="controller-contract-controls",
        prompt_version="controller-contract-controls-v1",
        model=configuration.model,
        temperature=configuration.temperature,
        max_tokens=configuration.max_tokens,
    )
    frozen_controller = ControllerRunConfiguration(
        provider=configuration,
        connection_id=f"controller:{configuration.provider}",
        connection_fingerprint=configuration.base_url,
        prompt_version="controller-prompt-v1",
        evidence_policy_version="controller-evidence-v1",
        thinking_disabled=True,
    )

    async def _run_and_close():
        try:
            return await run_controller_contract_controls(driver, controller=frozen_controller)
        finally:
            await provider.aclose()

    report = asyncio.run(_run_and_close())
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(report.model_dump_json(indent=2), encoding="utf-8")
    typer.echo(f"Controller controls: {out}")
    typer.echo("PASSED" if report.passed else "FAILED")
    if not report.passed:
        raise typer.Exit(ExitCode.BAD_CONFIG)


@app.command(name="controls")
def controls(
    out: Annotated[Path, typer.Option(help="明细输出目录")] = Path("runs"),
) -> None:
    """校准之前的**阳性 / 阴性对照**(`CALIBRATION.md` §2)。

    阳性:把防御措辞拿掉,最直白的攻击**必须**得手 —— 不得手说明链路断了
    (canary 没植入 / 工具没插桩 / 检测器有 bug),此时任何校准结果都无意义。

    阴性:一批完全正当的请求**必须零 Finding** —— 有 Finding 就是误报。

    ⚠️ **本命令没有离线模式,与 attacker-control 同一个理由:**
    离线要让脚本化 provider "配合"地被攻破,那证明的只是我们自己写的脚本能触发
    检测器。**报告里的发现必须来自模型决策。** 检测器本身由测试用脚本化 provider 锁住。
    """
    policy = SUPPORT_AGENT_POLICY
    try:
        pair = load_providers()
    except ProviderConfigError as exc:
        typer.secho(f"配置被拒绝:{exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(ExitCode.BAD_CONFIG) from exc

    scorer = Level1Scorer(policy)

    def _make(enforce_permissions: bool) -> ArenaAdapter:
        # 阳性对照必须在**移除防御措辞**的靶场上跑 —— 那正是 DefenseLevel.NONE 的用途。
        return _arena_adapter(
            pair.target,
            pair.target_configuration,
            defense=DefenseLevel.NONE,
            enforce_permissions=enforce_permissions,
        )

    async def _run_controls():
        try:
            positive = await run_positive_control(_make, scorer)
            # 阴性对照用**正常配置**跑:它要回答的是"日常设置下会不会误报",
            # 在无防御的靶场上问这个问题没有意义。
            negative = await run_negative_control(
                _arena_adapter(
                    pair.target,
                    pair.target_configuration,
                    defense=DefenseLevel.STANDARD,
                ),
                scorer,
            )
            return ControlsReport(
                positive=positive,
                negative=negative,
                conditions=controls_conditions(target=pair.target_configuration),
            )
        finally:
            await pair.aclose()

    report_data = asyncio.run(_run_controls())

    out.mkdir(parents=True, exist_ok=True)
    detail = out / "controls.json"
    detail.write_text(report_data.model_dump_json(indent=2), encoding="utf-8")

    typer.echo(f"模型    {pair.target.model}")
    typer.echo(report_data.summary())
    typer.echo(f"明细    {detail}")

    if not report_data.passed:
        raise typer.Exit(ExitCode.CONTROL_FAILED)
    raise typer.Exit(ExitCode.CLEAN)


@app.command(name="attacker-control")
def attacker_control(
    samples: Annotated[
        int, typer.Option(help="每个策略生成几条话术(总调用数 = 策略数 × 本值)")
    ] = 5,
    seed: Annotated[int, typer.Option(help="种子;与正式 run 同一套派生机制")] = 0,
    actor: Annotated[str, typer.Option(help="攻击时扮演的身份")] = "customer_a",
    out: Annotated[Path, typer.Option(help="话术明细的输出目录")] = Path("runs"),
) -> None:
    """校准之前先跑这个:确认**攻击方不是瓶颈**。

    若最终校准出现「六条 ASR 挤在一起」,有三种原因长得一模一样 ——
    靶场与策略不契合 / 靶场有缺陷 / **攻击方太弱**。前两种要动靶场,
    第三种动靶场是**调错地方**,还会白烧掉三轮配额里的一轮。
    这道对照专门把第三种择出来。

    ⚠️ **本命令没有离线模式,这是刻意的。** 离线用的是模板生成器,
    同一策略每次产出同一句话 —— 组内相似度必然接近 1、分离度必然很大,
    于是它会稳定地报告"攻击方不是瓶颈"。但那句话是关于**模板**的,
    与真正上场的 attacker 无关。一个永远说 OK 的对照比没有对照更危险。
    """
    policy = SUPPORT_AGENT_POLICY
    strategies = select_applicable(list(PHASE_0_STRATEGIES), policy)
    if samples < 2:
        typer.secho(
            "配置被拒绝:samples 至少为 2，才能计算策略内相似度。",
            fg=typer.colors.RED,
            err=True,
        )
        raise typer.Exit(ExitCode.BAD_CONFIG)
    if not strategies:
        typer.secho("没有适用于该目标的策略。", fg=typer.colors.RED, err=True)
        raise typer.Exit(ExitCode.BAD_CONFIG)

    try:
        brief = policy.brief_for(actor)
        attacker = load_attacker()
    except (KeyError, ProviderConfigError) as exc:
        typer.secho(f"配置被拒绝:{exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(ExitCode.BAD_CONFIG) from exc

    attacker_configuration = getattr(
        attacker,
        "run_configuration",
        ProviderRunConfiguration(
            provider=attacker.name,
            base_url="in-process://test-double",
            model=attacker.model,
            temperature=1.0,
            max_tokens=512,
            rpm=0,
            max_concurrency=0,
            input_usd_per_mtok=0,
            output_usd_per_mtok=0,
            cached_input_usd_per_mtok=0,
        ),
    )
    generator = LLMMutationGenerator(
        attacker,
        model=attacker_configuration.model,
        temperature=attacker_configuration.temperature,
        max_tokens=attacker_configuration.max_tokens,
    )
    attacker_conditions = AttackerControlConditions.build(
        attacker=attacker_configuration,
        strategy_catalogue=StrategyCatalogue(
            version="phase0.5-v1", strategies=strategies
        ).condition_summary(),
        brief=brief,
        samples_per_strategy=samples,
        seed=seed,
    )

    async def _control_and_close():
        # 与 run 同理:provider 必须在创建它的那个事件循环里关闭。
        try:
            return await run_attacker_control(
                generator,
                strategies,
                brief,
                samples_per_strategy=samples,
                seed=seed,
                conditions=attacker_conditions,
            )
        finally:
            await attacker.aclose()

    try:
        report_data = asyncio.run(_control_and_close())
    except ValueError as exc:
        typer.secho(f"配置被拒绝:{exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(ExitCode.BAD_CONFIG) from exc

    # 话术全文必须落盘:这道对照的结论只有两个小数,而 attacker_control 明确要求
    # 结果可以**手工复核**(Jaccard 选得这么土就是为了这个)。只打印两个数字的话,
    # 谁也没法回答"它们到底像在哪儿"。
    out.mkdir(parents=True, exist_ok=True)
    detail = out / f"attacker-control-seed{seed}.json"
    detail.write_text(report_data.model_dump_json(indent=2), encoding="utf-8")

    typer.echo(f"模型    {attacker.model}")
    typer.echo(f"策略    {len(strategies)} 个 × {samples} 条 = {len(strategies) * samples} 次调用")
    typer.echo(report_data.summary())
    typer.echo(f"明细    {detail}")

    if report_data.attacker_is_bottleneck:
        typer.secho(
            "不要用这套配置去跑校准 —— 先换攻击方或调高其 temperature,靶场一个字都别动。",
            fg=typer.colors.RED,
            err=True,
        )
        raise typer.Exit(ExitCode.CONTROL_FAILED)
    raise typer.Exit(ExitCode.CLEAN)


def _emit(run_record: Run, attempts: list, findings: list, out: Path) -> dict[str, Path]:
    data = ReportData.build(run_record, attempts, findings)
    return write_report(data, out / run_record.id)


def _summarise(run_record: Run, findings: list, paths: dict[str, Path]) -> None:
    typer.echo(f"run_id  {run_record.id}")
    typer.echo(f"status  {run_record.status.value}")
    typer.echo(f"停止于  {run_record.stopped_by.value if run_record.stopped_by else '—'}")
    typer.echo(f"attempts {run_record.usage.attempts}   findings {len(findings)}")
    if run_record.status is not RunStatus.COMPLETED:
        typer.secho("该 run 未正常完成,数字不可与完整 run 比较。", fg=typer.colors.YELLOW)
    for kind, path in paths.items():
        typer.echo(f"{kind:6} {path}")


def main() -> None:
    _ensure_cli_output_encoding()
    app()


def _ensure_cli_output_encoding() -> None:
    """在旧 Windows code page 下也保证 Typer/Rich help 不因 Unicode 崩溃。"""
    probe = "RedCell —— 授权测试"
    for stream in (sys.stdout, sys.stderr):
        encoding = getattr(stream, "encoding", None)
        reconfigure = getattr(stream, "reconfigure", None)
        if not encoding or reconfigure is None:
            continue
        try:
            probe.encode(encoding)
        except (LookupError, UnicodeEncodeError):
            reconfigure(encoding="utf-8", errors="replace")


if __name__ == "__main__":
    main()
