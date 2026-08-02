"""RedCell 命令行入口 —— **composition root,不含任何业务逻辑**。

它只做一件事:把已经写好的深模块接起来(Policy / Adapter / Generator /
Controller / Store / Orchestrator),然后把结果交给用户。

刻意不在这里放判定、预算或搜索逻辑:CLI 是最容易被随手加特例的地方,
一旦业务规则漏进来,同一件事就会有"库里一套、CLI 里一套"两个版本,
而它们迟早会不一致。
"""

from __future__ import annotations

import asyncio
from enum import IntEnum
from pathlib import Path
from typing import Annotated

import typer

from redcell.arena.support_agent import (
    SUPPORT_AGENT_POLICY,
    ArenaAdapter,
    DefenseLevel,
)
from redcell.attacker_control import run_attacker_control
from redcell.budget import BudgetLimits
from redcell.config import (
    ProviderConfigError,
    ProviderPair,
    load_attacker,
    load_providers,
)
from redcell.controls import ControlsReport, run_negative_control, run_positive_control
from redcell.executor import ConversationExecutor
from redcell.failures import FailureStage
from redcell.generation import AttackGenerator, TemplateAttackGenerator
from redcell.llm.base import LLMProvider
from redcell.llm.scripted import ScriptedProvider
from redcell.mutation import LLMMutationGenerator
from redcell.orchestrator import (
    RunExecutionRequest,
    RunFailedError,
    RunOrchestrator,
)
from redcell.protocols.run import Run, RunStatus
from redcell.protocols.strategy import select_applicable
from redcell.randomness import controller_seed_for
from redcell.report import ReportData, write_report
from redcell.scoring.level1 import Level1Scorer
from redcell.search import RandomController, SearchController, StaticController
from redcell.storage import DEFAULT_URL, RunStore
from redcell.strategies import PHASE_0_STRATEGIES

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
    raise typer.BadParameter(f"未知算法 '{algorithm}';可选:static / random")


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
        max_tokens=pair.attacker_max_tokens,
    )
    return pair.target, generator, pair


@app.command()
def run(
    algorithm: Annotated[str, typer.Option(help="搜索算法:static / random")] = "static",
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
            help="接真实模型跑(target=GLM / attacker=Gemini,从 .env 读)。" "默认离线,只验证流水线。"
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
    limits = BudgetLimits(
        max_attempts=budget,
        max_total_tokens=max_tokens,
        max_wall_seconds=max_seconds,
        max_cost_usd=max_cost,
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

    adapter = ArenaAdapter(
        target_provider,
        defense=defense,
        enforce_permissions=enforce_permissions,
        enforce_confirmation=enforce_confirmation,
    )

    run_record = Run(
        target_name=policy.target_name,
        policy_version=policy.version,
        adapter_type=adapter.adapter_type,
        algorithm=algorithm,
        limits=limits,
        seed=seed,
        strategy_ids=[s.id for s in strategies],
        notes=None if online else OFFLINE_NOTICE,
    )

    orchestrator = RunOrchestrator(
        executor=ConversationExecutor(
            adapter=adapter,
            generator=generator,
            scorer=Level1Scorer(policy),
            policy=policy,
        ),
        controller=_controller(algorithm, seed),
        store=(store := RunStore(db)),
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
        return ArenaAdapter(
            pair.target,
            defense=DefenseLevel.NONE,
            enforce_permissions=enforce_permissions,
        )

    async def _run_controls():
        try:
            positive = await run_positive_control(_make, scorer)
            # 阴性对照用**正常配置**跑:它要回答的是"日常设置下会不会误报",
            # 在无防御的靶场上问这个问题没有意义。
            negative = await run_negative_control(
                ArenaAdapter(pair.target, defense=DefenseLevel.STANDARD), scorer
            )
            return ControlsReport(positive=positive, negative=negative)
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
    if not strategies:
        typer.secho("没有适用于该目标的策略。", fg=typer.colors.RED, err=True)
        raise typer.Exit(ExitCode.BAD_CONFIG)

    try:
        brief = policy.brief_for(actor)
        attacker = load_attacker()
    except (KeyError, ProviderConfigError) as exc:
        typer.secho(f"配置被拒绝:{exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(ExitCode.BAD_CONFIG) from exc

    generator = LLMMutationGenerator(attacker, model=attacker.model)

    async def _control_and_close():
        # 与 run 同理:provider 必须在创建它的那个事件循环里关闭。
        try:
            return await run_attacker_control(
                generator,
                strategies,
                brief,
                samples_per_strategy=samples,
                seed=seed,
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
    app()


if __name__ == "__main__":
    main()
