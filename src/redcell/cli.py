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
from redcell.budget import BudgetLimits
from redcell.executor import ConversationExecutor
from redcell.generation import TemplateAttackGenerator
from redcell.llm.scripted import ScriptedProvider
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


def _controller(algorithm: str, seed: int) -> SearchController:
    order = [s.id for s in PHASE_0_STRATEGIES]
    if algorithm == "static":
        return StaticController(order)
    if algorithm == "random":
        import random

        # 私有 RNG:全局 random 会被任何其他代码干扰,复现直接报废。
        return RandomController(random.Random(controller_seed_for(seed)))
    raise typer.BadParameter(f"未知算法 '{algorithm}';可选:static / random")


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
    max_tokens: Annotated[int | None, typer.Option(help="token 上限")] = None,
    max_seconds: Annotated[float | None, typer.Option(help="墙钟上限(秒)")] = None,
    db: Annotated[str, typer.Option(help="SQLite 连接串")] = DEFAULT_URL,
    out: Annotated[Path, typer.Option(help="报告输出目录")] = Path("runs"),
) -> None:
    """对自带靶场跑一次评测。

    ⚠️ 目前只有脚本化离线 provider,因此这条命令验证的是**流水线**,
    不是靶场的真实安全性。接入真实模型后同一条命令才会产出可用结论。
    """
    limits = BudgetLimits(
        max_attempts=budget,
        max_total_tokens=max_tokens,
        max_wall_seconds=max_seconds,
        # 刻意不暴露 --max-cost:当前 provider 不报告成本,
        # 设了也永不触发 —— 那是个假的安全网,比没有更危险。
    )

    policy = SUPPORT_AGENT_POLICY
    strategies = select_applicable(list(PHASE_0_STRATEGIES), policy)
    if not strategies:
        typer.secho("没有适用于该目标的策略。", fg=typer.colors.RED, err=True)
        raise typer.Exit(ExitCode.BAD_CONFIG)

    provider = ScriptedProvider(
        default="I can help with orders and store policies. What do you need?",
        model="scripted-offline",
    )
    adapter = ArenaAdapter(
        provider,
        defense=defense,
        enforce_permissions=enforce_permissions,
    )

    run_record = Run(
        target_name=policy.target_name,
        policy_version=policy.version,
        adapter_type=adapter.adapter_type,
        algorithm=algorithm,
        limits=limits,
        seed=seed,
        strategy_ids=[s.id for s in strategies],
        notes=OFFLINE_NOTICE,
    )

    orchestrator = RunOrchestrator(
        executor=ConversationExecutor(
            adapter=adapter,
            generator=TemplateAttackGenerator(),
            scorer=Level1Scorer(policy),
            policy=policy,
        ),
        controller=_controller(algorithm, seed),
        store=(store := RunStore(db)),
    )

    typer.secho(f"⚠️  {OFFLINE_NOTICE}", fg=typer.colors.YELLOW, err=True)

    try:
        result = asyncio.run(
            orchestrator.execute(
                RunExecutionRequest(run=run_record, strategies=strategies, actor=actor)
            )
        )
    except RunFailedError as exc:
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
