"""开跑前的零成本环境自检 —— 不调用任何 Provider。

Runbook §4 之后的每一步都要花钱:controls 消耗配额,正式矩阵是小时级长作业,
连续外部调用。而此刻**能确定性判定的失败原因几乎全是配置**:少填一个价格、
Controller 连接没建、沿用了开发数据库。让这些错误在第一次付费调用**之前**暴露,
是本模块存在的唯一理由。

## 它明确不做的事

- **不调用 Provider。** 因此它证明不了 key 有效、模型可达或结构化输出可用 ——
  那是 `controller-controls` / `controls` 的职责,且必须真的花钱才能回答。
- **不替代任何对照。** 全绿只说明「配置齐了,可以开始跑对照」,
  不说明这套装置具备发现漏洞的能力。
- **不判定 Gate。** 判定只看 `gate-report.json` 的 fail-closed verdict。

写成独立模块而不是 CLI 里的一串 if:同一批检查在 runbook、未来的执行脚本和
CI 里都要用,而「什么算配置齐了」必须只有一份定义。
"""

from __future__ import annotations

from pathlib import Path

from pydantic import Field

from redcell.config import (
    AttackerSettings,
    ControllerSettings,
    ProviderSettings,
    TargetSettings,
    load_shared_rate_limit_database_url,
)
from redcell.gate_analysis import SeedPlan, require_frozen_seed_plan
from redcell.gate_billing_evidence import (
    BillingEvidenceBundle,
    BillingRole,
    billing_evidence_failures,
)
from redcell.golden import evaluate_golden
from redcell.protocols.common import RedCellModel
from redcell.protocols.run import ProviderRunConfiguration
from redcell.shared_rate_limit import SQLiteRateLimiter
from redcell.storage import RunStore
from redcell.utility_confirmation import (
    PHASE_0_5B_EXPERIMENT,
    UtilityConfirmationEvidence,
    validate_utility_confirmation,
)

PREFLIGHT_VERSION = "phase-0.5-preflight-v1"

DEVELOPMENT_DATABASE_MARKERS = ("redcell.db",)
"""正式矩阵不得写进的数据库。

冻结基线的 1080 场 attempt 就在 `redcell.db` 里;把正式 Run 混进去之后,
「这条记录属于哪次实验」只能靠时间戳猜,而 Gate 要求的是可审计。
"""


class PreflightCheck(RedCellModel):
    name: str
    passed: bool
    detail: str


class PreflightReport(RedCellModel):
    version: str = PREFLIGHT_VERSION
    checks: list[PreflightCheck] = Field(default_factory=list)

    @property
    def passed(self) -> bool:
        return all(check.passed for check in self.checks)

    def summary(self) -> str:
        lines = [
            f"{'PASS' if check.passed else 'FAIL'}  {check.name}: {check.detail}"
            for check in self.checks
        ]
        verdict = (
            "全部通过 —— 可以开始跑对照(那一步开始花钱)"
            if self.passed
            else "未通过 —— 不要开始付费步骤"
        )
        lines.append(verdict)
        return "\n".join(lines)


def _connection_check(name: str, settings: ProviderSettings) -> PreflightCheck:
    if settings.is_configured():
        return PreflightCheck(
            name=f"{name}.connection",
            passed=True,
            detail=f"已配置(model={settings.model})",
        )
    missing = [
        field
        for field, value in (
            ("PROVIDER", settings.provider),
            ("BASE_URL", settings.base_url),
            ("API_KEY", settings.api_key),
            ("MODEL", settings.model),
        )
        if not value
    ]
    return PreflightCheck(
        name=f"{name}.connection",
        passed=False,
        detail=f"缺少 REDCELL_{name.upper()}_{{{','.join(missing)}}}",
    )


def _pricing_check(name: str, settings: ProviderSettings) -> PreflightCheck:
    """三项单价必须全部显式给出;留空是「未知」,不是免费。

    缺价不会让 Token 预算失效(PRD ③),但会让美元估算静默少算。免费档写三个 0,
    那是一句可核对的断言;留空则只能显示 N/A。
    """
    missing = [
        field
        for field, value in (
            ("INPUT_USD_PER_MTOK", settings.input_usd_per_mtok),
            ("OUTPUT_USD_PER_MTOK", settings.output_usd_per_mtok),
            ("CACHED_INPUT_USD_PER_MTOK", settings.cached_input_usd_per_mtok),
        )
        if value is None
    ]
    if not missing:
        return PreflightCheck(
            name=f"{name}.pricing",
            passed=True,
            detail=(
                f"in={settings.input_usd_per_mtok} out={settings.output_usd_per_mtok} "
                f"cached={settings.cached_input_usd_per_mtok} USD/Mtok"
            ),
        )
    return PreflightCheck(
        name=f"{name}.pricing",
        passed=False,
        detail=f"未显式冻结:{', '.join(f'REDCELL_{name.upper()}_{item}' for item in missing)}",
    )


def _usage_coverage_check(name: str, settings: ProviderSettings) -> PreflightCheck:
    if settings.usage_covers_billed_tokens:
        return PreflightCheck(
            name=f"{name}.usage_coverage",
            passed=True,
            detail=(
                "声明 Provider usage 覆盖全部计费 Token;"
                f"accounting={settings.usage_accounting_mode.value}"
            ),
        )
    return PreflightCheck(
        name=f"{name}.usage_coverage",
        passed=False,
        detail=(
            f"REDCELL_{name.upper()}_USAGE_COVERS_BILLED_TOKENS 未确认；"
            "部分 usage（例如遗漏 thinking/reasoning）不得进入正式 Gate"
        ),
    )


def _shared_rate_limit_check(database_url: str | None, formal_database_url: str) -> PreflightCheck:
    if not database_url:
        return PreflightCheck(
            name="shared_rate_limit",
            passed=False,
            detail="缺少 REDCELL_SHARED_RATE_LIMIT_DB；多子进程矩阵不能只依赖本地 semaphore",
        )
    if database_url == formal_database_url:
        return PreflightCheck(
            name="shared_rate_limit",
            passed=False,
            detail="共享限流 SQLite 必须与正式矩阵数据库分离",
        )
    try:
        SQLiteRateLimiter(
            database_url,
            provider_key="preflight-probe",
            min_interval_seconds=0.0,
            max_concurrency=1,
        )
    except Exception as exc:
        return PreflightCheck(name="shared_rate_limit", passed=False, detail=f"无法初始化:{exc}")
    return PreflightCheck(name="shared_rate_limit", passed=True, detail=f"{database_url} 可用")


def _seed_plan_check(seed_plan_json: Path) -> PreflightCheck:
    try:
        seed_plan = SeedPlan.model_validate_json(seed_plan_json.read_text(encoding="utf-8"))
        require_frozen_seed_plan(seed_plan)
    except (OSError, ValueError) as exc:
        return PreflightCheck(name="seed_plan", passed=False, detail=str(exc))
    shape = f"{len(seed_plan.primary)} primary + {len(seed_plan.reserve)} reserve"
    return PreflightCheck(
        name="seed_plan",
        passed=True,
        detail=f"{shape},digest 与冻结值一致",
    )


def _requires_utility_confirmation(seed_plan_json: Path) -> bool:
    """Only Phase 0.5b is governed by the frozen post-failure amendment."""
    try:
        seed_plan = SeedPlan.model_validate_json(seed_plan_json.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False
    return seed_plan.experiment == PHASE_0_5B_EXPERIMENT


def _utility_confirmation_check(
    evidence: UtilityConfirmationEvidence | None,
    *,
    target: ProviderRunConfiguration,
) -> PreflightCheck:
    if evidence is None:
        return PreflightCheck(
            name="utility_confirmation_missing",
            passed=False,
            detail="Phase 0.5b 必须同时消费 137/200 与 160/200 的原始 controls 和独立裁决",
        )
    result = validate_utility_confirmation(
        evidence,
        expected_target=target,
    )
    if result.passed:
        return PreflightCheck(
            name="utility_confirmation",
            passed=True,
            detail=(
                f"{result.completed}/{result.runs} >= {result.floor}; "
                "两批 SHA、裁决、context 与逐任务统计均已复算"
            ),
        )
    return PreflightCheck(
        name="utility_confirmation",
        passed=False,
        detail="; ".join(result.failures),
    )


def _golden_check(fixtures: Path) -> PreflightCheck:
    try:
        report = evaluate_golden(fixtures)
    except (OSError, ValueError) as exc:
        return PreflightCheck(name="level1_golden", passed=False, detail=str(exc))
    detail = (
        f"positive {report.positive_passed}/{report.positive_total}; "
        f"negative {report.negative_passed}/{report.negative_total}"
    )
    return PreflightCheck(name="level1_golden", passed=report.passed, detail=detail)


def _database_check(database_url: str) -> PreflightCheck:
    """正式矩阵必须写进一个专属且当前为空的库。

    不是洁癖:Gate 要求 plan 中每个 cell 恰好各出现一次,而重复或残留的 Run 会让
    「这个 seed×condition 到底跑过几次」失去唯一答案。
    """
    for marker in DEVELOPMENT_DATABASE_MARKERS:
        if marker in database_url:
            return PreflightCheck(
                name="database",
                passed=False,
                detail=f"{database_url} 指向开发/基线数据库({marker}),正式矩阵必须另建",
            )
    try:
        with RunStore(database_url) as store:
            existing = len(store.list_runs())
    # 连不上、路径不可写、库损坏 —— 都是配置问题,一样要拦在第一次付费调用之前,
    # 所以这里刻意不挑异常类型:漏掉一种就等于放它进入付费步骤。
    except Exception as exc:
        return PreflightCheck(name="database", passed=False, detail=f"无法打开:{exc}")
    if existing:
        return PreflightCheck(
            name="database",
            passed=False,
            detail=f"已含 {existing} 条 Run;正式矩阵要求空库,以免 cell 计数出现两个答案",
        )
    return PreflightCheck(name="database", passed=True, detail=f"{database_url} 为空,可用")


def load_role_settings() -> list[tuple[str, ProviderSettings]]:
    """从环境与 `.env` 读三个模型位的配置。"""
    return [
        ("target", TargetSettings()),
        ("attacker", AttackerSettings()),
        ("controller", ControllerSettings()),
    ]


def run_preflight(
    *,
    seed_plan_json: Path,
    database_url: str,
    golden_fixtures: Path,
    roles: list[tuple[str, ProviderSettings]] | None = None,
    shared_rate_limit_db: str | None = None,
    billing_evidence: BillingEvidenceBundle | None = None,
    utility_confirmation: UtilityConfirmationEvidence | None = None,
) -> PreflightReport:
    """跑完全部零成本检查;任何一项失败都不应进入付费步骤。

    `roles` 是给测试用的注入点。真实调用要读 `.env`,而测试若也读它,
    "缺 Controller 配置会被拦下"这条断言就会在作者填好 `.env` 的那天变红 ——
    那不是回归,只是测试在观察开发机的状态。
    """
    roles = load_role_settings() if roles is None else roles
    expected_roles = {role.value for role in BillingRole}
    role_names = [name for name, _settings in roles]
    if len(role_names) != len(expected_roles) or set(role_names) != expected_roles:
        role_detail = f"必须且只能提供 target / attacker / controller 各一个；实际为 {role_names}"
        return PreflightReport(
            checks=[
                PreflightCheck(
                    name="role_configuration",
                    passed=False,
                    detail=role_detail,
                )
            ]
        )
    checks: list[PreflightCheck] = []
    for name, settings in roles:
        checks.append(_connection_check(name, settings))
        checks.append(_pricing_check(name, settings))
        checks.append(_usage_coverage_check(name, settings))
    configurations = {BillingRole(name): settings.run_configuration() for name, settings in roles}
    billing_failures = billing_evidence_failures(configurations, billing_evidence)
    for failure in billing_failures:
        checks.append(
            PreflightCheck(
                name=failure,
                passed=False,
                detail="正式 Gate 需要与当前非凭据 Provider 配置绑定的 billing evidence",
            )
        )
    if not billing_failures:
        checks.append(
            PreflightCheck(
                name="billing_evidence",
                passed=True,
                detail=(
                    f"三个角色的 billing evidence 已绑定(digest={billing_evidence.digest()[:12]})"
                ),
            )
        )
    checks.append(_seed_plan_check(seed_plan_json))
    if _requires_utility_confirmation(seed_plan_json):
        target = next(settings for name, settings in roles if name == "target")
        checks.append(
            _utility_confirmation_check(utility_confirmation, target=target.run_configuration())
        )
    checks.append(_golden_check(golden_fixtures))
    checks.append(_database_check(database_url))
    checks.append(
        _shared_rate_limit_check(
            (
                load_shared_rate_limit_database_url()
                if shared_rate_limit_db is None
                else shared_rate_limit_db
            ),
            database_url,
        )
    )
    return PreflightReport(checks=checks)
