from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from redcell.budget import BudgetLimits
from redcell.cli import ExitCode, app
from redcell.config import (
    AttackerSettings,
    ControllerSettings,
    ProviderSettings,
    TargetSettings,
)
from redcell.gate_analysis import PHASE_0_5_SEED_PLAN_DIGEST
from redcell.gate_preflight import run_preflight
from redcell.protocols.run import Run
from redcell.storage import RunStore

runner = CliRunner()

FROZEN_SEED_PLAN = Path("docs/PHASE0_5_SEED_PLAN.json").resolve()
GOLDEN_FIXTURES = Path("tests/fixtures/level1-golden-v2.json").resolve()

ROLES = ("target", "attacker", "controller")

SETTINGS_TYPES = {
    "target": TargetSettings,
    "attacker": AttackerSettings,
    "controller": ControllerSettings,
}


def _settings(role: str, *, connected: bool = True, prices: bool = True) -> ProviderSettings:
    """构造与运行环境完全无关的配置对象。

    **每个字段都显式赋值**,而不是只关掉 dotenv。`_env_file=None` 只停掉 `.env`
    这一个来源,进程环境变量照样会被读进来 —— 于是"缺 Controller 配置会被拦下"
    这条断言会在作者 export 了那几个变量、或填好 `.env` 的那天变红,
    而那不是回归,只是测试在观察开发机的状态。显式 init 值在
    pydantic-settings 里优先级最高,是唯一能让它真正确定的写法。
    """
    return SETTINGS_TYPES[role](
        _env_file=None,
        provider="glm" if connected else "",
        base_url="https://example.invalid/v1" if connected else "",
        api_key="not-a-real-key" if connected else "",
        model="test-model" if connected else "",
        input_usd_per_mtok=0.07 if prices else None,
        output_usd_per_mtok=0.4 if prices else None,
        cached_input_usd_per_mtok=0.0 if prices else None,
    )


def _roles(**overrides) -> list[tuple[str, ProviderSettings]]:
    return [(role, overrides.get(role) or _settings(role)) for role in ROLES]


def _db(tmp_path: Path) -> str:
    return f"sqlite:///{tmp_path / 'phase-0-5.db'}"


def _report(tmp_path: Path, roles=None):
    return run_preflight(
        seed_plan_json=FROZEN_SEED_PLAN,
        database_url=_db(tmp_path),
        golden_fixtures=GOLDEN_FIXTURES,
        roles=roles if roles is not None else _roles(),
    )


def _check(report, name: str):
    return next(item for item in report.checks if item.name == name)


def test_fully_configured_environment_passes(tmp_path) -> None:
    report = _report(tmp_path)

    assert report.passed, report.summary()


def test_missing_controller_connection_is_named_explicitly(tmp_path) -> None:
    """Controller 缺配是当前最可能的失败,报错必须指出**具体缺哪几个键**。"""
    roles = _roles(controller=_settings("controller", connected=False))

    report = _report(tmp_path, roles)
    check = _check(report, "controller.connection")

    assert not report.passed
    assert not check.passed
    assert "REDCELL_CONTROLLER_" in check.detail


def test_unset_price_is_unknown_not_free(tmp_path) -> None:
    """留空的单价必须判失败。

    它不是 0 —— 当成 0 会让美元估算静默少算,而 PRD 要求缺价时显示 N/A。
    免费档应当显式写三个 0,那是一句可核对的断言。
    """
    roles = _roles(target=_settings("target", prices=False))

    check = _check(_report(tmp_path, roles), "target.pricing")

    assert not check.passed
    assert "CACHED_INPUT_USD_PER_MTOK" in check.detail


def test_explicit_zero_price_is_accepted(tmp_path) -> None:
    assert _check(_report(tmp_path), "attacker.pricing").passed


def test_baseline_database_is_refused(tmp_path) -> None:
    """冻结基线的 1080 场 attempt 就在 redcell.db 里,正式矩阵不得写进去。"""
    report = run_preflight(
        seed_plan_json=FROZEN_SEED_PLAN,
        database_url="sqlite:///redcell.db",
        golden_fixtures=GOLDEN_FIXTURES,
        roles=_roles(),
    )
    check = _check(report, "database")

    assert not check.passed
    assert "redcell.db" in check.detail


def test_non_empty_database_is_refused(tmp_path) -> None:
    """残留 Run 会让「这个 seed×condition 跑过几次」出现两个答案。"""
    with RunStore(_db(tmp_path)) as store:
        store.save_run(
            Run(
                target_name="support-agent",
                policy_version="v1",
                adapter_type="arena/support-agent",
                algorithm="static",
                limits=BudgetLimits(max_attempts=1),
            )
        )

    check = _check(_report(tmp_path), "database")

    assert not check.passed
    assert "空库" in check.detail


def test_tampered_seed_plan_is_refused(tmp_path) -> None:
    """seed plan 是预注册文件;改一个数字就不再是被冻结的那份。"""
    plan = json.loads(FROZEN_SEED_PLAN.read_text(encoding="utf-8"))
    plan["primary"][0] += 1
    tampered = tmp_path / "seeds.json"
    tampered.write_text(json.dumps(plan), encoding="utf-8")

    report = run_preflight(
        seed_plan_json=tampered,
        database_url=_db(tmp_path),
        golden_fixtures=GOLDEN_FIXTURES,
        roles=_roles(),
    )

    assert not _check(report, "seed_plan").passed


def test_frozen_seed_plan_file_still_matches_its_digest() -> None:
    """把 runbook 里那串 digest 与仓库中的文件绑在一起。"""
    from redcell.gate_analysis import SeedPlan, seed_plan_digest

    plan = SeedPlan.model_validate_json(FROZEN_SEED_PLAN.read_text(encoding="utf-8"))

    assert seed_plan_digest(plan) == PHASE_0_5_SEED_PLAN_DIGEST


@pytest.fixture
def isolated_env(tmp_path, monkeypatch):
    """把 CWD 换到空目录,使 `env_file=".env"` 找不到开发机的真实配置。

    CLI 走的是不带注入的 `load_role_settings()`,所以隔离只能靠环境本身;
    否则这些断言观察的是作者 `.env` 的状态,而不是代码行为。
    """
    monkeypatch.chdir(tmp_path)
    for role in ROLES:
        for suffix in (
            "PROVIDER",
            "BASE_URL",
            "API_KEY",
            "MODEL",
            "INPUT_USD_PER_MTOK",
            "OUTPUT_USD_PER_MTOK",
            "CACHED_INPUT_USD_PER_MTOK",
        ):
            monkeypatch.delenv(f"REDCELL_{role.upper()}_{suffix}", raising=False)
    return monkeypatch


def _fill_env(monkeypatch) -> None:
    for role in ROLES:
        prefix = f"REDCELL_{role.upper()}_"
        monkeypatch.setenv(f"{prefix}PROVIDER", "glm")
        monkeypatch.setenv(f"{prefix}BASE_URL", "https://example.invalid/v1")
        monkeypatch.setenv(f"{prefix}API_KEY", "not-a-real-key")
        monkeypatch.setenv(f"{prefix}MODEL", "test-model")
        monkeypatch.setenv(f"{prefix}INPUT_USD_PER_MTOK", "0.07")
        monkeypatch.setenv(f"{prefix}OUTPUT_USD_PER_MTOK", "0.4")
        monkeypatch.setenv(f"{prefix}CACHED_INPUT_USD_PER_MTOK", "0")


def _invoke(tmp_path):
    return runner.invoke(
        app,
        [
            "gate-preflight",
            "--seed-plan-json",
            str(FROZEN_SEED_PLAN),
            "--db",
            _db(tmp_path),
            "--golden-fixtures",
            str(GOLDEN_FIXTURES),
        ],
    )


@pytest.mark.parametrize("configured", [True, False])
def test_cli_exit_code_tracks_configuration(isolated_env, tmp_path, configured) -> None:
    if configured:
        _fill_env(isolated_env)

    result = _invoke(tmp_path)

    assert result.exit_code == (ExitCode.CLEAN if configured else ExitCode.BAD_CONFIG)


def test_cli_output_does_not_read_as_ready_to_conclude(isolated_env, tmp_path) -> None:
    """全绿最容易被读成"可以出结论了" —— 输出必须自己挡住这个误读。"""
    _fill_env(isolated_env)

    result = _invoke(tmp_path)

    assert result.exit_code == ExitCode.CLEAN, result.output
    assert "可以开始跑对照" in result.output
