from __future__ import annotations

from pathlib import Path

import pytest

from redcell.config import ProviderSettings, load_target
from redcell.protocols.run import UsageAccountingMode


def _settings(**prices: float | None) -> ProviderSettings:
    return ProviderSettings(
        _env_file=None,
        provider="test",
        base_url="https://example.invalid/v1",
        api_key="not-a-real-key",
        model="test-model",
        **prices,
    )


@pytest.mark.asyncio
async def test_missing_price_is_unknown_not_implicitly_free() -> None:
    settings = _settings(input_usd_per_mtok=0.1, output_usd_per_mtok=0.2)
    provider = settings.build(name="test")
    try:
        assert settings.run_configuration().cached_input_usd_per_mtok is None
        assert not provider.reports_cost
    finally:
        await provider.aclose()


@pytest.mark.asyncio
async def test_explicit_zero_for_all_price_classes_confirms_free_service() -> None:
    settings = _settings(
        input_usd_per_mtok=0,
        output_usd_per_mtok=0,
        cached_input_usd_per_mtok=0,
    )
    provider = settings.build(name="test")
    try:
        assert provider.reports_cost
    finally:
        await provider.aclose()


@pytest.mark.asyncio
async def test_usage_accounting_mode_reaches_snapshot_and_provider() -> None:
    settings = _settings(
        input_usd_per_mtok=0.25,
        output_usd_per_mtok=1.5,
        cached_input_usd_per_mtok=0.025,
        usage_accounting_mode=UsageAccountingMode.TOTAL_MINUS_PROMPT_V1,
    )
    provider = settings.build(name="test")
    try:
        assert (
            settings.run_configuration().usage_accounting_mode
            is UsageAccountingMode.TOTAL_MINUS_PROMPT_V1
        )
        assert provider.usage_accounting_mode is UsageAccountingMode.TOTAL_MINUS_PROMPT_V1
    finally:
        await provider.aclose()


@pytest.mark.asyncio
async def test_request_timeout_reaches_the_actual_http_provider() -> None:
    settings = _settings(request_timeout_seconds=60.0)
    provider = settings.build(name="test")
    try:
        assert provider.timeout_seconds == 60.0
    finally:
        await provider.aclose()


@pytest.mark.asyncio
async def test_max_tokens_parameter_and_reasoning_effort_reach_snapshot_and_request() -> None:
    settings = _settings(
        max_tokens_parameter="max_completion_tokens",
        extra_body={"reasoning_effort": "low"},
    )
    configuration = settings.run_configuration()
    assert configuration.max_tokens_parameter == "max_completion_tokens"
    assert configuration.extra_body.reasoning_effort == "low"
    dumped = configuration.model_dump(mode="json")
    assert dumped["max_tokens_parameter"] == "max_completion_tokens"
    assert dumped["extra_body"] == {"thinking": None, "reasoning_effort": "low"}

    provider = settings.build(name="test")
    try:
        assert provider._max_tokens_field == "max_completion_tokens"
    finally:
        await provider.aclose()


def test_unset_new_provider_fields_keep_historical_serialisation() -> None:
    """未用到的新字段不能出现在序列化结果里。

    `AttackerControlConditions.fingerprint()` 对不带 `exclude_none` 的完整 dump 求哈希。
    新字段若以 `null` 出现,所有历史攻击方对照报告重算指纹都会对不上而加载失败。
    """
    dumped = _settings().run_configuration().model_dump(mode="json")

    assert "max_tokens_parameter" not in dumped
    assert dumped["extra_body"] == {"thinking": None}
    assert set(dumped) == {
        "provider",
        "base_url",
        "model",
        "temperature",
        "max_tokens",
        "rpm",
        "max_concurrency",
        "input_usd_per_mtok",
        "output_usd_per_mtok",
        "cached_input_usd_per_mtok",
        "extra_body",
        "usage_accounting_mode",
        "usage_covers_billed_tokens",
    }


_TARGET_VARS = (
    "REDCELL_TARGET_PROVIDER",
    "REDCELL_TARGET_BASE_URL",
    "REDCELL_TARGET_API_KEY",
    "REDCELL_TARGET_MODEL",
    "REDCELL_TARGET_EXTRA_BODY",
    "REDCELL_TARGET_MAX_TOKENS",
)


def _isolate_target_env(tmp_path, monkeypatch) -> None:
    """Process env would override both files; the test is about the files."""
    monkeypatch.chdir(tmp_path)
    for name in _TARGET_VARS:
        monkeypatch.delenv(name, raising=False)


@pytest.mark.asyncio
async def test_load_target_layers_a_candidate_env_file_over_dotenv(tmp_path, monkeypatch) -> None:
    """`positive-control --env-file`: the candidate file overrides `.env` key by key.

    JSON fields are replaced whole, unlike process-env overrides, which
    pydantic-settings deep-merges with the `.env` value (2026-09-23).
    """
    _isolate_target_env(tmp_path, monkeypatch)
    (tmp_path / ".env").write_text(
        "REDCELL_TARGET_PROVIDER=glm\n"
        "REDCELL_TARGET_BASE_URL=https://base.invalid/v1\n"
        "REDCELL_TARGET_API_KEY=not-a-real-key\n"
        "REDCELL_TARGET_MODEL=base-model\n"
        "REDCELL_TARGET_MAX_TOKENS=512\n"
        'REDCELL_TARGET_EXTRA_BODY={"thinking": {"type": "disabled"}}\n',
        encoding="utf-8",
    )
    (tmp_path / ".env.candidate").write_text(
        "REDCELL_TARGET_PROVIDER=gemini\n"
        "REDCELL_TARGET_MODEL=candidate-model\n"
        "REDCELL_TARGET_MAX_TOKENS=4096\n"
        "REDCELL_TARGET_EXTRA_BODY={}\n",
        encoding="utf-8",
    )

    provider, configuration = load_target(Path(".env.candidate"))
    try:
        assert configuration.provider == "gemini"
        assert configuration.model == "candidate-model"
        assert configuration.max_tokens == 4096
        assert configuration.base_url == "https://base.invalid/v1"
        assert configuration.extra_body.thinking is None
        assert provider.model == "candidate-model"
    finally:
        await provider.aclose()


@pytest.mark.asyncio
async def test_load_target_env_file_works_without_a_dotenv(tmp_path, monkeypatch) -> None:
    _isolate_target_env(tmp_path, monkeypatch)
    (tmp_path / ".env.candidate").write_text(
        "REDCELL_TARGET_PROVIDER=glm\n"
        "REDCELL_TARGET_BASE_URL=https://candidate.invalid/v1\n"
        "REDCELL_TARGET_API_KEY=not-a-real-key\n"
        "REDCELL_TARGET_MODEL=candidate-model\n",
        encoding="utf-8",
    )

    provider, configuration = load_target(Path(".env.candidate"))
    try:
        assert configuration.model == "candidate-model"
    finally:
        await provider.aclose()
