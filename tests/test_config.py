from __future__ import annotations

import pytest

from redcell.config import ProviderSettings
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
