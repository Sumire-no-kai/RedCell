from __future__ import annotations

import asyncio
import sqlite3
import time

import pytest

from redcell.shared_rate_limit import SQLiteRateLimiter


async def test_two_instances_share_one_concurrency_limit(tmp_path) -> None:
    """Separate child-like instances must not each believe they own the same quota."""
    database_url = f"sqlite:///{tmp_path / 'rate-limit.db'}"
    left = SQLiteRateLimiter(
        database_url, provider_key="provider|model", min_interval_seconds=0, max_concurrency=1
    )
    right = SQLiteRateLimiter(
        database_url, provider_key="provider|model", min_interval_seconds=0, max_concurrency=1
    )
    active = 0
    peak = 0

    async def work(limiter: SQLiteRateLimiter) -> None:
        nonlocal active, peak
        async with limiter.hold():
            active += 1
            peak = max(peak, active)
            await asyncio.sleep(0.02)
            active -= 1

    await asyncio.gather(work(left), work(right))

    assert peak == 1


async def test_expired_lease_does_not_block_a_restarted_child(tmp_path) -> None:
    database_url = f"sqlite:///{tmp_path / 'rate-limit.db'}"
    abandoned = SQLiteRateLimiter(
        database_url,
        provider_key="provider|model",
        min_interval_seconds=0,
        max_concurrency=1,
        lease_timeout_seconds=0.01,
    )
    await abandoned.acquire("crashed-child")
    await asyncio.sleep(0.02)
    restarted = SQLiteRateLimiter(
        database_url,
        provider_key="provider|model",
        min_interval_seconds=0,
        max_concurrency=1,
        lease_timeout_seconds=0.01,
    )

    async with restarted.hold():
        pass


async def test_pre_reboot_monotonic_timestamps_do_not_block_a_new_process(tmp_path) -> None:
    """Persisted monotonic values from a prior boot must be stale after restart."""
    path = tmp_path / "rate-limit.db"
    database_url = f"sqlite:///{path}"
    limiter = SQLiteRateLimiter(
        database_url,
        provider_key="provider|model",
        min_interval_seconds=1,
        max_concurrency=1,
    )
    legacy_monotonic = time.monotonic() + 10_000
    with sqlite3.connect(path) as connection:
        connection.execute(
            "INSERT OR REPLACE INTO shared_provider_rate_limit "
            "(provider_key, active_count, last_started_at, min_interval_seconds, max_concurrency) "
            "VALUES (?, 1, ?, 1, 1)",
            ("provider|model", legacy_monotonic),
        )
        connection.execute(
            "INSERT INTO shared_provider_rate_limit_lease (provider_key, lease_id, expires_at) "
            "VALUES (?, ?, ?)",
            ("provider|model", "pre-reboot-child", legacy_monotonic),
        )

    await asyncio.wait_for(limiter.acquire("new-child"), timeout=0.5)
    await limiter.release("new-child")


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"provider_key": "  "}, "provider_key"),
        ({"min_interval_seconds": -1}, "min_interval_seconds"),
        ({"max_concurrency": -1}, "max_concurrency"),
        ({"lease_timeout_seconds": 0}, "lease_timeout_seconds"),
    ],
)
def test_invalid_limiter_configuration_is_rejected(tmp_path, kwargs, message) -> None:
    values = {
        "provider_key": "provider|model",
        "min_interval_seconds": 0,
        "max_concurrency": 1,
        "lease_timeout_seconds": 300,
        **kwargs,
    }
    with pytest.raises(ValueError, match=message):
        SQLiteRateLimiter(f"sqlite:///{tmp_path / 'rate-limit.db'}", **values)
