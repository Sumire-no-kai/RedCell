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


async def _acquire_up_to(limiter: SQLiteRateLimiter, count: int) -> int:
    """How many leases `limiter` hands out within a short window (none are released)."""
    granted = 0
    for index in range(count):
        try:
            await asyncio.wait_for(limiter.acquire(f"lease-{index}"), timeout=0.3)
        except TimeoutError:
            break
        granted += 1
    return granted


def _stored_limits(path) -> tuple[int, float]:
    with sqlite3.connect(path) as connection:
        return connection.execute(
            "SELECT max_concurrency, min_interval_seconds FROM shared_provider_rate_limit"
        ).fetchone()


@pytest.mark.parametrize(
    ("saved", "configured", "granted"),
    [(1, 3, 3), (3, 1, 1), (1, 0, 4)],
    ids=["raised", "lowered", "unlimited"],
)
async def test_configured_concurrency_cap_replaces_the_saved_one(
    tmp_path, saved: int, configured: int, granted: int
) -> None:
    """Phase 0.5e: a calibration-era cap of 1 kept pinning the later, higher configuration."""
    path = tmp_path / "rate-limit.db"
    database_url = f"sqlite:///{path}"
    earlier = SQLiteRateLimiter(
        database_url, provider_key="provider|model", min_interval_seconds=0, max_concurrency=saved
    )
    await earlier.acquire("earlier-run")
    await earlier.release("earlier-run")

    current = SQLiteRateLimiter(
        database_url,
        provider_key="provider|model",
        min_interval_seconds=0,
        max_concurrency=configured,
    )

    assert await _acquire_up_to(current, 4) == granted
    assert _stored_limits(path)[0] == configured


async def test_configured_interval_replaces_the_saved_one(tmp_path) -> None:
    path = tmp_path / "rate-limit.db"
    database_url = f"sqlite:///{path}"
    earlier = SQLiteRateLimiter(
        database_url, provider_key="provider|model", min_interval_seconds=60, max_concurrency=0
    )
    await earlier.acquire("earlier-run")
    await earlier.release("earlier-run")

    current = SQLiteRateLimiter(
        database_url, provider_key="provider|model", min_interval_seconds=0, max_concurrency=0
    )

    assert await _acquire_up_to(current, 2) == 2
    assert _stored_limits(path)[1] == 0


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


async def test_rate_limit_cooldown_is_shared_across_child_like_instances(tmp_path) -> None:
    database_url = f"sqlite:///{tmp_path / 'rate-limit.db'}"
    left = SQLiteRateLimiter(
        database_url, provider_key="provider|model", min_interval_seconds=0, max_concurrency=1
    )
    right = SQLiteRateLimiter(
        database_url, provider_key="provider|model", min_interval_seconds=0, max_concurrency=1
    )

    assert await left.record_rate_limit(retry_after_seconds=0.03) == pytest.approx(0.03)
    started = time.perf_counter()
    await right.acquire("cooldown-observer")
    elapsed = time.perf_counter() - started
    await right.release("cooldown-observer")

    assert elapsed >= 0.02


async def test_rate_limit_without_retry_after_uses_a_capped_shared_streak(tmp_path) -> None:
    limiter = SQLiteRateLimiter(
        f"sqlite:///{tmp_path / 'rate-limit.db'}",
        provider_key="provider|model",
        min_interval_seconds=0,
        max_concurrency=1,
    )

    delays = [await limiter.record_rate_limit() for _ in range(6)]

    assert delays == [5.0, 10.0, 20.0, 40.0, 60.0, 60.0]


async def test_success_after_an_expired_or_zero_cooldown_resets_the_shared_streak(tmp_path) -> None:
    limiter = SQLiteRateLimiter(
        f"sqlite:///{tmp_path / 'rate-limit.db'}",
        provider_key="provider|model",
        min_interval_seconds=0,
        max_concurrency=1,
    )

    assert await limiter.record_rate_limit(retry_after_seconds=0) == 0.0
    await limiter.record_success()

    assert await limiter.record_rate_limit() == 5.0


def test_legacy_limiter_database_is_migrated_without_rebuilding_it(tmp_path) -> None:
    path = tmp_path / "rate-limit.db"
    with sqlite3.connect(path) as connection:
        connection.execute(
            "CREATE TABLE shared_provider_rate_limit ("
            "provider_key TEXT PRIMARY KEY, active_count INTEGER NOT NULL, "
            "last_started_at REAL, min_interval_seconds REAL NOT NULL, "
            "max_concurrency INTEGER NOT NULL)"
        )
        connection.execute(
            "CREATE TABLE shared_provider_rate_limit_lease ("
            "provider_key TEXT NOT NULL, lease_id TEXT NOT NULL, expires_at REAL NOT NULL, "
            "PRIMARY KEY (provider_key, lease_id))"
        )

    limiter = SQLiteRateLimiter(
        f"sqlite:///{path}",
        provider_key="provider|model",
        min_interval_seconds=0,
        max_concurrency=1,
    )
    with sqlite3.connect(path) as connection:
        columns = {
            row[1]
            for row in connection.execute(
                "PRAGMA table_info(shared_provider_rate_limit)"
            ).fetchall()
        }

    assert {"blocked_until", "consecutive_rate_limits"}.issubset(columns)
    assert limiter._cooldown_seconds(consecutive_rate_limits=1, retry_after_seconds=None) == 5.0


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
