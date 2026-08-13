from __future__ import annotations

import asyncio

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
