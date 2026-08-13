"""SQLite-backed provider rate coordination shared by matrix child processes."""

from __future__ import annotations

import asyncio
import secrets
import sqlite3
import time
from contextlib import asynccontextmanager
from pathlib import Path


class SQLiteRateLimiter:
    """Coordinate start rate and in-flight count for one non-secret provider key."""

    def __init__(
        self,
        database_url: str,
        *,
        provider_key: str,
        min_interval_seconds: float,
        max_concurrency: int,
        lease_timeout_seconds: float = 300.0,
    ) -> None:
        if not database_url.startswith("sqlite:///"):
            raise ValueError("共享速率协调器只支持 sqlite:/// 数据库 URL")
        self._path = database_url.removeprefix("sqlite:///")
        self._provider_key = provider_key
        self._min_interval = min_interval_seconds
        self._max_concurrency = max_concurrency
        self._lease_timeout = lease_timeout_seconds
        if not self._path:
            raise ValueError("共享速率协调器需要一个 SQLite 文件路径")
        Path(self._path).parent.mkdir(parents=True, exist_ok=True)
        self._initialise()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self._path, timeout=30.0, isolation_level=None)
        connection.execute("PRAGMA busy_timeout = 30000")
        return connection

    def _initialise(self) -> None:
        with self._connect() as connection:
            connection.execute(
                "CREATE TABLE IF NOT EXISTS shared_provider_rate_limit ("
                "provider_key TEXT PRIMARY KEY, active_count INTEGER NOT NULL, "
                "last_started_at REAL, min_interval_seconds REAL NOT NULL, "
                "max_concurrency INTEGER NOT NULL)"
            )
            connection.execute(
                "CREATE TABLE IF NOT EXISTS shared_provider_rate_limit_lease ("
                "provider_key TEXT NOT NULL, lease_id TEXT NOT NULL, expires_at REAL NOT NULL, "
                "PRIMARY KEY (provider_key, lease_id))"
            )

    def _try_acquire(self, lease_id: str) -> float:
        now = time.monotonic()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT active_count, last_started_at, min_interval_seconds, max_concurrency "
                "FROM shared_provider_rate_limit WHERE provider_key = ?",
                (self._provider_key,),
            ).fetchone()
            connection.execute(
                "DELETE FROM shared_provider_rate_limit_lease "
                "WHERE provider_key = ? AND expires_at <= ?",
                (self._provider_key, now),
            )
            active = connection.execute(
                "SELECT COUNT(*) FROM shared_provider_rate_limit_lease WHERE provider_key = ?",
                (self._provider_key,),
            ).fetchone()[0]
            if row is None:
                last_started, interval, limit = (
                    None,
                    self._min_interval,
                    self._max_concurrency,
                )
                connection.execute(
                    "INSERT INTO shared_provider_rate_limit "
                    "(provider_key, active_count, last_started_at, "
                    "min_interval_seconds, max_concurrency) "
                    "VALUES (?, 0, NULL, ?, ?)",
                    (self._provider_key, interval, limit),
                )
            else:
                _stored_active, last_started, saved_interval, saved_limit = row
                interval = max(float(saved_interval), self._min_interval)
                limits = [item for item in (int(saved_limit), self._max_concurrency) if item > 0]
                limit = min(limits) if limits else 0
                connection.execute(
                    "UPDATE shared_provider_rate_limit SET min_interval_seconds = ?, "
                    "max_concurrency = ? "
                    "WHERE provider_key = ?",
                    (interval, limit, self._provider_key),
                )
            if limit > 0 and active >= limit:
                connection.commit()
                return 0.05
            if last_started is not None:
                remaining = interval - (now - float(last_started))
                if remaining > 0:
                    connection.commit()
                    return remaining
            connection.execute(
                "UPDATE shared_provider_rate_limit SET active_count = ?, last_started_at = ? "
                "WHERE provider_key = ?",
                (active + 1, now, self._provider_key),
            )
            connection.execute(
                "INSERT INTO shared_provider_rate_limit_lease (provider_key, lease_id, expires_at) "
                "VALUES (?, ?, ?)",
                (self._provider_key, lease_id, now + self._lease_timeout),
            )
            connection.commit()
        return 0.0

    async def acquire(self, lease_id: str) -> None:
        while True:
            wait = await asyncio.to_thread(self._try_acquire, lease_id)
            if wait <= 0:
                return
            await asyncio.sleep(wait)

    def _release(self, lease_id: str) -> None:
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            deleted = connection.execute(
                "DELETE FROM shared_provider_rate_limit_lease "
                "WHERE provider_key = ? AND lease_id = ?",
                (self._provider_key, lease_id),
            ).rowcount
            if not deleted:
                connection.rollback()
                raise RuntimeError("共享速率协调器释放了不存在的 reservation")
            active = connection.execute(
                "SELECT COUNT(*) FROM shared_provider_rate_limit_lease WHERE provider_key = ?",
                (self._provider_key,),
            ).fetchone()[0]
            connection.execute(
                "UPDATE shared_provider_rate_limit SET active_count = ? WHERE provider_key = ?",
                (active, self._provider_key),
            )
            connection.commit()

    async def release(self, lease_id: str) -> None:
        await asyncio.to_thread(self._release, lease_id)

    @asynccontextmanager
    async def hold(self):
        lease_id = secrets.token_hex(16)
        await self.acquire(lease_id)
        try:
            yield
        finally:
            await self.release(lease_id)
