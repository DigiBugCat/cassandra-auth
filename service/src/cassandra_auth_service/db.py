"""Async SQLite with WAL mode."""

from __future__ import annotations

from pathlib import Path

import aiosqlite


class Database:
    def __init__(self, path: str | Path) -> None:
        self._path = str(path)
        self._conn: aiosqlite.Connection | None = None

    async def open(self) -> None:
        self._conn = await aiosqlite.connect(self._path)
        self._conn.row_factory = aiosqlite.Row
        await self._conn.execute("PRAGMA journal_mode=WAL")
        await self._conn.execute("PRAGMA foreign_keys=ON")
        await self._conn.execute("PRAGMA busy_timeout=5000")

    async def close(self) -> None:
        if self._conn:
            await self._conn.close()
            self._conn = None

    @property
    def conn(self) -> aiosqlite.Connection:
        if self._conn is None:
            raise RuntimeError("Database not open")
        return self._conn

    async def execute(self, sql: str, params: tuple = ()) -> aiosqlite.Cursor:
        return await self.conn.execute(sql, params)

    async def execute_script(self, sql: str) -> None:
        await self.conn.executescript(sql)

    async def fetchone(self, sql: str, params: tuple = ()) -> aiosqlite.Row | None:
        cursor = await self.conn.execute(sql, params)
        return await cursor.fetchone()

    async def fetchall(self, sql: str, params: tuple = ()) -> list[aiosqlite.Row]:
        cursor = await self.conn.execute(sql, params)
        return await cursor.fetchall()

    async def commit(self) -> None:
        await self.conn.commit()
