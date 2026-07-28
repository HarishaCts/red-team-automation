"""Async persistence layer.

The default backend is SQLite (zero-config, file-based) via ``aiosqlite``. A
PostgreSQL DSN in ``REDTEAM_DATABASE_URL`` switches the store to asyncpg (see
:class:`PostgresStore`), which is only imported if actually used.

All campaigns, prompts, responses, and judgements are persisted so that runs are
reproducible, auditable, and queryable by the dashboard.
"""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from typing import Any, Optional

import aiosqlite

from .config import StorageConfig
from .models import AttackResult, Campaign

# --- schema ------------------------------------------------------------------
# Kept intentionally simple and portable across SQLite/Postgres. Timestamps are
# stored as ISO-8601 text; JSON blobs hold the full model for lossless replay.
_SCHEMA = """
CREATE TABLE IF NOT EXISTS campaigns (
    id            TEXT PRIMARY KEY,
    target_name   TEXT NOT NULL,
    target_model  TEXT NOT NULL,
    provider      TEXT NOT NULL,
    categories    TEXT NOT NULL,           -- JSON array
    started_at    TEXT NOT NULL,
    finished_at   TEXT,
    total_attacks INTEGER DEFAULT 0,
    total_breaches INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS results (
    attack_id     TEXT PRIMARY KEY,
    campaign_id   TEXT NOT NULL,
    category      TEXT NOT NULL,
    variant       INTEGER NOT NULL,
    mutation_round INTEGER NOT NULL,
    score         TEXT NOT NULL,
    breach_type   TEXT NOT NULL,
    is_breach     INTEGER NOT NULL,        -- 0/1
    data          TEXT NOT NULL,           -- full AttackResult JSON
    created_at    TEXT NOT NULL,
    FOREIGN KEY (campaign_id) REFERENCES campaigns(id)
);

CREATE INDEX IF NOT EXISTS idx_results_campaign ON results(campaign_id);
CREATE INDEX IF NOT EXISTS idx_results_category ON results(campaign_id, category);
"""


class Store(ABC):
    """Async persistence interface."""

    @abstractmethod
    async def init(self) -> None: ...

    @abstractmethod
    async def create_campaign(self, campaign: Campaign) -> None: ...

    @abstractmethod
    async def save_result(self, campaign_id: str, result: AttackResult) -> None: ...

    @abstractmethod
    async def finalize_campaign(self, campaign: Campaign) -> None: ...

    @abstractmethod
    async def list_campaigns(self, limit: int = 50) -> list[dict[str, Any]]: ...

    @abstractmethod
    async def get_campaign(self, campaign_id: str) -> Optional[dict[str, Any]]: ...

    @abstractmethod
    async def get_results(self, campaign_id: str) -> list[AttackResult]: ...

    @abstractmethod
    async def aclose(self) -> None: ...


class SQLiteStore(Store):
    """SQLite-backed store using aiosqlite (default backend)."""

    def __init__(self, path: str) -> None:
        # Strip the "sqlite:///" prefix if a URL was passed.
        self._path = path.replace("sqlite:///", "", 1)
        self._db: Optional[aiosqlite.Connection] = None

    async def init(self) -> None:
        self._db = await aiosqlite.connect(self._path)
        self._db.row_factory = aiosqlite.Row
        await self._db.executescript(_SCHEMA)
        await self._db.commit()

    @property
    def _conn(self) -> aiosqlite.Connection:
        if self._db is None:
            raise RuntimeError("Store.init() must be awaited before use.")
        return self._db

    async def create_campaign(self, campaign: Campaign) -> None:
        await self._conn.execute(
            """INSERT INTO campaigns
               (id, target_name, target_model, provider, categories, started_at)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (
                campaign.id,
                campaign.target_name,
                campaign.target_model,
                campaign.provider,
                json.dumps(campaign.categories),
                campaign.started_at.isoformat(),
            ),
        )
        await self._conn.commit()

    async def save_result(self, campaign_id: str, result: AttackResult) -> None:
        await self._conn.execute(
            """INSERT OR REPLACE INTO results
               (attack_id, campaign_id, category, variant, mutation_round,
                score, breach_type, is_breach, data, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                result.attack.id,
                campaign_id,
                result.attack.category,
                result.attack.variant,
                result.attack.mutation_round,
                result.judgement.score.value,
                result.judgement.breach_type,
                1 if result.is_breach else 0,
                result.model_dump_json(),
                result.attack.created_at.isoformat(),
            ),
        )
        await self._conn.commit()

    async def finalize_campaign(self, campaign: Campaign) -> None:
        await self._conn.execute(
            """UPDATE campaigns
               SET finished_at = ?, total_attacks = ?, total_breaches = ?
               WHERE id = ?""",
            (
                campaign.finished_at.isoformat() if campaign.finished_at else None,
                campaign.total_attacks,
                campaign.total_breaches,
                campaign.id,
            ),
        )
        await self._conn.commit()

    async def list_campaigns(self, limit: int = 50) -> list[dict[str, Any]]:
        cur = await self._conn.execute(
            "SELECT * FROM campaigns ORDER BY started_at DESC LIMIT ?", (limit,)
        )
        rows = await cur.fetchall()
        return [self._campaign_row(r) for r in rows]

    async def get_campaign(self, campaign_id: str) -> Optional[dict[str, Any]]:
        cur = await self._conn.execute(
            "SELECT * FROM campaigns WHERE id = ?", (campaign_id,)
        )
        row = await cur.fetchone()
        return self._campaign_row(row) if row else None

    async def get_results(self, campaign_id: str) -> list[AttackResult]:
        cur = await self._conn.execute(
            "SELECT data FROM results WHERE campaign_id = ? ORDER BY created_at",
            (campaign_id,),
        )
        rows = await cur.fetchall()
        return [AttackResult.model_validate_json(r["data"]) for r in rows]

    async def aclose(self) -> None:
        if self._db is not None:
            await self._db.close()
            self._db = None

    @staticmethod
    def _campaign_row(row: aiosqlite.Row) -> dict[str, Any]:
        d = dict(row)
        d["categories"] = json.loads(d["categories"])
        return d


def build_store(cfg: StorageConfig) -> Store:
    """Return the appropriate store based on configuration/environment.

    A ``postgresql://`` DSN selects :class:`PostgresStore`; anything else uses
    SQLite. Postgres support is imported lazily so the extra dependency is only
    required when actually used.
    """
    url = cfg.database_url
    if url.startswith("postgres"):
        from .db_postgres import PostgresStore  # optional dependency

        return PostgresStore(url)
    return SQLiteStore(cfg.sqlite_path)