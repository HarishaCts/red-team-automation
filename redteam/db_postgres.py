"""Optional PostgreSQL persistence backend (asyncpg).

Imported lazily by :func:`redteam.db.build_store` only when a ``postgresql://``
DSN is configured. Install with the ``postgres`` extra:

    pip install -e ".[postgres]"
"""

from __future__ import annotations

import json
from typing import Any, Optional

from .models import AttackResult, Campaign

_SCHEMA = """
CREATE TABLE IF NOT EXISTS campaigns (
    id             TEXT PRIMARY KEY,
    target_name    TEXT NOT NULL,
    target_model   TEXT NOT NULL,
    provider       TEXT NOT NULL,
    categories     JSONB NOT NULL,
    started_at     TIMESTAMPTZ NOT NULL,
    finished_at    TIMESTAMPTZ,
    total_attacks  INTEGER DEFAULT 0,
    total_breaches INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS results (
    attack_id      TEXT PRIMARY KEY,
    campaign_id    TEXT NOT NULL REFERENCES campaigns(id),
    category       TEXT NOT NULL,
    variant        INTEGER NOT NULL,
    mutation_round INTEGER NOT NULL,
    score          TEXT NOT NULL,
    breach_type    TEXT NOT NULL,
    is_breach      BOOLEAN NOT NULL,
    data           JSONB NOT NULL,
    created_at     TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_results_campaign ON results(campaign_id);
"""


class PostgresStore:
    """asyncpg-backed store mirroring :class:`redteam.db.SQLiteStore`."""

    def __init__(self, dsn: str) -> None:
        self._dsn = dsn
        self._pool: Optional[Any] = None

    async def init(self) -> None:
        import asyncpg

        self._pool = await asyncpg.create_pool(self._dsn)
        async with self._pool.acquire() as conn:
            await conn.execute(_SCHEMA)

    async def create_campaign(self, campaign: Campaign) -> None:
        async with self._pool.acquire() as conn:  # type: ignore[union-attr]
            await conn.execute(
                """INSERT INTO campaigns
                   (id, target_name, target_model, provider, categories, started_at)
                   VALUES ($1, $2, $3, $4, $5, $6)""",
                campaign.id,
                campaign.target_name,
                campaign.target_model,
                campaign.provider,
                json.dumps(campaign.categories),
                campaign.started_at,
            )

    async def save_result(self, campaign_id: str, result: AttackResult) -> None:
        async with self._pool.acquire() as conn:  # type: ignore[union-attr]
            await conn.execute(
                """INSERT INTO results
                   (attack_id, campaign_id, category, variant, mutation_round,
                    score, breach_type, is_breach, data, created_at)
                   VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
                   ON CONFLICT (attack_id) DO UPDATE SET data = EXCLUDED.data""",
                result.attack.id,
                campaign_id,
                result.attack.category,
                result.attack.variant,
                result.attack.mutation_round,
                result.judgement.score.value,
                result.judgement.breach_type,
                result.is_breach,
                result.model_dump_json(),
                result.attack.created_at,
            )

    async def finalize_campaign(self, campaign: Campaign) -> None:
        async with self._pool.acquire() as conn:  # type: ignore[union-attr]
            await conn.execute(
                """UPDATE campaigns
                   SET finished_at=$1, total_attacks=$2, total_breaches=$3
                   WHERE id=$4""",
                campaign.finished_at,
                campaign.total_attacks,
                campaign.total_breaches,
                campaign.id,
            )

    async def list_campaigns(self, limit: int = 50) -> list[dict[str, Any]]:
        async with self._pool.acquire() as conn:  # type: ignore[union-attr]
            rows = await conn.fetch(
                "SELECT * FROM campaigns ORDER BY started_at DESC LIMIT $1", limit
            )
        return [self._row(r) for r in rows]

    async def get_campaign(self, campaign_id: str) -> Optional[dict[str, Any]]:
        async with self._pool.acquire() as conn:  # type: ignore[union-attr]
            row = await conn.fetchrow(
                "SELECT * FROM campaigns WHERE id=$1", campaign_id
            )
        return self._row(row) if row else None

    async def get_results(self, campaign_id: str) -> list[AttackResult]:
        async with self._pool.acquire() as conn:  # type: ignore[union-attr]
            rows = await conn.fetch(
                "SELECT data FROM results WHERE campaign_id=$1 ORDER BY created_at",
                campaign_id,
            )
        return [AttackResult.model_validate_json(r["data"]) for r in rows]

    async def aclose(self) -> None:
        if self._pool is not None:
            await self._pool.close()
            self._pool = None

    @staticmethod
    def _row(row: Any) -> dict[str, Any]:
        d = dict(row)
        if isinstance(d.get("categories"), str):
            d["categories"] = json.loads(d["categories"])
        # Normalize timestamps to ISO strings for JSON responses.
        for k in ("started_at", "finished_at"):
            if d.get(k) is not None and not isinstance(d[k], str):
                d[k] = d[k].isoformat()
        return d