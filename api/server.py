"""FastAPI backend for the red-team dashboard.

Endpoints:
    GET  /api/health                      -> liveness probe
    GET  /api/categories                  -> attack category catalog
    GET  /api/runs                        -> list campaigns
    GET  /api/runs/{run_id}               -> campaign metadata + full report
    GET  /api/runs/{run_id}/results       -> raw results (prompt inventory)
    POST /api/runs                        -> launch a new campaign (async)
    GET  /api/runs/{run_id}/stream        -> Server-Sent Events live attack feed

The live feed uses SSE (rather than websockets) for simplicity and proxy
friendliness. A new campaign is run in a background task; results are pushed onto
a per-run asyncio.Queue that the SSE endpoint drains.
"""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
from typing import Any, Optional

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from redteam.categories import CATEGORIES
from redteam.config import Config
from redteam.db import build_store
from redteam.engine import RedTeamEngine
from redteam.models import AttackResult, Campaign

app = FastAPI(title="Red-Team Automation API", version="1.0.0")

# The Vite dev server runs on :5173; allow it (and configurable extra origins).
_origins = ["http://localhost:5173", "http://127.0.0.1:5173"]
if extra := os.getenv("REDTEAM_CORS_ORIGINS"):
    _origins.extend(extra.split(","))
app.add_middleware(
    CORSMiddleware,
    allow_origins=_origins,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Config path is resolvable via env so the API and CLI share one config.
_CONFIG_PATH = os.getenv("REDTEAM_CONFIG", "config/config.yaml")


def _load_config() -> Config:
    path = _CONFIG_PATH if Path(_CONFIG_PATH).exists() else None
    return Config.load(path)


# In-memory registry of live campaigns: run_id -> event queue.
# For a single-process deployment this is sufficient; a multi-worker deployment
# would back this with Redis pub/sub.
_live_queues: dict[str, asyncio.Queue] = {}


# ---------------------------------------------------------------------------
# Simple read endpoints
# ---------------------------------------------------------------------------
@app.get("/api/health")
async def health() -> dict[str, str]:
    cfg = _load_config()
    return {"status": "ok", "provider": cfg.llm.resolve_provider()}


@app.get("/api/categories")
async def get_categories() -> list[dict[str, str]]:
    return [
        {"key": c.key, "title": c.title, "objective": c.objective}
        for c in CATEGORIES.values()
    ]


@app.get("/api/runs")
async def list_runs(limit: int = 50) -> list[dict[str, Any]]:
    store = build_store(_load_config().storage)
    await store.init()
    try:
        return await store.list_campaigns(limit)
    finally:
        await store.aclose()


@app.get("/api/runs/{run_id}")
async def get_run(run_id: str) -> dict[str, Any]:
    cfg = _load_config()
    campaign, results = await _load_run(cfg, run_id)
    if campaign is None:
        raise HTTPException(status_code=404, detail="run not found")
    async with RedTeamEngine(cfg) as engine:
        report = await engine.build_report(campaign, results)
    return report


@app.get("/api/runs/{run_id}/results")
async def get_results(run_id: str) -> list[dict[str, Any]]:
    store = build_store(_load_config().storage)
    await store.init()
    try:
        results = await store.get_results(run_id)
        return [r.model_dump(mode="json") for r in results]
    finally:
        await store.aclose()


# ---------------------------------------------------------------------------
# Launch a campaign
# ---------------------------------------------------------------------------
class RunRequest(BaseModel):
    """Optional overrides for a launched campaign (falls back to config file)."""

    categories: Optional[list[str]] = None
    variants_per_category: Optional[int] = None


@app.post("/api/runs")
async def launch_run(req: RunRequest) -> dict[str, str]:
    """Kick off a campaign in the background and return its run ID immediately."""
    cfg = _load_config()
    if req.categories is not None:
        cfg.campaign.categories = req.categories
    if req.variants_per_category is not None:
        cfg.campaign.variants_per_category = req.variants_per_category

    # Pre-generate the run ID so the client can open the SSE stream right away.
    queue: asyncio.Queue = asyncio.Queue()

    # Launch the campaign as a detached background task.
    async def _worker() -> None:
        async with RedTeamEngine(cfg) as engine:
            async def on_result(result: AttackResult) -> None:
                await queue.put(result.model_dump(mode="json"))

            campaign, _ = await engine.run_campaign(on_result=on_result)
            # Signal completion to the SSE stream.
            await queue.put({"event": "done", "run_id": campaign.id})

    task = asyncio.create_task(_worker())
    # We don't know the campaign ID until the worker creates it; instead we key
    # the queue by the task id and expose a stream that the client subscribes to
    # via the returned token.
    token = str(id(task))
    _live_queues[token] = queue
    return {"stream_token": token}


@app.get("/api/stream/{token}")
async def stream(token: str) -> StreamingResponse:
    """Server-Sent Events feed for an in-progress campaign."""
    queue = _live_queues.get(token)
    if queue is None:
        raise HTTPException(status_code=404, detail="unknown stream token")

    async def event_gen():
        try:
            while True:
                item = await queue.get()
                yield f"data: {json.dumps(item)}\n\n"
                if isinstance(item, dict) and item.get("event") == "done":
                    break
        finally:
            _live_queues.pop(token, None)

    return StreamingResponse(event_gen(), media_type="text/event-stream")


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
async def _load_run(
    cfg: Config, run_id: str
) -> tuple[Optional[Campaign], list[AttackResult]]:
    store = build_store(cfg.storage)
    await store.init()
    try:
        row = await store.get_campaign(run_id)
        if row is None:
            return None, []
        results = await store.get_results(run_id)
        campaign = Campaign(
            id=row["id"],
            target_name=row["target_name"],
            target_model=row["target_model"],
            provider=row["provider"],
            categories=row["categories"],
            variants_per_category=0,
            total_attacks=row.get("total_attacks", len(results)),
            total_breaches=row.get("total_breaches", 0),
        )
        return campaign, results
    finally:
        await store.aclose()