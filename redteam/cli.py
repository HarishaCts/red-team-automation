"""Command-line interface for the red-team framework.

Commands:
    redteam run             Run a full red-team campaign and write a report.
    redteam report          Re-render the report for a past run.
    redteam list-runs       List recent campaigns.
    redteam export-baseline Export a run's JSON regression baseline.
    redteam categories      List available attack categories.
"""

from __future__ import annotations

import asyncio
import json
import logging
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.logging import RichHandler
from rich.table import Table

from .categories import CATEGORIES
from .config import Config
from .db import build_store
from .engine import RedTeamEngine
from .models import AttackResult, Campaign, RiskScore

app = typer.Typer(
    add_completion=False,
    help="Automated adversarial prompt red-teaming for LLM applications.",
)
console = Console()

# Color coding for scores in terminal output.
_SCORE_STYLE = {
    RiskScore.CRITICAL: "bold white on red",
    RiskScore.HIGH: "bold red",
    RiskScore.MEDIUM: "yellow",
    RiskScore.LOW: "cyan",
    RiskScore.PASS: "green",
}


def _setup_logging(verbose: bool) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(message)s",
        datefmt="[%X]",
        handlers=[RichHandler(console=console, show_path=False, markup=True)],
    )
    # Quiet noisy third-party loggers unless verbose.
    if not verbose:
        logging.getLogger("httpx").setLevel(logging.WARNING)
        logging.getLogger("anthropic").setLevel(logging.WARNING)


# ---------------------------------------------------------------------------
# run
# ---------------------------------------------------------------------------
@app.command()
def run(
    config: Optional[Path] = typer.Option(
        None, "--config", "-c", help="Path to config YAML (defaults used if omitted)."
    ),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Debug logging."),
) -> None:
    """Run a full red-team campaign against the configured target."""
    _setup_logging(verbose)
    cfg = Config.load(config)

    provider = cfg.llm.resolve_provider()
    if provider == "mock":
        console.print(
            "[yellow]No ANTHROPIC_API_KEY found — running in MOCK mode "
            "(offline, deterministic). Set the key to use the real Claude API.[/yellow]"
        )

    campaign, results = asyncio.run(_run_campaign(cfg))
    _print_summary(campaign, results)

    # Build and write the report(s).
    report_paths = asyncio.run(_write_report(cfg, campaign, results))
    for p in report_paths:
        console.print(f"[green]Report written:[/green] {p}")
    console.print(f"\n[bold]Run ID:[/bold] {campaign.id}")


async def _run_campaign(cfg: Config) -> tuple[Campaign, list[AttackResult]]:
    """Drive the engine and stream a one-line progress update per result."""
    async with RedTeamEngine(cfg) as engine:
        completed = 0

        async def on_result(result: AttackResult) -> None:
            nonlocal completed
            completed += 1
            style = _SCORE_STYLE[result.judgement.score]
            tag = f"[{style}]{result.judgement.score.value.upper():^8}[/]"
            console.print(
                f"  {tag} {result.attack.category:<22} "
                f"variant {result.attack.variant} "
                f"(round {result.attack.mutation_round})"
            )

        return await engine.run_campaign(on_result=on_result)


async def _write_report(
    cfg: Config, campaign: Campaign, results: list[AttackResult]
) -> list[Path]:
    """Build the report and persist the configured formats to disk."""
    out_dir = Path(cfg.report.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    paths: list[Path] = []

    # The reporter needs an engine (for the LLM narrative), but we already
    # closed the campaign engine; build a lightweight one just for reporting.
    async with RedTeamEngine(cfg) as engine:
        report = await engine.build_report(campaign, results)

        if "json" in cfg.report.formats:
            jpath = out_dir / f"report_{campaign.id}.json"
            jpath.write_text(json.dumps(report, indent=2), encoding="utf-8")
            paths.append(jpath)

        if "markdown" in cfg.report.formats:
            mpath = out_dir / f"report_{campaign.id}.md"
            mpath.write_text(engine.render_markdown(report), encoding="utf-8")
            paths.append(mpath)

    return paths


# ---------------------------------------------------------------------------
# report
# ---------------------------------------------------------------------------
@app.command()
def report(
    run_id: str = typer.Option(..., "--run-id", "-r", help="Campaign/run ID."),
    config: Optional[Path] = typer.Option(None, "--config", "-c"),
) -> None:
    """Re-render the report for a previously stored run."""
    _setup_logging(False)
    cfg = Config.load(config)
    campaign, results = asyncio.run(_load_run(cfg, run_id))
    if campaign is None:
        console.print(f"[red]No campaign found with ID {run_id}[/red]")
        raise typer.Exit(code=1)
    _print_summary(campaign, results)
    paths = asyncio.run(_write_report(cfg, campaign, results))
    for p in paths:
        console.print(f"[green]Report written:[/green] {p}")


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


# ---------------------------------------------------------------------------
# list-runs
# ---------------------------------------------------------------------------
@app.command("list-runs")
def list_runs(
    config: Optional[Path] = typer.Option(None, "--config", "-c"),
    limit: int = typer.Option(20, "--limit", "-n"),
) -> None:
    """List recent red-team campaigns."""
    _setup_logging(False)
    cfg = Config.load(config)
    rows = asyncio.run(_list_runs(cfg, limit))
    if not rows:
        console.print("No campaigns found. Run `redteam run` first.")
        return
    table = Table(title="Red-Team Campaigns")
    table.add_column("Run ID", style="cyan", no_wrap=True)
    table.add_column("Target")
    table.add_column("Provider")
    table.add_column("Attacks", justify="right")
    table.add_column("Breaches", justify="right")
    table.add_column("Started")
    for r in rows:
        table.add_row(
            r["id"], r["target_name"], r["provider"],
            str(r.get("total_attacks", 0)), str(r.get("total_breaches", 0)),
            str(r["started_at"]),
        )
    console.print(table)


async def _list_runs(cfg: Config, limit: int) -> list[dict]:
    store = build_store(cfg.storage)
    await store.init()
    try:
        return await store.list_campaigns(limit)
    finally:
        await store.aclose()


# ---------------------------------------------------------------------------
# export-baseline
# ---------------------------------------------------------------------------
@app.command("export-baseline")
def export_baseline(
    run_id: str = typer.Option(..., "--run-id", "-r"),
    output: Optional[Path] = typer.Option(None, "--output", "-o"),
    config: Optional[Path] = typer.Option(None, "--config", "-c"),
) -> None:
    """Export a run's JSON regression baseline for future comparison."""
    _setup_logging(False)
    cfg = Config.load(config)
    campaign, results = asyncio.run(_load_run(cfg, run_id))
    if campaign is None:
        console.print(f"[red]No campaign found with ID {run_id}[/red]")
        raise typer.Exit(code=1)

    baseline = {
        "run_id": campaign.id,
        "target_model": campaign.target_model,
        "prompts": [
            {
                "category": r.attack.category,
                "variant": r.attack.variant,
                "mutation_round": r.attack.mutation_round,
                "prompt": r.attack.prompt,
                "score": r.judgement.score.value,
                "breach_type": r.judgement.breach_type,
            }
            for r in results
        ],
    }
    out = output or Path(cfg.report.output_dir) / f"baseline_{campaign.id}.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(baseline, indent=2), encoding="utf-8")
    console.print(f"[green]Baseline exported:[/green] {out}")


# ---------------------------------------------------------------------------
# categories
# ---------------------------------------------------------------------------
@app.command()
def categories() -> None:
    """List the available attack categories."""
    table = Table(title="Attack Categories")
    table.add_column("Key", style="cyan")
    table.add_column("Title")
    table.add_column("Objective")
    for cat in CATEGORIES.values():
        table.add_row(cat.key, cat.title, cat.objective)
    console.print(table)


# ---------------------------------------------------------------------------
# shared helpers
# ---------------------------------------------------------------------------
def _print_summary(campaign: Campaign, results: list[AttackResult]) -> None:
    """Print a compact severity breakdown after a run/report."""
    dist = {s: 0 for s in RiskScore}
    for r in results:
        dist[r.judgement.score] += 1
    table = Table(title=f"Campaign {campaign.id} — {campaign.target_name}")
    table.add_column("Severity")
    table.add_column("Count", justify="right")
    for score in reversed(list(RiskScore)):  # critical first
        table.add_row(
            f"[{_SCORE_STYLE[score]}]{score.value.upper()}[/]", str(dist[score])
        )
    console.print(table)


if __name__ == "__main__":  # pragma: no cover
    app()