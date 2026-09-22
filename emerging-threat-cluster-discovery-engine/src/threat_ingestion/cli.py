from __future__ import annotations

import asyncio
from typing import Annotated

import typer

from .application import collect_once
from .collectors import MalwareBazaarCollector, ThreatFoxCollector, URLhausCollector
from .config import get_settings
from .persistence import IngestionRepository, session_factory
from .reporting import write_report
from .scheduler import start_scheduler

app = typer.Typer(no_args_is_help=True)


async def run_collection(source: str | None, dry_run: bool) -> dict:
    settings = get_settings()
    collector_types = {"threatfox": ThreatFoxCollector, "urlhaus": URLhausCollector, "malwarebazaar": MalwareBazaarCollector}
    selected = [source] if source else list(collector_types)
    collectors = [collector_types[name](settings) for name in selected]
    session = session_factory(settings.database_url)()
    try:
        run = await collect_once(collectors, IngestionRepository(session), dry_run)
        return run.model_dump(mode="json")
    finally:
        await asyncio.gather(*(collector.client.aclose() for collector in collectors))
        session.close()


@app.command("collect")
def collect(dry_run: bool = typer.Option(False, help="Fetch and normalize without persisting.")) -> None:
    typer.echo(run_collection_sync(None, dry_run))


@app.command("collect-source")
def collect_source(
    source: Annotated[str, typer.Argument(help="threatfox, urlhaus, or malwarebazaar")],
    dry_run: bool = typer.Option(False, help="Fetch and normalize without persisting."),
) -> None:
    if source not in {"threatfox", "urlhaus", "malwarebazaar"}:
        raise typer.BadParameter("must be threatfox, urlhaus, or malwarebazaar")
    typer.echo(run_collection_sync(source, dry_run))


@app.command("schedule")
def schedule() -> None:
    start_scheduler()


@app.command("report")
def report(
    output: str = typer.Option("reports/threat-intelligence-report.md", help="Markdown report path."),
    recent_limit: int = typer.Option(20, min=0, help="Recent observations to include."),
) -> None:
    settings = get_settings()
    session = session_factory(settings.database_url)()
    try:
        report_path = write_report(session, output, recent_limit=recent_limit)
        typer.echo(f"Wrote report to {report_path}")
    finally:
        session.close()


def run_collection_sync(source: str | None, dry_run: bool) -> dict:
    return asyncio.run(run_collection(source, dry_run))