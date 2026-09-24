from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Annotated

import typer

from .application import collect_once
from .application.enrich_and_cluster import indicators_pending_enrichment, run_cluster_detection
from .briefing_bridge import write_manual_signals
from .collectors import MalwareBazaarCollector, ThreatFoxCollector, URLhausCollector
from .config import get_settings
from .enrichment import EnrichmentEngine, default_providers
from .osint_reports import sync_osint_reports
from .persistence import IngestionRepository, session_factory
from .reporting import write_report
from .scheduler import start_scheduler
from .vulnerability_intel import lookup_cve, sync_kev_catalog

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


async def run_enrichment(limit: int) -> int:
    settings = get_settings()
    engine = EnrichmentEngine(default_providers(settings))
    session = session_factory(settings.database_url)()
    try:
        repository = IngestionRepository(session)
        indicators = indicators_pending_enrichment(session, limit)
        results = await engine.enrich_many(indicators, repository)
        return len(results)
    finally:
        await engine.aclose()
        session.close()


@app.command("enrich")
def enrich(
    limit: int = typer.Option(25, min=1, help="Number of domain/IP indicators to enrich this run."),
) -> None:
    """Pivot recently collected domains/IPs through RDAP, DNS, urlscan, and GreyNoise."""
    count = asyncio.run(run_enrichment(limit))
    typer.echo(f"Recorded {count} enrichment observations.")


@app.command("cluster")
def cluster() -> None:
    """Detect infrastructure clusters from observations + enrichment and persist them."""
    settings = get_settings()
    session = session_factory(settings.database_url)()
    try:
        repository = IngestionRepository(session)
        clusters = run_cluster_detection(session, repository)
        typer.echo(f"Detected {len(clusters)} candidate infrastructure clusters.")
        for candidate in clusters:
            typer.echo(f"  {candidate.cluster_key}: {candidate.summary}")
    finally:
        session.close()


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


@app.command("vuln-sync")
def vuln_sync() -> None:
    """Refresh the local CISA KEV catalog and attach EPSS exploitation-probability scores."""
    settings = get_settings()
    session = session_factory(settings.database_url)()
    try:
        repository = IngestionRepository(session)
        entries = asyncio.run(sync_kev_catalog(settings, repository))
        typer.echo(f"Synced {len(entries)} known-exploited vulnerabilities.")
    finally:
        session.close()


@app.command("vuln-lookup")
def vuln_lookup(cve_id: Annotated[str, typer.Argument(help="e.g. CVE-2021-44228")]) -> None:
    """Combine the local KEV catalog with live EPSS + NVD data for one CVE."""
    settings = get_settings()
    session = session_factory(settings.database_url)()
    try:
        repository = IngestionRepository(session)
        result = asyncio.run(lookup_cve(settings, repository, cve_id.upper()))
        typer.echo(result.model_dump_json(indent=2))
    finally:
        session.close()


@app.command("osint-sync")
def osint_sync() -> None:
    """Pull the latest posts from Unit 42, The DFIR Report, and CISA advisories."""
    settings = get_settings()
    session = session_factory(settings.database_url)()
    try:
        repository = IngestionRepository(session)
        items = asyncio.run(sync_osint_reports(settings, repository))
        typer.echo(f"Synced {len(items)} OSINT report items.")
    finally:
        session.close()


@app.command("export-signals")
def export_signals(
    output: str = typer.Option(
        "reports/manual-signals.json",
        help=(
            "Where to write Signal-schema JSON. Point this at a companion project's "
            "data/manual_signals.json (e.g. Daily-Cyber-Threat-Intelligence-Briefing) "
            "to fold infrastructure clusters and observed KEV exposure into its report."
        ),
    ),
) -> None:
    """Export infrastructure clusters + observed KEV exposure as manual_signals.json."""
    settings = get_settings()
    session = session_factory(settings.database_url)()
    try:
        count = write_manual_signals(session, Path(output))
        typer.echo(f"Wrote {count} signals to {output}")
    finally:
        session.close()


def run_collection_sync(source: str | None, dry_run: bool) -> dict:
    return asyncio.run(run_collection(source, dry_run))