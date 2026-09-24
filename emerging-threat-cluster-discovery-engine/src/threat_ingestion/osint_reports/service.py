from __future__ import annotations

import httpx

from threat_ingestion.config import Settings
from threat_ingestion.domain.models import OsintReportItem
from threat_ingestion.persistence.repositories import IngestionRepository

from .feeds import DEFAULT_FEEDS, fetch_all_feeds


async def sync_osint_reports(settings: Settings, repository: IngestionRepository) -> list[OsintReportItem]:
    """Pulls every configured OSINT research feed and upserts each item by link.
    A single broken/unreachable feed does not block the others."""
    all_items: list[OsintReportItem] = []
    async with httpx.AsyncClient(timeout=settings.timeout_seconds) as client:
        results = await fetch_all_feeds(client, DEFAULT_FEEDS)
    for result in results.values():
        if isinstance(result, list):
            all_items.extend(result)
    for item in all_items:
        repository.upsert_osint_report(item)
    repository.session.commit()
    return all_items
