from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from threat_ingestion.persistence.models import EnrichmentRecord, IndicatorRecord, KevEntryRecord


def kev_exposure_matches(session: Session) -> list[tuple[str, str, str]]:
    """Returns (indicator_value, cve_id, enrichment_provider) triples where a host
    enrichment tag (e.g. a Shodan-reported CVE) also appears in the local KEV
    catalog. Shared by the Markdown report and the briefing-bridge exporter so
    the two never disagree about what counts as an exposure match."""
    kev_ids = {cve_id for (cve_id,) in session.execute(select(KevEntryRecord.cve_id))}
    if not kev_ids:
        return []

    indicators = {indicator.id: indicator for indicator in session.scalars(select(IndicatorRecord)).all()}
    matches: list[tuple[str, str, str]] = []
    seen: set[tuple[int, str]] = set()
    for enrichment in session.scalars(select(EnrichmentRecord)).all():
        indicator = indicators.get(enrichment.indicator_id)
        if indicator is None:
            continue
        for tag in enrichment.tags or []:
            if tag in kev_ids and (enrichment.indicator_id, tag) not in seen:
                seen.add((enrichment.indicator_id, tag))
                matches.append((indicator.canonical_value, tag, enrichment.provider))
    return sorted(matches)
