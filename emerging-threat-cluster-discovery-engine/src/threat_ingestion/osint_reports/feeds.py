from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from xml.etree import ElementTree

import httpx

from threat_ingestion.domain.models import OsintReportItem

_ATOM_NS = "{http://www.w3.org/2005/Atom}"

# Curated set of established CTI research feeds. RSS (Unit 42, DFIR Report) and
# Atom (CISA) are both supported by the parser below.
DEFAULT_FEEDS: dict[str, str] = {
    "unit42": "https://unit42.paloaltonetworks.com/feed/",
    "dfir_report": "https://thedfirreport.com/feed/",
    "cisa_advisories": "https://www.cisa.gov/cybersecurity-advisories/all.xml",
}


def _parse_rss_date(value: str | None) -> datetime:
    if not value:
        return datetime.now(timezone.utc)
    for fmt in ("%a, %d %b %Y %H:%M:%S %z", "%a, %d %b %Y %H:%M:%S %Z"):
        try:
            return datetime.strptime(value, fmt)
        except ValueError:
            continue
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return datetime.now(timezone.utc)


def _parse_feed(source: str, raw_xml: bytes) -> list[OsintReportItem]:
    root = ElementTree.fromstring(raw_xml)
    items: list[OsintReportItem] = []

    for item in root.findall("./channel/item"):
        title = (item.findtext("title") or "").strip()
        link = (item.findtext("link") or "").strip()
        if not link:
            continue
        summary = (item.findtext("description") or "").strip()
        items.append(
            OsintReportItem(
                source=source,
                title=title,
                link=link,
                published_at=_parse_rss_date(item.findtext("pubDate")),
                summary=summary[:2000],
            )
        )

    for entry in root.findall(f"{_ATOM_NS}entry"):
        title = (entry.findtext(f"{_ATOM_NS}title") or "").strip()
        link_el = entry.find(f"{_ATOM_NS}link")
        link = link_el.get("href", "") if link_el is not None else ""
        if not link:
            continue
        summary = (entry.findtext(f"{_ATOM_NS}summary") or entry.findtext(f"{_ATOM_NS}content") or "").strip()
        published = entry.findtext(f"{_ATOM_NS}published") or entry.findtext(f"{_ATOM_NS}updated")
        items.append(
            OsintReportItem(
                source=source,
                title=title,
                link=link,
                published_at=_parse_rss_date(published),
                summary=summary[:2000],
            )
        )

    return items


async def fetch_feed(client: httpx.AsyncClient, source: str, url: str) -> list[OsintReportItem]:
    response = await client.get(url)
    response.raise_for_status()
    return _parse_feed(source, response.content)


async def fetch_all_feeds(
    client: httpx.AsyncClient, feeds: dict[str, str] | None = None
) -> dict[str, list[OsintReportItem] | str]:
    """Fetches every configured feed independently; a single unreachable/broken
    feed is recorded as an error string rather than failing the whole sync."""
    results: dict[str, Any] = {}
    for source, url in (feeds or DEFAULT_FEEDS).items():
        try:
            results[source] = await fetch_feed(client, source, url)
        except Exception as error:
            results[source] = f"{type(error).__name__}: {str(error)[:200]}"
    return results
