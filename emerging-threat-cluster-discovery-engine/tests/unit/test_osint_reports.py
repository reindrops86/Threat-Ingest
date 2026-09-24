from __future__ import annotations

from threat_ingestion.osint_reports.feeds import _parse_feed

_RSS_SAMPLE = b"""<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0">
  <channel>
    <title>Sample Feed</title>
    <item>
      <title>Emotet resurgence targets healthcare</title>
      <link>https://example.test/emotet-report</link>
      <pubDate>Mon, 22 Sep 2026 10:00:00 +0000</pubDate>
      <description>Analysis of a new Emotet campaign.</description>
    </item>
  </channel>
</rss>
"""

_ATOM_SAMPLE = b"""<?xml version="1.0" encoding="UTF-8"?>
<feed xmlns="http://www.w3.org/2005/Atom">
  <title>Sample Advisory Feed</title>
  <entry>
    <title>CISA Advisory: Example Vulnerability</title>
    <link href="https://example.test/advisory-1"/>
    <published>2026-09-22T10:00:00Z</published>
    <summary>Details about an example advisory.</summary>
  </entry>
</feed>
"""


def test_parse_rss_feed_extracts_items() -> None:
    items = _parse_feed("unit42", _RSS_SAMPLE)

    assert len(items) == 1
    assert items[0].title == "Emotet resurgence targets healthcare"
    assert items[0].link == "https://example.test/emotet-report"
    assert items[0].published_at.year == 2026


def test_parse_atom_feed_extracts_items() -> None:
    items = _parse_feed("cisa_advisories", _ATOM_SAMPLE)

    assert len(items) == 1
    assert items[0].title == "CISA Advisory: Example Vulnerability"
    assert items[0].link == "https://example.test/advisory-1"
    assert items[0].summary == "Details about an example advisory."


def test_parse_feed_skips_items_without_link() -> None:
    broken = b"""<?xml version="1.0"?><rss><channel><item><title>No link</title></item></channel></rss>"""
    assert _parse_feed("unit42", broken) == []
