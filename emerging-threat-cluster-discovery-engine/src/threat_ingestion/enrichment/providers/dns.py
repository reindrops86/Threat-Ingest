from __future__ import annotations

from typing import Any

from threat_ingestion.domain.models import EnrichmentResult

from .base import EnrichmentProvider

_DOH_HEADERS = {"Accept": "application/dns-json"}


class DnsProvider(EnrichmentProvider):
    """Passive-DNS-style enrichment using DNS-over-HTTPS (Cloudflare) so no
    resolver credentials are required. Resolves A records and nameservers."""

    provider = "dns"
    applies_to = {"domain"}

    async def _lookup(self, indicator_type: str, indicator_value: str) -> EnrichmentResult:
        a_records = await self._query(indicator_value, "A")
        ns_records = await self._query(indicator_value, "NS")
        resolved_ips = [record["data"] for record in a_records if record.get("data")]
        nameservers = [str(record["data"]).rstrip(".").lower() for record in ns_records if record.get("data")]
        return EnrichmentResult(
            provider=self.provider,
            indicator_type="domain",
            indicator_value=indicator_value,
            resolved_ips=resolved_ips,
            related_domains=nameservers,
            raw={"answer_count": len(a_records) + len(ns_records)},
        )

    async def _query(self, name: str, record_type: str) -> list[dict[str, Any]]:
        response = await self.client.get(
            "https://cloudflare-dns.com/dns-query",
            params={"name": name, "type": record_type},
            headers=_DOH_HEADERS,
        )
        response.raise_for_status()
        payload: dict[str, Any] = response.json()
        return list(payload.get("Answer", []) or [])
