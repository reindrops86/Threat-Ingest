from __future__ import annotations

from typing import Any

from threat_ingestion.domain.models import EnrichmentResult

from .base import EnrichmentProvider


class UrlscanProvider(EnrichmentProvider):
    """Pivots a domain into related pages, hosting IPs, and TLS certificates observed
    by urlscan.io. The public search endpoint works without an API key (rate limited);
    setting URLSCAN_API_KEY raises the rate limit and enables submission-based lookups."""

    provider = "urlscan"
    applies_to = {"domain"}
    max_results = 20

    async def _lookup(self, indicator_type: str, indicator_value: str) -> EnrichmentResult:
        headers = {"API-Key": self.settings.urlscan_api_key} if self.settings.urlscan_api_key else None
        response = await self.client.get(
            "https://urlscan.io/api/v1/search/",
            params={"q": f"domain:{indicator_value}", "size": self.max_results},
            headers=headers,
        )
        response.raise_for_status()
        payload: dict[str, Any] = response.json()
        results = payload.get("results", [])

        resolved_ips: set[str] = set()
        related_domains: set[str] = set()
        cert_fingerprints: set[str] = set()
        for result in results:
            page = result.get("page", {}) or {}
            if page.get("ip"):
                resolved_ips.add(str(page["ip"]))
            if page.get("domain") and page["domain"].lower() != indicator_value.lower():
                related_domains.add(str(page["domain"]).lower())
            for name in (page.get("apexDomain"), page.get("ptr")):
                if name and name.lower() != indicator_value.lower():
                    related_domains.add(str(name).lower())
            tls = result.get("tls") or {}
            fingerprint = tls.get("certSHA1") or tls.get("fingerprint")
            if fingerprint:
                cert_fingerprints.add(str(fingerprint).lower())

        return EnrichmentResult(
            provider=self.provider,
            indicator_type="domain",
            indicator_value=indicator_value,
            resolved_ips=sorted(resolved_ips),
            related_domains=sorted(related_domains),
            cert_fingerprints=sorted(cert_fingerprints),
            raw={"total": payload.get("total", len(results))},
        )
