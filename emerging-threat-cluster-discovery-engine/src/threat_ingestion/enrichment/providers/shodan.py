from __future__ import annotations

import re
from typing import Any

from threat_ingestion.domain.models import EnrichmentResult

from .base import EnrichmentProvider

HOST_URL = "https://api.shodan.io/shodan/host/{ip}"
_ASN_PATTERN = re.compile(r"^AS(\d+)$")


class ShodanProvider(EnrichmentProvider):
    """Open ports/services, TLS certificate fingerprints, and known CVEs exposed on a
    host, via Shodan's host lookup. Requires SHODAN_API_KEY; skipped without one.
    The `vulns` Shodan reports are surfaced as tags so they can be cross-referenced
    against the local CISA KEV catalog when building the report."""

    provider = "shodan"
    applies_to = {"ip"}

    async def _lookup(self, indicator_type: str, indicator_value: str) -> EnrichmentResult:
        if not self.settings.shodan_api_key:
            return EnrichmentResult(
                provider=self.provider,
                indicator_type="ip",
                indicator_value=indicator_value,
                error="SHODAN_API_KEY not configured; skipped",
            )
        response = await self.client.get(
            HOST_URL.format(ip=indicator_value),
            params={"key": self.settings.shodan_api_key, "minify": "false"},
        )
        response.raise_for_status()
        data: dict[str, Any] = response.json()

        asn_number: int | None = None
        match = _ASN_PATTERN.match(str(data.get("asn") or ""))
        if match:
            asn_number = int(match.group(1))

        cert_fingerprints: set[str] = set()
        for banner in data.get("data") or []:
            fingerprint = ((banner.get("ssl") or {}).get("cert") or {}).get("fingerprint") or {}
            sha256 = fingerprint.get("sha256")
            if sha256:
                cert_fingerprints.add(str(sha256).lower())

        tags = set(data.get("tags") or [])
        tags.update(str(cve) for cve in data.get("vulns") or [])

        return EnrichmentResult(
            provider=self.provider,
            indicator_type="ip",
            indicator_value=indicator_value,
            asn=asn_number,
            asn_name=data.get("org") or data.get("isp"),
            country=data.get("country_code"),
            related_domains=sorted(str(name).lower() for name in data.get("hostnames") or []),
            cert_fingerprints=sorted(cert_fingerprints),
            tags=sorted(tags),
            raw={"ports": data.get("ports") or []},
        )
