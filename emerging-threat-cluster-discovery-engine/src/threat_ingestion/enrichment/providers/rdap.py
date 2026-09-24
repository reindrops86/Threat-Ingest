from __future__ import annotations

import re
from typing import Any

from threat_ingestion.domain.models import EnrichmentResult

from .base import EnrichmentProvider

_ASN_PATTERN = re.compile(r"^AS(\d+)\s*(.*)$")


class RdapProvider(EnrichmentProvider):
    """Free, keyless RDAP/ASN enrichment. IPs use ip-api.com for ASN + geo; domains
    use the RDAP bootstrap service (rdap.org) for registrar and nameserver data."""

    provider = "rdap"
    applies_to = {"domain", "ip", "ipv4", "ipv6"}

    async def _lookup(self, indicator_type: str, indicator_value: str) -> EnrichmentResult:
        if indicator_type == "domain":
            return await self._lookup_domain(indicator_value)
        return await self._lookup_ip(indicator_value)

    async def _lookup_ip(self, ip: str) -> EnrichmentResult:
        response = await self.client.get(
            f"http://ip-api.com/json/{ip}",
            params={"fields": "status,message,country,countryCode,as,asname,query"},
        )
        response.raise_for_status()
        data: dict[str, Any] = response.json()
        asn_number: int | None = None
        as_field = data.get("as") or ""
        match = _ASN_PATTERN.match(as_field)
        if match:
            asn_number = int(match.group(1))
        return EnrichmentResult(
            provider=self.provider,
            indicator_type="ip",
            indicator_value=ip,
            asn=asn_number,
            asn_name=data.get("asname"),
            country=data.get("countryCode"),
            raw=data,
        )

    async def _lookup_domain(self, domain: str) -> EnrichmentResult:
        response = await self.client.get(f"https://rdap.org/domain/{domain}", follow_redirects=True)
        response.raise_for_status()
        data: dict[str, Any] = response.json()
        nameservers = [
            str(server.get("ldhName")).lower()
            for server in data.get("nameservers", [])
            if server.get("ldhName")
        ]
        statuses = [str(status) for status in data.get("status", [])]
        return EnrichmentResult(
            provider=self.provider,
            indicator_type="domain",
            indicator_value=domain,
            related_domains=nameservers,
            tags=statuses,
            raw={"handle": data.get("handle"), "nameservers": nameservers},
        )
