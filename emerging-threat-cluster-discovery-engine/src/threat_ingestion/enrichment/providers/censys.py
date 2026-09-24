from __future__ import annotations

from typing import Any

from threat_ingestion.domain.models import EnrichmentResult

from .base import EnrichmentProvider

HOST_ENRICHMENT_URL = "https://api.platform.censys.io/v3/global/asset/enrichment/host/{ip}"
CERT_HISTORY_URL = "https://api.platform.censys.io/v3/threat-hunting/certificate/{certificate_id}/observations/hosts"


class CensysProvider(EnrichmentProvider):
    """ASN, geo, and embedded GreyNoise/threat/privacy labels for a host via the
    Censys Platform enrichment endpoint. This endpoint is optimized for high-volume
    lookups and does not consume Censys credits. Requires CENSYS_PERSONAL_ACCESS_TOKEN."""

    provider = "censys"
    applies_to = {"ip"}

    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.settings.censys_personal_access_token}"}

    def _org_params(self) -> dict[str, str]:
        if self.settings.censys_organization_id:
            return {"organization_id": self.settings.censys_organization_id}
        return {}

    async def _lookup(self, indicator_type: str, indicator_value: str) -> EnrichmentResult:
        if not self.settings.censys_personal_access_token:
            return EnrichmentResult(
                provider=self.provider,
                indicator_type="ip",
                indicator_value=indicator_value,
                error="CENSYS_PERSONAL_ACCESS_TOKEN not configured; skipped",
            )
        response = await self.client.get(
            HOST_ENRICHMENT_URL.format(ip=indicator_value),
            headers=self._headers(),
            params=self._org_params(),
        )
        response.raise_for_status()
        payload: dict[str, Any] = response.json()
        resource = (((payload.get("result") or {}).get("result") or {}).get("resource")) or {}

        routing = resource.get("autonomous_system") or {}
        location = resource.get("location") or {}
        greynoise = resource.get("greynoise") or {}
        privacy_entries = resource.get("privacy") or []
        network_entries = resource.get("network") or []
        services = resource.get("services") or []

        tags: set[str] = set()
        if any(entry.get("vpn") for entry in privacy_entries):
            tags.add("vpn")
        if any(entry.get("tor") for entry in privacy_entries):
            tags.add("tor-exit-node")
        if any(entry.get("proxy") for entry in privacy_entries):
            tags.add("open-proxy")
        if any(entry.get("hosting") for entry in network_entries):
            tags.add("hosting-provider")
        for service in services:
            for threat in service.get("threats") or []:
                if threat.get("name"):
                    tags.add(str(threat["name"]))

        return EnrichmentResult(
            provider=self.provider,
            indicator_type="ip",
            indicator_value=indicator_value,
            asn=routing.get("asn"),
            asn_name=routing.get("name"),
            country=location.get("country_code"),
            classification=greynoise.get("classification"),
            tags=sorted(tags),
            raw={"service_count": resource.get("service_count")},
        )

    async def expand_certificate_hosts(self, fingerprint: str) -> list[str]:
        """Finds other hosts that have presented the same TLS certificate over time.
        Requires the paid Adversary Investigation module and CENSYS_ENABLE_CERT_PIVOT;
        returns an empty list (never raises) if unavailable so callers can degrade."""
        if not self.settings.censys_personal_access_token or not self.settings.censys_enable_cert_pivot:
            return []
        try:
            response = await self.client.get(
                CERT_HISTORY_URL.format(certificate_id=fingerprint),
                headers=self._headers(),
                params={**self._org_params(), "page_size": 50},
            )
            response.raise_for_status()
        except Exception:
            return []
        payload: dict[str, Any] = response.json()
        ranges = ((payload.get("result") or {}).get("result") or {}).get("ranges") or []
        return sorted({str(entry["ip"]) for entry in ranges if entry.get("ip")})
