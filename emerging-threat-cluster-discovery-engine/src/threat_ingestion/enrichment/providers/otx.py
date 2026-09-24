from __future__ import annotations

from typing import Any

from threat_ingestion.domain.models import EnrichmentResult

from .base import EnrichmentProvider

GENERAL_URL = "https://otx.alienvault.com/api/v1/indicators/{section}/{value}/general"


class OtxProvider(EnrichmentProvider):
    """AlienVault OTX pulse correlation: how many threat-intel "pulses" (community
    reports) reference this indicator, and under what malware/adversary tags.
    Requires OTX_API_KEY; skipped (not an error) if unset."""

    provider = "otx"
    applies_to = {"ip", "domain"}

    async def _lookup(self, indicator_type: str, indicator_value: str) -> EnrichmentResult:
        if not self.settings.otx_api_key:
            return EnrichmentResult(
                provider=self.provider,
                indicator_type=indicator_type,
                indicator_value=indicator_value,
                error="OTX_API_KEY not configured; skipped",
            )
        section = "IPv4" if indicator_type == "ip" else "domain"
        response = await self.client.get(
            GENERAL_URL.format(section=section, value=indicator_value),
            headers={"X-OTX-API-KEY": self.settings.otx_api_key},
        )
        response.raise_for_status()
        data: dict[str, Any] = response.json()
        pulse_info = data.get("pulse_info") or {}
        pulses = pulse_info.get("pulses") or []
        tags: set[str] = set()
        for pulse in pulses:
            tags.update(str(tag) for tag in pulse.get("tags") or [])
            tags.update(str(family) for family in pulse.get("malware_families") or [])

        return EnrichmentResult(
            provider=self.provider,
            indicator_type=indicator_type,
            indicator_value=indicator_value,
            classification="malicious" if pulse_info.get("count") else "unknown",
            tags=sorted(tags),
            raw={"pulse_count": pulse_info.get("count", 0)},
        )
