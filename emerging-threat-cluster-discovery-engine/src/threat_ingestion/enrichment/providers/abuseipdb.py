from __future__ import annotations

from typing import Any

from threat_ingestion.domain.models import EnrichmentResult

from .base import EnrichmentProvider

CHECK_URL = "https://api.abuseipdb.com/api/v2/check"


class AbuseIpdbProvider(EnrichmentProvider):
    """Community-reported abuse confidence score for an IP. Requires
    ABUSEIPDB_API_KEY; skipped (not an error) if unset."""

    provider = "abuseipdb"
    applies_to = {"ip"}

    async def _lookup(self, indicator_type: str, indicator_value: str) -> EnrichmentResult:
        if not self.settings.abuseipdb_api_key:
            return EnrichmentResult(
                provider=self.provider,
                indicator_type="ip",
                indicator_value=indicator_value,
                error="ABUSEIPDB_API_KEY not configured; skipped",
            )
        response = await self.client.get(
            CHECK_URL,
            params={"ipAddress": indicator_value, "maxAgeInDays": 90},
            headers={"Key": self.settings.abuseipdb_api_key, "Accept": "application/json"},
        )
        response.raise_for_status()
        data: dict[str, Any] = (response.json()).get("data", {})

        score = data.get("abuseConfidenceScore")
        classification = None
        if score is not None:
            classification = "malicious" if score >= 50 else "suspicious" if score > 0 else "benign"

        tags = [f"abuseipdb-reports:{data.get('totalReports', 0)}"] if data.get("totalReports") else []

        return EnrichmentResult(
            provider=self.provider,
            indicator_type="ip",
            indicator_value=indicator_value,
            country=data.get("countryCode"),
            related_domains=[data["domain"].lower()] if data.get("domain") else [],
            classification=classification,
            tags=tags,
            raw={"abuse_confidence_score": score, "is_tor": data.get("isTor")},
        )
