from __future__ import annotations

from typing import Any

from threat_ingestion.domain.models import EnrichmentResult

from .base import EnrichmentProvider


class GreyNoiseProvider(EnrichmentProvider):
    """Distinguishes background Internet scanning from activity worth investigating.
    Requires GREYNOISE_API_KEY; the provider is skipped (not an error) without one."""

    provider = "greynoise"
    applies_to = {"ip", "ipv4", "ipv6"}

    async def _lookup(self, indicator_type: str, indicator_value: str) -> EnrichmentResult:
        if not self.settings.greynoise_api_key:
            return EnrichmentResult(
                provider=self.provider,
                indicator_type="ip",
                indicator_value=indicator_value,
                error="GREYNOISE_API_KEY not configured; skipped",
            )
        response = await self.client.get(
            f"https://api.greynoise.io/v3/community/{indicator_value}",
            headers={"key": self.settings.greynoise_api_key},
        )
        if response.status_code == 404:
            return EnrichmentResult(
                provider=self.provider,
                indicator_type="ip",
                indicator_value=indicator_value,
                classification="unknown",
            )
        response.raise_for_status()
        data: dict[str, Any] = response.json()
        tags = [data["name"]] if data.get("name") else []
        return EnrichmentResult(
            provider=self.provider,
            indicator_type="ip",
            indicator_value=indicator_value,
            classification=data.get("classification"),
            tags=tags,
            raw=data,
        )
