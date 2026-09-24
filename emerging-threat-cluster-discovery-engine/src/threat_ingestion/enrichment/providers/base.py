from __future__ import annotations

from abc import ABC, abstractmethod

import httpx

from threat_ingestion.config import Settings
from threat_ingestion.domain.models import EnrichmentProviderName, EnrichmentResult


class EnrichmentProvider(ABC):
    """A single OSINT enrichment source. Providers must degrade gracefully (never
    raise) so one unreachable/unkeyed source does not block the rest of the pipeline."""

    provider: EnrichmentProviderName
    applies_to: set[str] = {"domain", "ip", "ipv4", "ipv6"}

    def __init__(self, settings: Settings, client: httpx.AsyncClient | None = None) -> None:
        self.settings = settings
        self.client = client or httpx.AsyncClient(timeout=settings.timeout_seconds)

    def supports(self, indicator_type: str) -> bool:
        return indicator_type in self.applies_to

    @abstractmethod
    async def _lookup(self, indicator_type: str, indicator_value: str) -> EnrichmentResult:
        """Perform the provider-specific lookup. May raise; caller wraps in try/except."""

    async def enrich(self, indicator_type: str, indicator_value: str) -> EnrichmentResult:
        try:
            return await self._lookup(indicator_type, indicator_value)
        except Exception as error:
            sanitized = f"{type(error).__name__}: {str(error)[:200]}"
            return EnrichmentResult(
                provider=self.provider,
                indicator_type=indicator_type,
                indicator_value=indicator_value,
                error=sanitized,
            )
