from __future__ import annotations

import asyncio

from threat_ingestion.config import Settings
from threat_ingestion.domain.models import EnrichmentResult
from threat_ingestion.persistence.repositories import IngestionRepository

from .providers import (
    AbuseIpdbProvider,
    CensysProvider,
    DnsProvider,
    GreyNoiseProvider,
    OtxProvider,
    RdapProvider,
    ShodanProvider,
    UrlscanProvider,
)
from .providers.base import EnrichmentProvider


def default_providers(settings: Settings) -> list[EnrichmentProvider]:
    return [
        RdapProvider(settings),
        DnsProvider(settings),
        UrlscanProvider(settings),
        GreyNoiseProvider(settings),
        CensysProvider(settings),
        ShodanProvider(settings),
        OtxProvider(settings),
        AbuseIpdbProvider(settings),
    ]


class EnrichmentEngine:
    """Fans an indicator out to every applicable OSINT provider and persists each
    result as its own event, so infrastructure changes over time stay queryable."""

    def __init__(self, providers: list[EnrichmentProvider]) -> None:
        self.providers = providers

    async def enrich_indicator(self, indicator_type: str, indicator_value: str) -> list[EnrichmentResult]:
        applicable = [provider for provider in self.providers if provider.supports(indicator_type)]
        results = list(
            await asyncio.gather(*(provider.enrich(indicator_type, indicator_value) for provider in applicable))
        )
        results.extend(await self._expand_certificate_pivots(indicator_type, indicator_value, results))
        return results

    async def _expand_certificate_pivots(
        self, indicator_type: str, indicator_value: str, results: list[EnrichmentResult]
    ) -> list[EnrichmentResult]:
        """For any TLS certificate fingerprint another provider (e.g. urlscan) just
        found, ask Censys which other hosts have presented the same certificate."""
        censys = next((p for p in self.providers if isinstance(p, CensysProvider)), None)
        if censys is None:
            return []
        fingerprints = {fp for result in results for fp in result.cert_fingerprints}
        pivots: list[EnrichmentResult] = []
        for fingerprint in fingerprints:
            hosts = await censys.expand_certificate_hosts(fingerprint)
            if hosts:
                pivots.append(
                    EnrichmentResult(
                        provider="censys",
                        indicator_type=indicator_type,
                        indicator_value=indicator_value,
                        cert_fingerprints=[fingerprint],
                        resolved_ips=hosts,
                    )
                )
        return pivots

    async def enrich_many(
        self, indicators: list[tuple[str, str]], repository: IngestionRepository | None = None
    ) -> list[EnrichmentResult]:
        all_results: list[EnrichmentResult] = []
        for indicator_type, indicator_value in indicators:
            results = await self.enrich_indicator(indicator_type, indicator_value)
            all_results.extend(results)
            if repository:
                for result in results:
                    repository.add_enrichment(result)
        if repository:
            repository.session.commit()
        return all_results

    async def aclose(self) -> None:
        await asyncio.gather(*(provider.client.aclose() for provider in self.providers))
