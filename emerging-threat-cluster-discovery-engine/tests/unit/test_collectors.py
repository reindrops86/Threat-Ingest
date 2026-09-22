from __future__ import annotations

import asyncio
from collections.abc import Iterable
from typing import Any

from threat_ingestion.collectors import MalwareBazaarCollector, ThreatFoxCollector, URLhausCollector
from threat_ingestion.collectors.base import MetadataCollector
from threat_ingestion.config import Settings
from threat_ingestion.domain.models import IocObservation


def test_all_collectors_implement_metadata_contract() -> None:
    settings = Settings()
    for collector_type in (ThreatFoxCollector, URLhausCollector, MalwareBazaarCollector):
        collector = collector_type(settings)
        assert isinstance(collector, MetadataCollector)
        assert "download" not in collector.endpoint
        assert "sample" not in collector.endpoint
        asyncio.run(collector.client.aclose())


class FixtureCollector(MetadataCollector):
    source = "threatfox"

    async def fetch_records(self, cursor: str | None = None) -> Iterable[dict[str, Any]]:
        return [{"id": "record-1", "ioc_type": "domain", "ioc_value": "EXAMPLE.TEST", "first_seen": "2026-01-01T00:00:00Z"}]

    def normalize(self, record: dict[str, Any]) -> IocObservation:
        from threat_ingestion.domain.normalization import normalized_observation

        return normalized_observation(self.source, record)


def test_normalization_produces_stable_canonical_value() -> None:
    collector = FixtureCollector(Settings())
    observation = asyncio.run(collector.collect())[0]
    assert observation.source_record_id == "record-1"
    assert observation.canonical_value == "example.test"
    asyncio.run(collector.client.aclose())


def test_threatfox_ioc_field_is_normalized() -> None:
    collector = FixtureCollector(Settings())
    observation = collector.normalize(
        {"id": "record-2", "ioc_type": "url", "ioc": "https://example.test/path"}
    )
    assert observation.canonical_value == "https://example.test/path"
    asyncio.run(collector.client.aclose())