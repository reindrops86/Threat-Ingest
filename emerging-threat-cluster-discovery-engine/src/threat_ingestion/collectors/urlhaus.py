from __future__ import annotations

from typing import Any, Iterable

from threat_ingestion.domain.models import IocObservation
from threat_ingestion.domain.normalization import normalized_observation

from .base import MetadataCollector


class URLhausCollector(MetadataCollector):
    source = "urlhaus"
    endpoint = "https://urlhaus-api.abuse.ch/v1/urls/recent/"

    async def fetch_records(self, cursor: str | None = None) -> Iterable[dict[str, Any]]:
        response = await self.request_metadata("GET", self.endpoint)
        return response.json().get("urls", [])

    def normalize(self, record: dict[str, Any]) -> IocObservation:
        return normalized_observation(self.source, record)