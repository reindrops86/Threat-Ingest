from __future__ import annotations

import asyncio
import random
from abc import ABC, abstractmethod
from collections.abc import Iterable
from datetime import datetime
from typing import Any

import httpx

from threat_ingestion.config import Settings
from threat_ingestion.domain.models import IocObservation, SourceName


class MetadataCollector(ABC):
    source: SourceName

    def __init__(self, settings: Settings, client: httpx.AsyncClient | None = None) -> None:
        self.settings = settings
        headers = {"Auth-Key": settings.abuse_ch_auth_key} if settings.abuse_ch_auth_key else None
        self.client = client or httpx.AsyncClient(timeout=settings.timeout_seconds, headers=headers)

    @abstractmethod
    async def fetch_records(self, cursor: str | None = None) -> Iterable[dict[str, Any]]:
        """Fetch metadata only. Implementations must never request samples or binaries."""

    @abstractmethod
    def normalize(self, record: dict[str, Any]) -> IocObservation:
        """Convert source metadata into a canonical observation."""

    async def collect(self, cursor: str | None = None) -> list[IocObservation]:
        return [self.normalize(record) for record in await self.fetch_records(cursor)]

    async def request_metadata(self, method: str, url: str, **kwargs: Any) -> httpx.Response:
        for attempt in range(self.settings.max_retries + 1):
            response = await self.client.request(method, url, **kwargs)
            if response.status_code < 400:
                return response
            if response.status_code not in {429, 500, 502, 503, 504} or attempt == self.settings.max_retries:
                response.raise_for_status()
            retry_after = float(response.headers.get("Retry-After", "0") or 0)
            await asyncio.sleep(max(retry_after, min(2**attempt + random.random(), 30)))
        raise RuntimeError("Unreachable retry loop")