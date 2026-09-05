from __future__ import annotations

import os
from typing import Any, Dict

import requests


class AlienVaultOTXWrapper:
    """Wrapper for AlienVault OTX API (Open Threat Exchange indicators & pulse lookup) with offline fallback."""

    def __init__(self, api_key: str | None = None) -> None:
        self.api_key = api_key or os.getenv("OTX_API_KEY")
        self.base_url = "https://otx.alienvault.com/api/v1"

    def get_indicator_details(self, indicator_type: str, indicator: str) -> Dict[str, Any]:
        """Query indicator details (IPv4, domain, hostname, file_hash, URL)."""
        if not self.api_key:
            return {
                "status": "mock",
                "indicator": indicator,
                "type": indicator_type,
                "pulse_info": {
                    "count": 4,
                    "pulses": [
                        {"id": "60e1d5f2a1b2c3", "name": "Active Phishing Campaign Q3 2026", "author_name": "AlienVault"}
                    ],
                },
                "validation": [{"source": "whitelist", "name": "not_whitelisted"}],
                "note": "OTX_API_KEY not set. Returning offline mock response.",
            }
        headers = {"X-OTX-API-KEY": self.api_key}
        # OTX type mapping: IPv4 -> IPv4, domain -> domain, file_hash -> file
        otx_type = "file" if indicator_type in ("hash", "file_hash") else indicator_type
        response = requests.get(
            f"{self.base_url}/indicators/{otx_type}/{indicator}/general",
            headers=headers,
            timeout=15,
        )
        response.raise_for_status()
        return response.json()

    def get_pulse_details(self, pulse_id: str) -> Dict[str, Any]:
        """Retrieve threat pulse detail including indicators, tags, and targeted industries."""
        if not self.api_key:
            return {
                "status": "mock",
                "pulse_id": pulse_id,
                "name": "UNC-2026 Cloud Credential Harvester",
                "tags": ["credential-harvesting", "phishing", "cloud-iam"],
                "author_name": "ThreatIntelLab",
                "indicator_count": 12,
                "note": "OTX_API_KEY not set. Returning offline mock response.",
            }
        headers = {"X-OTX-API-KEY": self.api_key}
        response = requests.get(f"{self.base_url}/pulses/{pulse_id}", headers=headers, timeout=15)
        response.raise_for_status()
        return response.json()
