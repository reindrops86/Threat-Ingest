from __future__ import annotations

import os
from typing import Any, Dict

import requests


class AbuseIPDBWrapper:
    """Wrapper for AbuseIPDB v2 API (IP threat intelligence scoring) with offline fallback."""

    def __init__(self, api_key: str | None = None) -> None:
        self.api_key = api_key or os.getenv("ABUSEIPDB_API_KEY")
        self.base_url = "https://api.abuseipdb.com/api/v2"

    def check_ip(self, ip: str) -> Dict[str, Any]:
        if not self.api_key:
            return {
                "status": "mock",
                "ipAddress": ip,
                "abuseConfidenceScore": 85,
                "countryCode": "RU",
                "usageType": "Data Center/Web Hosting/Transit",
                "isp": "EXAMPLE-HOSTING-ASN",
                "totalReports": 142,
                "lastReportedAt": "2026-08-30T14:22:10+00:00",
                "note": "ABUSEIPDB_API_KEY not set. Returning offline mock response.",
            }
        headers = {"Key": self.api_key, "Accept": "application/json"}
        params = {"ipAddress": ip, "maxAgeInDays": 90}
        response = requests.get(f"{self.base_url}/check", headers=headers, params=params, timeout=15)
        response.raise_for_status()
        return response.json()

