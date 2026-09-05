from __future__ import annotations

import os
from typing import Any, Dict

import requests


class ShodanWrapper:
    """Wrapper for Shodan API (Infrastructure, open ports, banners, certificates) with offline fallback."""

    def __init__(self, api_key: str | None = None) -> None:
        self.api_key = api_key or os.getenv("SHODAN_API_KEY")
        self.base_url = "https://api.shodan.io"

    def host(self, ip: str) -> Dict[str, Any]:
        if not self.api_key:
            return {
                "status": "mock",
                "ip_str": ip,
                "org": "DigitalOcean, LLC",
                "asn": "AS14061",
                "ports": [22, 80, 443, 8080],
                "vulns": ["CVE-2023-38606", "CVE-2021-44228"],
                "tags": ["cloud", "vpn"],
                "note": "SHODAN_API_KEY not set. Returning offline mock response.",
            }
        response = requests.get(f"{self.base_url}/shodan/host/{ip}", params={"key": self.api_key}, timeout=15)
        response.raise_for_status()
        return response.json()

    def search(self, query: str) -> Dict[str, Any]:
        if not self.api_key:
            return {
                "status": "mock",
                "query": query,
                "total": 1,
                "matches": [
                    {
                        "ip_str": "192.0.2.45",
                        "port": 443,
                        "ssl": {"cert": {"subject": {"CN": "phish-domain.com"}}},
                        "product": "nginx",
                    }
                ],
                "note": "SHODAN_API_KEY not set. Returning offline mock response.",
            }
        response = requests.get(f"{self.base_url}/shodan/host/search", params={"key": self.api_key, "query": query}, timeout=15)
        response.raise_for_status()
        return response.json()
