from __future__ import annotations

import os
from typing import Any, Dict

import requests


class CensysWrapper:
    """Wrapper for Censys API v2 (Hosts & Certificates infrastructure discovery) with offline fallback."""

    def __init__(self, api_id: str | None = None, api_secret: str | None = None) -> None:
        self.api_id = api_id or os.getenv("CENSYS_API_ID")
        self.api_secret = api_secret or os.getenv("CENSYS_API_SECRET")
        self.base_url = "https://search.censys.io/api/v2"

    def view_host(self, ip: str) -> Dict[str, Any]:
        """Query host details, open services, TLS certificates, and location."""
        if not self.api_id or not self.api_secret:
            return {
                "status": "mock",
                "ip": ip,
                "services": [
                    {"port": 443, "service_name": "HTTP", "certificate": {"fingerprint_sha256": "abc123def456..."}},
                    {"port": 22, "service_name": "SSH"},
                ],
                "location": {"country": "Germany", "country_code": "DE"},
                "autonomous_system": {"asn": 24940, "name": "Hetzner Online GmbH"},
                "note": "CENSYS_API_ID or CENSYS_API_SECRET not set. Returning offline mock response.",
            }
        auth = (self.api_id, self.api_secret)
        response = requests.get(f"{self.base_url}/hosts/{ip}", auth=auth, timeout=15)
        response.raise_for_status()
        return response.json()

    def search_certificates(self, query: str) -> Dict[str, Any]:
        """Search Censys certificate index by subject, issuer, SHA256 fingerprint, etc."""
        if not self.api_id or not self.api_secret:
            return {
                "status": "mock",
                "query": query,
                "hits": [
                    {
                        "fingerprint_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                        "subject_dn": "CN=login.secure-bank-update.com",
                        "issuer_dn": "CN=Let's Encrypt Authority X3",
                    }
                ],
                "note": "CENSYS_API_ID or CENSYS_API_SECRET not set. Returning offline mock response.",
            }
        auth = (self.api_id, self.api_secret)
        params = {"q": query}
        response = requests.get(f"{self.base_url}/certificates/search", auth=auth, params=params, timeout=15)
        response.raise_for_status()
        return response.json()
