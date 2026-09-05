from __future__ import annotations

import os
from typing import Any, Dict

import requests


class MISPWrapper:
    """Wrapper for MISP REST API (Event & Attribute Indicator Search) with offline fallback."""

    def __init__(self, misp_url: str | None = None, api_key: str | None = None) -> None:
        self.misp_url = (misp_url or os.getenv("MISP_URL") or "https://misp.local").rstrip("/")
        self.api_key = api_key or os.getenv("MISP_API_KEY")

    def search_attributes(self, value: str) -> Dict[str, Any]:
        """Search MISP attributes for an exact IP, domain, hash, or URL string match."""
        if not self.api_key:
            return {
                "status": "mock",
                "value": value,
                "matches": [
                    {
                        "event_id": 1042,
                        "category": "Network activity",
                        "type": "ip-dst",
                        "value": value,
                        "to_ids": True,
                        "comment": "Associated with credential phishing C2 server",
                    }
                ],
                "note": "MISP_API_KEY not set. Returning offline mock response.",
            }
        headers = {
            "Authorization": self.api_key,
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        body = {"returnFormat": "json", "value": value}
        response = requests.post(f"{self.misp_url}/attributes/restSearch", headers=headers, json=body, timeout=15)
        response.raise_for_status()
        return response.json()

    def search_events(self, tag: str) -> Dict[str, Any]:
        """Search MISP events tagged with a specific threat actor or campaign tag."""
        if not self.api_key:
            return {
                "status": "mock",
                "tag": tag,
                "events": [
                    {
                        "Event": {
                            "id": "1042",
                            "info": "Campaign Analysis - Credential Theft Loader 2026",
                            "threat_level_id": "2",
                            "analysis": "2",
                            "attribute_count": 18,
                        }
                    }
                ],
                "note": "MISP_API_KEY not set. Returning offline mock response.",
            }
        headers = {
            "Authorization": self.api_key,
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        body = {"returnFormat": "json", "tags": [tag]}
        response = requests.post(f"{self.misp_url}/events/restSearch", headers=headers, json=body, timeout=15)
        response.raise_for_status()
        return response.json()
