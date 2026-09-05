from __future__ import annotations

import os
from typing import Any, Dict

import requests


class GreyNoiseWrapper:
    """Wrapper for GreyNoise API (IP context, internet background noise vs targeted attack) with offline fallback."""

    def __init__(self, api_key: str | None = None) -> None:
        self.api_key = api_key or os.getenv("GREYNOISE_API_KEY")
        self.base_url = "https://api.greynoise.io/v2"

    def quick_check(self, ip: str) -> Dict[str, Any]:
        """Quickly check if an IP is mass-scanning internet background noise."""
        if not self.api_key:
            return {
                "status": "mock",
                "ip": ip,
                "noise": True,
                "code": "0x01",
                "code_message": "IP has been observed scanning the internet recently.",
                "note": "GREYNOISE_API_KEY not set. Returning offline mock response.",
            }
        headers = {"key": self.api_key, "Accept": "application/json"}
        response = requests.get(f"{self.base_url}/noise/quick/{ip}", headers=headers, timeout=15)
        response.raise_for_status()
        return response.json()

    def ip_context(self, ip: str) -> Dict[str, Any]:
        """Get detailed context, actor attribution, intention (benign vs malicious), and tags for an IP."""
        if not self.api_key:
            return {
                "status": "mock",
                "ip": ip,
                "classification": "malicious",
                "actor": "unknown_scanner",
                "tags": ["SSH Bruteforce", "Mirai Scanner"],
                "vpn": False,
                "tor": False,
                "bot": True,
                "note": "GREYNOISE_API_KEY not set. Returning offline mock response.",
            }
        headers = {"key": self.api_key, "Accept": "application/json"}
        response = requests.get(f"{self.base_url}/noise/context/{ip}", headers=headers, timeout=15)
        response.raise_for_status()
        return response.json()
