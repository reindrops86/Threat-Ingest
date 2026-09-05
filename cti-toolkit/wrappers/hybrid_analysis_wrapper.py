from __future__ import annotations

import os
from typing import Any, Dict

import requests


class HybridAnalysisWrapper:
    """Wrapper for Hybrid Analysis (Falcon Sandbox) API for Hash & URL reputation checks."""

    def __init__(self, api_key: str | None = None) -> None:
        self.api_key = api_key or os.getenv("HYBRID_ANALYSIS_API_KEY") or os.getenv("HA_API_KEY")
        self.base_url = "https://www.hybrid-analysis.com/api/v2"

    def hash_search(self, file_hash: str) -> Dict[str, Any]:
        """Search Hybrid Analysis by SHA256, SHA1, or MD5."""
        if not self.api_key:
            return {
                "status": "mock",
                "indicator": file_hash,
                "verdict": "malicious",
                "threat_score": 92,
                "vx_family": "AgentTesla",
                "environment": "Windows 10 64-bit",
                "note": "HYBRID_ANALYSIS_API_KEY not set. Returning offline mock response.",
            }
        headers = {
            "api-token": self.api_key,
            "user-agent": "Falcon Sandbox Client",
            "Accept": "application/json",
        }
        data = {"hash": file_hash}
        response = requests.post(f"{self.base_url}/search/hash", headers=headers, data=data, timeout=15)
        response.raise_for_status()
        return response.json()

    def url_quick_scan(self, url: str) -> Dict[str, Any]:
        """Quickly scan or query a URL reputation on Hybrid Analysis."""
        if not self.api_key:
            return {
                "status": "mock",
                "indicator": url,
                "verdict": "suspicious",
                "threat_score": 68,
                "scanned_url": url,
                "note": "HYBRID_ANALYSIS_API_KEY not set. Returning offline mock response.",
            }
        headers = {
            "api-token": self.api_key,
            "user-agent": "Falcon Sandbox Client",
            "Accept": "application/json",
        }
        data = {"url": url}
        response = requests.post(f"{self.base_url}/quick-scan/url", headers=headers, data=data, timeout=15)
        response.raise_for_status()
        return response.json()
