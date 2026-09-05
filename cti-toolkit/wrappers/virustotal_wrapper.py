from __future__ import annotations

import base64
import os
from typing import Any, Dict

import requests


class VirusTotalWrapper:
    """Wrapper for VirusTotal v3 API (Hashes, URLs, Domains, IPs) with offline fallback."""

    def __init__(self, api_key: str | None = None) -> None:
        self.api_key = api_key or os.getenv("VT_API_KEY")
        self.base_url = "https://www.virustotal.com/api/v3"

    def ip_report(self, ip: str) -> Dict[str, Any]:
        if not self.api_key:
            return {
                "status": "mock",
                "indicator": ip,
                "type": "ip_address",
                "malicious_count": 0,
                "suspicious_count": 0,
                "harmless_count": 88,
                "reputation": 0,
                "note": "VT_API_KEY not set. Returning offline mock response.",
            }
        headers = {"x-apikey": self.api_key}
        response = requests.get(f"{self.base_url}/ip_addresses/{ip}", headers=headers, timeout=15)
        response.raise_for_status()
        return response.json()

    def hash_report(self, file_hash: str) -> Dict[str, Any]:
        if not self.api_key:
            return {
                "status": "mock",
                "indicator": file_hash,
                "type": "file_hash",
                "malicious_count": 18,
                "suspicious_count": 3,
                "harmless_count": 42,
                "meaningful_name": "Trojan.PowerShell.Downloader",
                "tags": ["powershell", "obfuscated", "downloader"],
                "note": "VT_API_KEY not set. Returning offline mock response.",
            }
        headers = {"x-apikey": self.api_key}
        response = requests.get(f"{self.base_url}/files/{file_hash}", headers=headers, timeout=15)
        response.raise_for_status()
        return response.json()

    def url_report(self, url: str) -> Dict[str, Any]:
        if not self.api_key:
            return {
                "status": "mock",
                "indicator": url,
                "type": "url",
                "malicious_count": 6,
                "suspicious_count": 2,
                "harmless_count": 60,
                "categories": {"Forcepoint ThreatSeeker": "phishing"},
                "note": "VT_API_KEY not set. Returning offline mock response.",
            }
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        headers = {"x-apikey": self.api_key}
        response = requests.get(f"{self.base_url}/urls/{url_id}", headers=headers, timeout=15)
        response.raise_for_status()
        return response.json()

    def domain_report(self, domain: str) -> Dict[str, Any]:
        if not self.api_key:
            return {
                "status": "mock",
                "indicator": domain,
                "type": "domain",
                "malicious_count": 2,
                "suspicious_count": 1,
                "harmless_count": 75,
                "reputation": -5,
                "note": "VT_API_KEY not set. Returning offline mock response.",
            }
        headers = {"x-apikey": self.api_key}
        response = requests.get(f"{self.base_url}/domains/{domain}", headers=headers, timeout=15)
        response.raise_for_status()
        return response.json()
