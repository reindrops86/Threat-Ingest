from __future__ import annotations

import re
from typing import Any, Dict, List

import requests


class DomainCollector:
    def __init__(self, timeout: int = 10):
        self.timeout = timeout

    def query_domain_metadata(self, domain: str) -> Dict[str, Any]:
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        response = requests.get(url, timeout=self.timeout)
        response.raise_for_status()
        parsed = response.json()
        if not parsed:
            return {"domain": domain, "certificates": []}
        certificates = []
        for item in parsed[:5]:
            name_value = item.get("name_value", "")
            certificates.append({
                "common_name": name_value,
                "issuer_name": item.get("issuer_name"),
                "not_before": item.get("not_before"),
                "not_after": item.get("not_after"),
            })
        return {"domain": domain, "certificates": certificates}

    def extract_domains(self, text: str) -> List[str]:
        return sorted(set(re.findall(r"(?:https?://)?(?:www\.)?([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})", text)))
