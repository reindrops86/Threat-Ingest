from __future__ import annotations

import re
from typing import Dict, List


class KeywordSignalExtractor:
    def __init__(self, suspicious_terms: List[str] | None = None):
        self.suspicious_terms = suspicious_terms or [
            "ransomware",
            "malware",
            "exploit",
            "botnet",
            "credential",
            "phishing",
            "loader",
            "dropper",
            "c2",
            "stealer",
            "crack",
            "keylogger",
            "token",
        ]

    def extract(self, text: str, source: str, source_type: str) -> List[Dict[str, object]]:
        matches = []
        for term in self.suspicious_terms:
            if re.search(re.escape(term), text, flags=re.IGNORECASE):
                matches.append({
                    "entity": term,
                    "signal_type": "keyword_match",
                    "source": source,
                    "source_type": source_type,
                    "snippet": text[:250],
                    "confidence": 0.55,
                    "tags": ["keyword-match", term.lower()],
                })
        return matches
