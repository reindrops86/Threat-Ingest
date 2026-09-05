from __future__ import annotations

import re
from typing import Any, Dict, List


RISK_KEYWORDS = {
    "malware": ["malware", "trojan", "dropper", "ransomware", "payload"],
    "phishing": ["phishing", "credential", "harvest", "spoof", "social engineering"],
    "jailbreak": ["ignore", "bypass", "safety", "system prompt", "jailbreak", "hidden rules"],
    "deception": ["trick", "deceive", "spoof", "impersonate", "fake"],
    "exfiltration": ["exfiltrate", "steal", "collect", "dump", "download"],
    "persistence": ["persistence", "install", "auto-start", "registry", "service"],
}


class LLMAbuseDetector:
    def __init__(self) -> None:
        self.compiled = {k: [re.compile(re.escape(term), re.IGNORECASE) for term in terms] for k, terms in RISK_KEYWORDS.items()}

    def analyze(self, text: str) -> Dict[str, Any]:
        categories: Dict[str, int] = {}
        matches: List[str] = []
        for category, patterns in self.compiled.items():
            count = 0
            for pattern in patterns:
                found = pattern.findall(text)
                if found:
                    count += len(found)
                    matches.extend(found)
            categories[category] = count

        score = 0.15
        score += min(sum(categories.values()) * 0.12, 0.75)

        lowered = text.lower()
        if "ignore" in lowered and "safety" in lowered:
            score += 0.08
        if "bypass" in lowered or "jailbreak" in lowered:
            score += 0.07
        if "malware" in lowered or "ransomware" in lowered:
            score += 0.08
        if "credential" in lowered or "phishing" in lowered:
            score += 0.05

        score = round(min(max(score, 0.0), 0.99), 2)
        if score >= 0.75:
            classification = "high_risk"
        elif score >= 0.45:
            classification = "medium_risk"
        else:
            classification = "low_risk"

        return {
            "classification": classification,
            "risk_score": score,
            "categories": categories,
            "matches": sorted(set(matches)),
        }
