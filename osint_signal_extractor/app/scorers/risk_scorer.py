from __future__ import annotations

from typing import Dict, List


class RiskScorer:
    def score(self, signal: Dict[str, object]) -> Dict[str, object]:
        base = float(signal.get("confidence", 0.0))
        tags = signal.get("tags", [])
        if "malware" in tags or "ransomware" in tags:
            base += 0.2
        if "repo" in tags:
            base += 0.1
        score = max(0.0, min(1.0, base))
        if score >= 0.8:
            severity = "high"
        elif score >= 0.55:
            severity = "medium"
        else:
            severity = "low"
        signal["confidence"] = round(score, 2)
        signal["severity"] = severity
        return signal

    def score_batch(self, signals: List[Dict[str, object]]) -> List[Dict[str, object]]:
        return [self.score(signal) for signal in signals]
