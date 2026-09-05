from __future__ import annotations

from typing import Any, Dict, List


class EnrichmentEngine:
    def enrich(self, detections: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        enriched = []
        for det in detections:
            record = det.get("record", {})
            command = record.get("command", "")
            object_name = record.get("object", "")
            enrichment = {
                "risk": "medium",
                "confidence": 0.6,
                "reason": "Behavioral match",
            }
            if "powershell" in command.lower() or "lsass" in object_name.lower():
                enrichment["risk"] = "high"
                enrichment["confidence"] = 0.84
                enrichment["reason"] = "High-signal command/object pattern"
            enriched.append({**det, "enrichment": enrichment})
        return enriched
