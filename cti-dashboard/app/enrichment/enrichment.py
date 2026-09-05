from __future__ import annotations

from typing import Any, Dict, List

from app.collectors.ioc_collector import IOCCollector
from app.models import IOC, Signal


class EnrichmentEngine:
    def __init__(self) -> None:
        self.iocs = IOCCollector().collect_iocs()

    def lookup(self, indicator: str) -> Dict[str, Any] | None:
        for ioc in self.iocs:
            if ioc["indicator"].lower() == indicator.lower():
                return ioc
        return None

    def enrich(self, signals: List[Signal]) -> Dict[str, Any]:
        matches = []
        for signal in signals:
            entity = signal.get("entity", "")
            match = self.lookup(entity)
            if match:
                matches.append(
                    {
                        "indicator": entity,
                        "signal_type": signal.get("signal_type"),
                        "source": signal.get("source"),
                        "ioc": match,
                    }
                )
        return {
            "matched_count": len(matches),
            "matches": matches,
            "lookup_index": self.iocs,
        }
