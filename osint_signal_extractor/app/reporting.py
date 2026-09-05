from __future__ import annotations

from typing import Any, Dict, List


class ThreatReportBuilder:
    def build(self, signals: List[Dict[str, Any]]) -> Dict[str, Any]:
        high = [s for s in signals if s.get("severity") == "high"]
        medium = [s for s in signals if s.get("severity") == "medium"]
        low = [s for s in signals if s.get("severity") == "low"]
        ranked = sorted(signals, key=lambda s: float(s.get("confidence", 0)), reverse=True)
        return {
            "summary": {
                "total_signals": len(signals),
                "high": len(high),
                "medium": len(medium),
                "low": len(low),
            },
            "signals": ranked,
            "top_signal": ranked[0] if ranked else None,
        }

    def build_summary(self, signals: List[Dict[str, Any]]) -> Dict[str, Any]:
        report = self.build(signals)
        items = report["signals"][:5]
        return {
            "total_signals": report["summary"]["total_signals"],
            "high": report["summary"]["high"],
            "medium": report["summary"]["medium"],
            "low": report["summary"]["low"],
            "top_signal": report["top_signal"],
            "top_items": items,
        }
