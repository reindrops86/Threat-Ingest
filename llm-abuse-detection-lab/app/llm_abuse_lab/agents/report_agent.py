from __future__ import annotations

from typing import Any, Dict, List


class ReportAgent:
    def run(self, intake: Dict[str, Any], classification: Dict[str, Any], response: Dict[str, Any]) -> Dict[str, Any]:
        matched_categories = [category for category, count in classification["categories"].items() if count > 0]
        return {
            "id": intake["id"],
            "summary": f"{classification['classification']} prompt detected ({classification['risk_score']})",
            "matched_categories": matched_categories,
            "recommended_action": response["action"],
            "notes": classification["matches"][:5],
        }
