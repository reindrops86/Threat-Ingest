from __future__ import annotations

from typing import Any, Dict


class ResponseAgent:
    def run(self, intake: Dict[str, Any], classification: Dict[str, Any]) -> Dict[str, Any]:
        category = classification["classification"]
        if category == "high_risk":
            action = "block"
            message = "This request appears unsafe and should be blocked."
        elif category == "medium_risk":
            action = "review"
            message = "This request is suspicious and needs analyst review."
        else:
            action = "allow"
            message = "This request appears acceptable."

        return {
            "action": action,
            "message": message,
            "rationale": f"Detected categories: {classification['categories']}",
        }
