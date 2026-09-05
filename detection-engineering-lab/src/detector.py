from __future__ import annotations

from typing import Any, Dict, List


class DetectionEngine:
    def __init__(self) -> None:
        self.rules = [
            {
                "name": "Suspicious PowerShell Loader",
                "description": "Encoded or suspicious PowerShell execution",
                "ttp": "Execution",
                "condition": lambda r: "powershell" in r.get("command", "").lower() and any(
                    x in r.get("command", "").lower() for x in ["-enc", "iex", "downloadstring", "frombase64string"]
                ),
            },
            {
                "name": "Potential Credential Dumping",
                "description": "Access to credential stores or LSASS-like objects",
                "ttp": "Credential Access",
                "condition": lambda r: any(x in r.get("object", "").lower() for x in ["lsass", "sam"]),
            },
            {
                "name": "Persistence via Scheduled Task",
                "description": "Scheduled task creation observed",
                "ttp": "Persistence",
                "condition": lambda r: "schtasks" in r.get("command", "").lower() and "/create" in r.get("command", "").lower(),
            },
        ]

    def run(self, records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        detections = []
        for record in records:
            for rule in self.rules:
                try:
                    if rule["condition"](record):
                        detections.append(
                            {
                                "rule": rule["name"],
                                "ttp": rule["ttp"],
                                "host": record.get("host"),
                                "user": record.get("user"),
                                "record": record,
                            }
                        )
                except Exception:
                    continue
        return detections
