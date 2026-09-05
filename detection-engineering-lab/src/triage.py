from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List


class TriageReporter:
    def summarize(self, enriched: List[Dict[str, Any]]) -> Dict[str, Any]:
        by_rule = Counter(det["rule"] for det in enriched)
        by_ttp = Counter(det["ttp"] for det in enriched)
        highest = max(enriched, key=lambda d: d["enrichment"]["confidence"], default=None)
        return {
            "total_detections": len(enriched),
            "by_rule": dict(by_rule),
            "by_ttp": dict(by_ttp),
            "highest_confidence": highest,
        }

    def export_json(self, enriched: List[Dict[str, Any]], path: str | Path) -> None:
        payload = self.summarize(enriched)
        Path(path).write_text(json.dumps(payload, indent=2), encoding="utf-8")

    def export_markdown(self, enriched: List[Dict[str, Any]], path: str | Path) -> None:
        payload = self.summarize(enriched)
        lines = [
            "# Detection Triage Report",
            "",
            f"- Total detections: {payload['total_detections']}",
            "",
            "## By Rule",
        ]
        for rule, count in payload["by_rule"].items():
            lines.append(f"- {rule}: {count}")
        lines.extend(["", "## By TTP"])
        for ttp, count in payload["by_ttp"].items():
            lines.append(f"- {ttp}: {count}")
        lines.extend(["", "## Highest Confidence Hit"])
        highest = payload["highest_confidence"]
        if highest:
            lines.append(f"- Rule: {highest['rule']}")
            lines.append(f"- TTP: {highest['ttp']}")
            lines.append(f"- Host: {highest.get('host')}")
            lines.append(f"- User: {highest.get('user')}")
            lines.append(f"- Risk: {highest['enrichment']['risk']}")
            lines.append(f"- Confidence: {highest['enrichment']['confidence']}")
            lines.append(f"- Reason: {highest['enrichment']['reason']}")
        else:
            lines.append("- None")
        Path(path).write_text("\n".join(lines), encoding="utf-8")
