from __future__ import annotations

from typing import Any, Dict

from ..detection import LLMAbuseDetector


class ClassifierAgent:
    def __init__(self, detector: LLMAbuseDetector) -> None:
        self.detector = detector

    def run(self, intake: Dict[str, Any]) -> Dict[str, Any]:
        result = self.detector.analyze(intake["prompt"])
        result["prompt_id"] = intake["id"]
        return result
