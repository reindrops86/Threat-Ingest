from __future__ import annotations

from typing import Any, Dict

from .detection import LLMAbuseDetector
from .agents.intake_agent import IntakeAgent
from .agents.classifier_agent import ClassifierAgent
from .agents.responder_agent import ResponseAgent
from .agents.report_agent import ReportAgent


class AbuseWorkflow:
    def __init__(self) -> None:
        detector = LLMAbuseDetector()
        self.intake = IntakeAgent()
        self.classifier = ClassifierAgent(detector)
        self.responder = ResponseAgent()
        self.reporter = ReportAgent()

    def run(self, prompt_text: str, prompt_id: str | None = None) -> Dict[str, Any]:
        intake_result = self.intake.run(prompt_text=prompt_text, prompt_id=prompt_id)
        classification = self.classifier.run(intake_result)
        response = self.responder.run(intake_result, classification)
        report = self.reporter.run(intake_result, classification, response)
        return {
            "intake": intake_result,
            "classification": classification,
            "response": response,
            "report": report,
        }
