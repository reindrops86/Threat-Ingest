from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from gtm_project.compare import compare
from gtm_project.evidence import assess_evidence, load_evidence_catalog
from gtm_project.exporters import write_outputs
from gtm_project.pipeline import DeterministicGTMFlow


class GTMReferenceWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.evidence_path = PROJECT_ROOT / "data" / "evidence_catalog.json"
        cls.evidence = load_evidence_catalog(cls.evidence_path)

    def test_evidence_targets_are_met(self) -> None:
        assessment = assess_evidence(self.evidence, answered_questions=4, total_questions=4)
        self.assertGreaterEqual(assessment["coverage_percent"], 90)
        self.assertGreaterEqual(assessment["source_quality_percent"], 80)
        self.assertEqual(assessment["broken_links"], 0)

    def test_golden_brief_has_citations_and_required_strategy_sections(self) -> None:
        result = DeterministicGTMFlow(self.evidence).run("Build a GTM plan for compliance automation in fintech.")
        self.assertEqual(result["observability"]["kpis"]["uncited_claims"], 0)
        self.assertIn("## Ideal Customer Profiles", result["strategy_document"])
        self.assertIn("## Competitor Scan", result["strategy_document"])
        self.assertIn("## Evidence Register", result["strategy_document"])
        self.assertEqual(len(result["strategy"]["evidence_ids"]), 4)

    def test_export_artifacts_include_pdf_and_google_docs_payload(self) -> None:
        result = DeterministicGTMFlow(self.evidence).run("Golden test brief")
        with tempfile.TemporaryDirectory() as temporary_directory:
            paths = write_outputs(result, temporary_directory)
            self.assertTrue(Path(paths["markdown"]).exists())
            self.assertTrue(Path(paths["json"]).exists())
            self.assertTrue(Path(paths["google_docs_payload"]).exists())
            self.assertTrue(Path(paths["pdf"]).read_bytes().startswith(b"%PDF-"))
            self.assertEqual(json.loads(Path(paths["google_docs_payload"]).read_text(encoding="utf-8"))["title"], "GTM Strategy Memo")

    def test_comparison_meets_acceptance_targets(self) -> None:
        result = compare("Golden test brief", self.evidence_path)
        self.assertTrue(all(result["acceptance"].values()))
        self.assertEqual(result["fact_consistency_percent"], 100)


if __name__ == "__main__":
    unittest.main()