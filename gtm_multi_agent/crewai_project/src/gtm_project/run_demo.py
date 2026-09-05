from __future__ import annotations

import argparse
import json
from pathlib import Path

from .evidence import load_evidence_catalog
from .exporters import export_to_google_docs, write_outputs
from .pipeline import DeterministicGTMFlow


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the offline evidence-backed GTM reference workflow.")
    parser.add_argument("--brief", default="Build a GTM plan for compliance automation in fintech.")
    parser.add_argument("--evidence", default=str(Path("data") / "evidence_catalog.json"))
    parser.add_argument("--output-dir", default="outputs")
    parser.add_argument("--implementation", default="crewai_demo", choices=("crewai_demo", "n8n_simulation"))
    parser.add_argument("--google-docs", action="store_true", help="Export to Google Docs when environment credentials are configured.")
    args = parser.parse_args()

    result = DeterministicGTMFlow(load_evidence_catalog(args.evidence), implementation=args.implementation).run(args.brief)
    paths = write_outputs(result, args.output_dir)
    google_result = export_to_google_docs(result["strategy_document"]) if args.google_docs else {"status": "skipped"}
    print(json.dumps({"run_id": result["run_id"], "kpis": result["observability"]["kpis"], "outputs": paths, "google_docs": google_result}, indent=2))


if __name__ == "__main__":
    main()