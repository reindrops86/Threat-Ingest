from __future__ import annotations

import argparse
import json
from pathlib import Path

from .evidence import load_evidence_catalog
from .pipeline import DeterministicGTMFlow


def compare(brief: str, evidence_path: str | Path) -> dict:
    evidence = load_evidence_catalog(evidence_path)
    crewai = DeterministicGTMFlow(evidence, implementation="crewai_demo").run(brief)
    n8n = DeterministicGTMFlow(evidence, implementation="n8n_simulation").run(brief)
    crewai_ids = crewai["strategy"]["evidence_ids"]
    n8n_ids = n8n["strategy"]["evidence_ids"]
    consistent = crewai_ids == n8n_ids and crewai["strategy"]["value_proposition"] == n8n["strategy"]["value_proposition"]
    return {
        "brief": brief,
        "comparison_mode": "offline reference comparison; replace n8n_simulation metrics with n8n execution exports after live testing",
        "fact_consistency_percent": 100 if consistent else 0,
        "comparison": [
            {"implementation": "CrewAI demo", **crewai["observability"]["kpis"], "agent_events": len(crewai["observability"]["events"])},
            {"implementation": "n8n simulation", **n8n["observability"]["kpis"], "agent_events": len(n8n["observability"]["events"])},
        ],
        "shared_evidence_ids": crewai_ids,
        "acceptance": {
            "coverage_target_met": crewai["observability"]["kpis"]["coverage_percent"] >= 90,
            "source_quality_target_met": crewai["observability"]["kpis"]["source_quality_percent"] >= 80,
            "latency_target_met": crewai["observability"]["kpis"]["latency_seconds"] < 900,
            "reproducibility_target_met": consistent,
            "budget_target_met": crewai["observability"]["kpis"]["budget_within_cap"],
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Compare deterministic CrewAI and n8n reference runs.")
    parser.add_argument("--brief", default="Build a GTM plan for compliance automation in fintech.")
    parser.add_argument("--evidence", default=str(Path("data") / "evidence_catalog.json"))
    parser.add_argument("--output", default=str(Path("outputs") / "implementation_comparison.json"))
    args = parser.parse_args()
    result = compare(args.brief, args.evidence)
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()