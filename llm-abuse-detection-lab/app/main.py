from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List

PACKAGE_ROOT = Path(__file__).resolve().parent
if str(PACKAGE_ROOT) not in sys.path:
    sys.path.insert(0, str(PACKAGE_ROOT))

from llm_abuse_lab.workflow import AbuseWorkflow


def load_examples(path: str) -> List[Dict[str, Any]]:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    return payload.get("examples", [])


def build_report(results: List[Dict[str, Any]]) -> Dict[str, Any]:
    total = len(results)
    high = sum(1 for r in results if r["classification"]["classification"] == "high_risk")
    medium = sum(1 for r in results if r["classification"]["classification"] == "medium_risk")
    low = sum(1 for r in results if r["classification"]["classification"] == "low_risk")
    categories: Dict[str, int] = {}
    for result in results:
        for category, count in result["classification"]["categories"].items():
            if count:
                categories[category] = categories.get(category, 0) + count

    return {
        "summary": {
            "total": total,
            "high": high,
            "medium": medium,
            "low": low,
        },
        "category_totals": categories,
        "results": results,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="LLM Abuse Detection Lab")
    parser.add_argument("--input", default=str(Path("data") / "adversarial_prompts.json"), help="Path to prompt examples JSON")
    parser.add_argument("--output", default=str(Path("data") / "misuse_report.json"), help="Path to save the report JSON")
    args = parser.parse_args()

    examples = load_examples(args.input)
    workflow = AbuseWorkflow()
    results = [workflow.run(example["prompt"], example.get("id")) for example in examples]
    report = build_report(results)

    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    Path(args.output).write_text(json.dumps(report, indent=2), encoding="utf-8")

    print(json.dumps(report, indent=2))
    print(f"Saved misuse report to {args.output}")


if __name__ == "__main__":
    main()
