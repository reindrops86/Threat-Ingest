from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PACKAGE_ROOT = Path(__file__).resolve().parent
if str(PACKAGE_ROOT) not in sys.path:
    sys.path.insert(0, str(PACKAGE_ROOT))

from cti_pipeline import CTIPipelineSimulator


def main() -> None:
    parser = argparse.ArgumentParser(description="Simulate an autonomous CTI ingestion pipeline and emit a health report.")
    parser.add_argument("--scenario", required=True, help="Path to a simulation scenario JSON file")
    parser.add_argument("--output", default="data/pipeline_health_report.json", help="Path for the generated report")
    args = parser.parse_args()

    scenario = json.loads(Path(args.scenario).read_text(encoding="utf-8"))
    report = CTIPipelineSimulator().run(scenario)
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps({key: value for key, value in report.items() if key != "transported_stix_objects"}, indent=2))
    print(f"Saved pipeline health report to {output}")


if __name__ == "__main__":
    main()