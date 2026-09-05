from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PACKAGE_ROOT = Path(__file__).resolve().parent
if str(PACKAGE_ROOT) not in sys.path:
    sys.path.insert(0, str(PACKAGE_ROOT))

from feed_quality import ThreatFeedQualityWorkflow


def main() -> None:
    parser = argparse.ArgumentParser(description="Score a STIX threat feed and recommend an intake action.")
    parser.add_argument("--input", required=True, help="Path to a STIX bundle JSON file")
    parser.add_argument("--output", default="data/feed_quality_report.json", help="Path for the quality report")
    args = parser.parse_args()

    feed = json.loads(Path(args.input).read_text(encoding="utf-8"))
    if not isinstance(feed, dict):
        raise SystemExit("The feed must be a JSON object containing a STIX bundle.")
    report = ThreatFeedQualityWorkflow().run(feed)
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))
    print(f"Saved feed quality report to {output}")


if __name__ == "__main__":
    main()