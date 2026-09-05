from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

PACKAGE_ROOT = Path(__file__).resolve().parent
if str(PACKAGE_ROOT) not in sys.path:
    sys.path.insert(0, str(PACKAGE_ROOT))

from connector_troubleshooter import ConnectorTroubleshootingWorkflow


def load_json(path: str) -> Any:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def main() -> None:
    parser = argparse.ArgumentParser(description="Replay connector failures and generate an evidence-driven diagnostic report.")
    parser.add_argument("--connector", required=True, help="Connector configuration JSON")
    parser.add_argument("--attempts", required=True, help="Captured ingestion attempts JSON")
    parser.add_argument("--output", default="data/diagnostic_report.json", help="Path to save the report")
    args = parser.parse_args()

    connector = load_json(args.connector)
    attempts = load_json(args.attempts)
    if not isinstance(attempts, list):
        raise SystemExit("The attempts file must be a JSON array.")
    report = ConnectorTroubleshootingWorkflow().run(connector, attempts)
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))
    print(f"Saved diagnostic report to {output}")


if __name__ == "__main__":
    main()