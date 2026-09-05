from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from urllib.request import Request, urlopen

PACKAGE_ROOT = Path(__file__).resolve().parent
if str(PACKAGE_ROOT) not in sys.path:
    sys.path.insert(0, str(PACKAGE_ROOT))

from stix_normalizer import FeedNormalizationWorkflow


def publish_taxii(collection_url: str, bundle: dict) -> int:
    request = Request(
        collection_url.rstrip("/") + "/objects/",
        data=json.dumps(bundle).encode("utf-8"),
        headers={"Content-Type": "application/taxii+json;version=2.1", "Accept": "application/taxii+json;version=2.1"},
        method="POST",
    )
    with urlopen(request, timeout=20) as response:  # nosec B310 - explicit user-supplied TAXII endpoint
        return response.status


def main() -> None:
    parser = argparse.ArgumentParser(description="Normalize threat feeds to STIX 2.1 and optionally push them to TAXII.")
    parser.add_argument("--input", required=True, help="CSV or JSON feed to normalize")
    parser.add_argument("--output", default="data/normalized_bundle.json", help="Path for the STIX bundle")
    parser.add_argument("--taxii-collection-url", help="TAXII 2.1 collection URL; publishing is disabled when omitted")
    args = parser.parse_args()

    result = FeedNormalizationWorkflow().run(args.input)
    if result["validation_errors"]:
        raise SystemExit("STIX validation failed: " + "; ".join(result["validation_errors"]))

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(result["bundle"], indent=2), encoding="utf-8")
    print(json.dumps({key: value for key, value in result.items() if key != "bundle"}, indent=2))
    print(f"Wrote {len(result['bundle']['objects'])} STIX objects to {output_path}")
    if args.taxii_collection_url:
        print(f"TAXII publish response: HTTP {publish_taxii(args.taxii_collection_url, result['bundle'])}")


if __name__ == "__main__":
    main()