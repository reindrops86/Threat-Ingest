from __future__ import annotations

import argparse
import re
from pathlib import Path
from typing import List


DOMAIN_RE = re.compile(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b", re.IGNORECASE)
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
URL_RE = re.compile(r"https?://[^\s]+", re.IGNORECASE)


def extract_iocs(text: str) -> dict:
    return {
        "domains": sorted(set(DOMAIN_RE.findall(text))),
        "ips": sorted(set(IP_RE.findall(text))),
        "urls": sorted(set(URL_RE.findall(text))),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Normalize IOCs from text")
    parser.add_argument("--input", required=True, help="Path to text file")
    args = parser.parse_args()
    text = Path(args.input).read_text(encoding="utf-8")
    print(extract_iocs(text))


if __name__ == "__main__":
    main()
