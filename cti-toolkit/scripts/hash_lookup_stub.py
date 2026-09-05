from __future__ import annotations

import argparse


def mock_lookup_hash(file_hash: str) -> dict:
    return {
        "hash": file_hash,
        "verdict": "unknown",
        "note": "Replace with a real hash reputation API integration.",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Stub hash lookup")
    parser.add_argument("--hash", required=True, help="File hash to look up")
    args = parser.parse_args()
    print(mock_lookup_hash(args.hash))


if __name__ == "__main__":
    main()
