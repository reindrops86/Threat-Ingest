from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Dict, List


LOG_PATTERN = re.compile(r"^(?P<ts>[^ ]+ [^ ]+) host=(?P<host>\S+) event=(?P<event>\S+) (?P<rest>.*)$")
KV_PATTERN = re.compile(r'(\w+)=("[^"]*"|\S+)')


def parse_log_line(line: str) -> Dict[str, Any]:
    match = LOG_PATTERN.match(line.strip())
    if not match:
        return {"raw": line.strip()}

    record: Dict[str, Any] = match.groupdict()
    rest = record.pop("rest", "")
    kv = {k: v.strip('"') for k, v in KV_PATTERN.findall(rest)}
    record.update(kv)
    return record


def parse_log_file(path: str | Path) -> List[Dict[str, Any]]:
    lines = Path(path).read_text(encoding="utf-8").splitlines()
    return [parse_log_line(line) for line in lines if line.strip()]
