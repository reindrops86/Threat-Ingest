from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable


class JsonExporter:
    def export(self, data: Iterable[Any], path: str | Path) -> str:
        output_path = Path(path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(list(data), indent=2), encoding="utf-8")
        return str(output_path)
