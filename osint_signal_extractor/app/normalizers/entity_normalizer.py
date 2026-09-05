from __future__ import annotations

import re
from typing import Dict, Iterable, List


class EntityNormalizer:
    def normalize(self, entity: str) -> str:
        value = re.sub(r"[^a-zA-Z0-9._-]+", "-", entity.strip().lower())
        return value.strip("-") or "unknown-entity"

    def deduplicate(self, signals: Iterable[Dict[str, object]]) -> List[Dict[str, object]]:
        seen: Dict[str, Dict[str, object]] = {}
        ordered: List[Dict[str, object]] = []
        for signal in signals:
            entity = self.normalize(str(signal.get("entity", "unknown")))
            key = f"{entity}|{signal.get('source', '')}|{signal.get('signal_type', '')}"
            if key not in seen:
                signal["entity"] = entity
                seen[key] = signal
                ordered.append(signal)
        return ordered
