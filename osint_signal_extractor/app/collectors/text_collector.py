from __future__ import annotations

from typing import Dict, List


class TextCollector:
    def collect(self, text: str) -> List[Dict[str, str]]:
        return [{
            "source": "inline_text",
            "source_type": "text",
            "title": "Inline text snippet",
            "content": text[:500],
        }]
