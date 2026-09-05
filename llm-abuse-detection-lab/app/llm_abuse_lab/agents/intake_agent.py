from __future__ import annotations

from typing import Any, Dict


class IntakeAgent:
    def run(self, prompt_text: str, prompt_id: str | None = None) -> Dict[str, Any]:
        return {
            "id": prompt_id,
            "prompt": prompt_text,
            "length": len(prompt_text),
            "token_count_estimate": max(1, len(prompt_text.split())),
        }
