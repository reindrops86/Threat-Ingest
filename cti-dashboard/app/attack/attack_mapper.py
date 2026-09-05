from __future__ import annotations

from typing import Dict, List


class AttackMapper:
    def __init__(self) -> None:
        self.mapping = {
            "Spear Phishing": {"id": "T1566", "tactic": "Initial Access"},
            "Credential Harvesting": {"id": "T1557", "tactic": "Credential Access"},
            "PowerShell Loader": {"id": "T1059.001", "tactic": "Execution"},
            "Living-off-the-land": {"id": "T1218", "tactic": "Defense Evasion"},
            "Web delivery": {"id": "T1105", "tactic": "Command and Control"},
        }

    def map_ttps(self, ttps: List[str]) -> List[Dict[str, str]]:
        mapped = []
        for ttp in ttps:
            item = self.mapping.get(ttp)
            if item:
                mapped.append({"ttp": ttp, **item})
        return mapped
