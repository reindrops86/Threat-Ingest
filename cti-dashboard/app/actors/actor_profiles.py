from __future__ import annotations

from typing import List

from app.models import ActorProfile


class ActorProfileStore:
    def list_profiles(self) -> List[ActorProfile]:
        return [
            {
                "name": "APT29",
                "aliases": ["Cozy Bear", "IRON HEMLOCK"],
                "region": "Russia",
                "focus": "Cyber espionage",
                "confidence": 0.88,
                "summary": "Known for targeted credential theft, phishing, and long-dwell operations.",
                "related_iocs": ["mail-verify[.]com"],
                "ttps": ["Spear Phishing", "Credential Harvesting"],
            },
            {
                "name": "FIN7",
                "aliases": ["Carbon Spider"],
                "region": "Global",
                "focus": "Financial theft and POS attacks",
                "confidence": 0.82,
                "summary": "Leverages deceptive web infrastructure and PowerShell execution patterns.",
                "related_iocs": ["invoice-update[.]cloud", "powershell loader"],
                "ttps": ["PowerShell Loader", "Web delivery"],
            },
            {
                "name": "Lazarus Group",
                "aliases": ["Hidden Cobra"],
                "region": "North Korea",
                "focus": "Strategic disruption and theft",
                "confidence": 0.9,
                "summary": "Often uses living-off-the-land techniques and covert web infrastructure.",
                "related_iocs": ["webmail-security[.]net"],
                "ttps": ["Living-off-the-land"],
            },
        ]
