from __future__ import annotations

from typing import List

from app.models import IOC


class IOCCollector:
    def collect_iocs(self) -> List[IOC]:
        return [
            {
                "indicator": "mail-verify[.]com",
                "type": "domain",
                "context": "Phishing infrastructure used in credential harvesting",
                "confidence": 0.88,
                "source": "osint-signal",
            },
            {
                "indicator": "invoice-update[.]cloud",
                "type": "cdn",
                "context": "Likely delivery infrastructure for malicious payloads",
                "confidence": 0.79,
                "source": "osint-signal",
            },
            {
                "indicator": "powershell loader",
                "type": "process",
                "context": "Observed in staged execution patterns",
                "confidence": 0.74,
                "source": "att&ck",
            },
        ]
