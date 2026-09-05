from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


MITRE_MAP = {
    "phishing": ["T1566"],
    "credential_theft": ["T1555", "T1110"],
    "social_engineering": ["T1566", "T1078"],
    "malware": ["T1204", "T1059"],
    "ransomware": ["T1486", "T1490"],
    "c2": ["T1071", "T1041"],
    "prompt_bypass": ["T1059", "T1204"],
    "fraud": ["T1566", "T1110"],
    "credential_access": ["T1555", "T1110"],
}

SAMPLE_ABUSE_REPORT = """
SOC analyst intake: phishing lure targeting payroll users.
The user reported a fake portal asking employees to login at https://payroll-login-secure[.]co/portal.
The sender helpdesk@secure-payroll[.]co impersonates internal support and asks users to verify credentials.
The malicious IP is 185.220.101.42 and the affiliate infrastructure uses a known blocked hash 9f1c4a2e5b6d7a88d0e9f9b2c1d3a4f5.
The attack also contains a prompt injection attempt instructing the model to ignore safeguards, reveal secrets, and provide a credential harvest workflow.
This looks like a broader identity theft and phishing campaign.
"""


@dataclass
class AbuseIndicator:
    value: str
    type: str
    confidence: float = 0.0
    tags: List[str] = field(default_factory=list)
    mitre: List[str] = field(default_factory=list)
    enrichment: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AbuseCaseRecord:
    case_id: str
    title: str
    priority: str
    status: str
    created_at: str
    updated_at: str
    risk_score: int
    severity: str
    summary: str
    indicators: List[str]
    source_text_snippet: str
    related_cases: List[str] = field(default_factory=list)
    assignee: str = "unassigned"
    notes: List[Dict[str, Any]] = field(default_factory=list)


class LocalIntelClient:
    LOCAL_FEED = {
        "185.220.101.42": {
            "provider": "local-feed",
            "reputation": "malicious",
            "confidence": 0.92,
            "category": "phishing-c2",
            "note": "Known malicious infrastructure associated with phishing and C2 behavior.",
        },
        "secure-payroll.co": {
            "provider": "local-feed",
            "reputation": "suspicious",
            "confidence": 0.91,
            "category": "phishing",
            "note": "Domain overlaps with active credential phishing activity.",
        },
        "payroll-login-secure.co": {
            "provider": "local-feed",
            "reputation": "suspicious",
            "confidence": 0.93,
            "category": "phishing",
            "note": "Impersonation infrastructure seen in phishing lure campaigns.",
        },
        "lockfiles-update.net": {
            "provider": "local-feed",
            "reputation": "malicious",
            "confidence": 0.89,
            "category": "ransomware-loader",
            "note": "Infrastructure historically associated with ransomware loader behavior.",
        },
    }

    @staticmethod
    def normalize_domain(value: str) -> str:
        return value.lower().replace("[.]", ".").strip(".")

    @staticmethod
    def normalize_url(value: str) -> str:
        return value.strip().replace("[.]", ".").rstrip(').,;:!"\'')

    @staticmethod
    def feed_result(provider: str, reputation: str, confidence: float, category: str, note: str) -> Dict[str, Any]:
        return {
            "provider": provider,
            "reputation": reputation,
            "confidence": confidence,
            "category": category,
            "note": note,
        }

    def get_ip_intel(self, ip_value: str) -> Dict[str, Any]:
        key = ip_value.strip().lower()
        if key in self.LOCAL_FEED:
            record = self.LOCAL_FEED[key]
            return self.feed_result(record.get("provider", "local-feed"), record.get("reputation", "unknown"), record.get("confidence", 0.5), record.get("category", "unknown"), record.get("note", "Local match"))
        return self.feed_result("local", "unknown", 0.0, "not-enriched", "No local match for this IP.")

    def get_domain_intel(self, domain_value: str) -> Dict[str, Any]:
        key = self.normalize_domain(domain_value)
        if key in self.LOCAL_FEED:
            record = self.LOCAL_FEED[key]
            return self.feed_result(record.get("provider", "local-feed"), record.get("reputation", "unknown"), record.get("confidence", 0.5), record.get("category", "unknown"), record.get("note", "Local domain match"))
        return self.feed_result("local", "unknown", 0.0, "not-enriched", "No local match for this domain.")

    def get_hash_intel(self, hash_value: str) -> Dict[str, Any]:
        key = hash_value.lower()
        if key.startswith("9f1c4a2e5b6d7a88d0e9f9b2c1d3a4f5"):
            return self.feed_result("local-feed", "malicious", 0.97, "malware", "Hash matches a known suspicious sample in the local dataset.")
        return self.feed_result("local", "unknown", 0.0, "not-enriched", "Hash not present in local intel.")

    def enrich_indicator(self, indicator: AbuseIndicator) -> Dict[str, Any]:
        if indicator.type == "ip":
            return self.get_ip_intel(indicator.value)
        if indicator.type == "domain":
            return self.get_domain_intel(indicator.value)
        if indicator.type == "url":
            parsed = __import__("urllib.parse").parse.urlparse(self.normalize_url(indicator.value))
            host = parsed.netloc.lower().split(":")[0]
            return self.get_domain_intel(host)
        if indicator.type == "hash":
            return self.get_hash_intel(indicator.value)
        if indicator.type == "email":
            return self.feed_result("local", "unknown", 0.0, "social-engineering", "Email reputation requires a dedicated mail intel source.")
        return self.feed_result("local", "unknown", 0.0, "not-enriched", "No enrichment match available.")


class AbuseIndicatorExtractor:
    @staticmethod
    def normalize_text(value: str) -> str:
        return value.strip().replace("[.]", ".").lower()

    @staticmethod
    def normalize_url(value: str) -> str:
        return value.strip().replace("[.]", ".").rstrip(').,;:!"\'')

    def extract(self, text: str) -> List[AbuseIndicator]:
        indicators: List[AbuseIndicator] = []

        ip_matches = re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", text)
        for ip in ip_matches:
            indicators.append(AbuseIndicator(value=ip, type="ip", confidence=0.85))

        domain_matches = re.findall(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b", text)
        for domain in domain_matches:
            normalized = self.normalize_text(domain)
            if not normalized.startswith(("http://", "https://")):
                indicators.append(AbuseIndicator(value=normalized, type="domain", confidence=0.8))

        for url in re.findall(r"https?://[^\s)>\"]+", text, flags=re.IGNORECASE):
            indicators.append(AbuseIndicator(value=self.normalize_url(url), type="url", confidence=0.9))

        for email in re.findall(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", text):
            indicators.append(AbuseIndicator(value=email.lower(), type="email", confidence=0.88))

        for h in re.findall(r"\b(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{64})\b", text):
            indicators.append(AbuseIndicator(value=h.lower(), type="hash", confidence=0.95))

        deduped: Dict[str, AbuseIndicator] = {}
        for item in indicators:
            key = f"{item.type}:{item.value}"
            if key not in deduped:
                deduped[key] = item
        return list(deduped.values())


class AbuseBehaviorClassifier:
    PATTERNS = {
        "jailbreak": ["ignore previous instructions", "bypass safeguards", "ignore policy", "do not mention safety", "override restrictions"],
        "phishing": ["phishing", "fake login", "credential theft", "payroll", "secure portal", "lure", "impersonate"],
        "malware": ["malware", "ransomware", "loader", "powershell", "encoded commands", "hash", "payload"],
        "credential_theft": ["credential", "login", "password", "secret", "harvest", "steal accounts"],
        "social_engineering": ["impersonate", "helpdesk", "urgent", "trusted source", "pretext", "social engineering"],
    }

    def classify(self, text: str) -> List[str]:
        lowered = text.lower()
        matches = []
        for category, keywords in self.PATTERNS.items():
            if any(keyword in lowered for keyword in keywords):
                matches.append(category)
        return matches or ["general_abuse"]


class AbuseRiskScorer:
    @staticmethod
    def score(indicators: List[AbuseIndicator]) -> Dict[str, Any]:
        base = 0
        for indicator in indicators:
            base += indicator.confidence * 25

        malicious_types = {"ip", "domain", "url", "hash"}
        if any(indicator.type in malicious_types for indicator in indicators):
            base += 20

        if any("phishing" in tag for indicator in indicators for tag in indicator.tags):
            base += 15

        if any("malware" in tag for indicator in indicators for tag in indicator.tags):
            base += 20

        if any("credential" in tag for indicator in indicators for tag in indicator.tags):
            base += 15

        risk_score = min(100, int(base))
        if risk_score >= 80:
            severity = "Critical"
        elif risk_score >= 60:
            severity = "High"
        elif risk_score >= 40:
            severity = "Medium"
        else:
            severity = "Low"

        return {"score": risk_score, "severity": severity}


class CaseArchive:
    def __init__(self, path: str | Path = "sample_cases.json"):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.exists():
            self.path.write_text(json.dumps({"cases": []}), encoding="utf-8")

    def load(self) -> List[Dict[str, Any]]:
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
            return payload.get("cases", []) if isinstance(payload, dict) else []
        except Exception:
            return []

    def save(self, payload: List[Dict[str, Any]]) -> None:
        self.path.write_text(json.dumps({"cases": payload}, indent=2), encoding="utf-8")

    def add_case(self, record: Dict[str, Any]) -> Dict[str, Any]:
        cases = self.load()
        cases.append(record)
        self.save(cases)
        return record

    def update_status(self, case_id: str, new_status: str) -> Optional[Dict[str, Any]]:
        cases = self.load()
        for case in cases:
            if case.get("case_id") == case_id:
                case["status"] = new_status
                case["updated_at"] = datetime.now(timezone.utc).isoformat()
                self.save(cases)
                return case
        return None

    def find_related(self, current_case: Dict[str, Any], limit: int = 5) -> List[Dict[str, Any]]:
        current_values = {str(v).lower() for v in current_case.get("indicators", []) if isinstance(v, str)}
        summary_text = (current_case.get("summary") or "").lower()
        shared_keywords = ["phishing", "payroll", "credential", "secure", "malware", "ransomware", "jailbreak"]
        matches: List[Dict[str, Any]] = []

        for prior in self.load():
            if prior.get("case_id") == current_case.get("case_id"):
                continue
            prior_values = {str(v).lower() for v in prior.get("indicators", []) if isinstance(v, str)}
            overlap = len(current_values & prior_values)
            prior_summary = (prior.get("summary") or "").lower()
            if overlap == 0 and prior_summary and summary_text:
                if any(word in summary_text for word in shared_keywords) and any(word in prior_summary for word in shared_keywords):
                    overlap = 1
            if overlap > 0:
                matches.append({
                    "case_id": prior.get("case_id"),
                    "title": prior.get("title", "Historical case"),
                    "severity": prior.get("severity", "Unknown"),
                    "risk_score": prior.get("risk_score", 0),
                    "match_count": overlap,
                    "assignee": prior.get("assignee", "unassigned"),
                })

        matches = sorted(matches, key=lambda item: (item.get("match_count", 0), item.get("risk_score", 0)), reverse=True)
        return matches[:limit]


class InvestigationReporter:
    @staticmethod
    def build_summary(text: str, indicators: List[AbuseIndicator], risk: Dict[str, Any], behavior: List[str], alerts: List[Dict[str, Any]]) -> str:
        lines = [
            "Adversarial model abuse investigation",
            "===================================",
            f"Risk level: {risk['severity']} ({risk['score']}/100)",
            "",
            "Observed behaviors:",
        ]
        for category in behavior:
            lines.append(f"- {category}")
        lines.extend(["", "Observed indicators:"])
        for ind in indicators:
            lines.append(f"- {ind.type.upper()}: {ind.value} | confidence={ind.confidence:.2f} | tags={', '.join(ind.tags) or 'none'}")
        if alerts:
            lines.extend(["", "Generated alerts:"])
            for alert in alerts:
                lines.append(f"- {alert['title']} [{alert['severity']}] | {alert['indicator']} | {alert['summary']}")
        return "\n".join(lines)


class AlertGenerator:
    @staticmethod
    def generate(indicators: List[AbuseIndicator], risk: Dict[str, Any], behavior: List[str]) -> List[Dict[str, Any]]:
        alerts: List[Dict[str, Any]] = []

        if risk.get("score", 0) >= 80:
            alerts.append({
                "alert_id": f"ALERT-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}",
                "title": "Critical model abuse incident",
                "severity": "Critical",
                "source": "risk-engine",
                "indicator": "campaign",
                "summary": "High-confidence phishing, credential theft, and prompt abuse behavior indicates active malicious activity.",
                "status": "open",
            })

        for indicator in indicators:
            if indicator.enrichment.get("reputation") == "malicious":
                alerts.append({
                    "alert_id": f"ALERT-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}-{len(alerts)}",
                    "title": f"Malicious {indicator.type.upper()} observed",
                    "severity": "High" if risk.get("score", 0) >= 70 else "Medium",
                    "source": indicator.enrichment.get("provider", "local"),
                    "indicator": indicator.value,
                    "summary": indicator.enrichment.get("note", "Malicious enrichment match detected."),
                    "status": "open",
                })

        if not alerts:
            alerts.append({
                "alert_id": f"ALERT-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}",
                "title": "Monitoring only",
                "severity": "Low",
                "source": "triage",
                "indicator": "watchlist",
                "summary": "No high-confidence malicious enrichment was found; the activity remains under watch.",
                "status": "monitor",
            })

        return alerts


class SOCAnalystWorkflow:
    @staticmethod
    def derive_priority(risk_score: int) -> str:
        if risk_score >= 80:
            return "P1"
        if risk_score >= 60:
            return "P2"
        if risk_score >= 40:
            return "P3"
        return "P4"

    @staticmethod
    def derive_status(risk_score: int, assignee: Optional[str]) -> str:
        if assignee and assignee != "unassigned":
            return "assigned"
        if risk_score >= 80:
            return "triage"
        return "new"


class ModelAbuseHunter:
    def __init__(self, storage_path: str | Path = "sample_cases.json"):
        self.extractor = AbuseIndicatorExtractor()
        self.classifier = AbuseBehaviorClassifier()
        self.scorer = AbuseRiskScorer()
        self.reporter = InvestigationReporter()
        self.intel = LocalIntelClient()
        self.archive = CaseArchive(storage_path)
        self.workflow = SOCAnalystWorkflow()

    def enrich_indicators(self, indicators: List[AbuseIndicator]) -> List[AbuseIndicator]:
        for indicator in indicators:
            indicator.tags = []
            indicator.mitre = []
            if indicator.type == "ip":
                indicator.tags.extend(["network", "infrastructure"])
            if indicator.type == "domain":
                indicator.tags.extend(["host", "suspicious-domain"])
            if indicator.type == "url":
                indicator.tags.extend(["delivery", "phishing"])
            if indicator.type == "hash":
                indicator.tags.extend(["malware", "execution"])
            if indicator.type == "email":
                indicator.tags.extend(["phishing", "social-engineering"])
            indicator.enrichment = self.intel.enrich_indicator(indicator)

            value_lower = indicator.value.lower()
            if "phish" in value_lower or indicator.type in {"email", "url"}:
                indicator.mitre.extend(MITRE_MAP.get("phishing", []))
            if "payroll" in value_lower or "login" in value_lower or "secure" in value_lower or "credential" in value_lower:
                indicator.mitre.extend(MITRE_MAP.get("credential_access", []))
            if indicator.type == "hash":
                indicator.mitre.extend(MITRE_MAP.get("malware", []))
            if indicator.type == "ip" and "42" in value_lower:
                indicator.mitre.extend(MITRE_MAP.get("c2", []))
            if any(word in value_lower for word in ["ransom", "lock", "encrypt"]):
                indicator.mitre.extend(MITRE_MAP.get("ransomware", []))
            if any(word in value_lower for word in ["override", "ignore", "bypass", "safeguard", "policy"]) or indicator.type == "url":
                indicator.mitre.extend(MITRE_MAP.get("prompt_bypass", []))
            if not indicator.mitre:
                indicator.mitre = ["T1204"]
            indicator.mitre = sorted(set(indicator.mitre))
        return indicators

    def update_case_status(self, case_id: str, new_status: str) -> Optional[Dict[str, Any]]:
        return self.archive.update_status(case_id, new_status)

    def analyze(self, source_text: str, assignee: str | None = None, notes: Optional[List[str]] = None) -> Dict[str, Any]:
        indicators = self.extractor.extract(source_text)
        indicators = self.enrich_indicators(indicators)
        behavior = self.classifier.classify(source_text)
        risk = self.scorer.score(indicators)
        alerts = AlertGenerator.generate(indicators, risk, behavior)
        summary = self.reporter.build_summary(source_text, indicators, risk, behavior, alerts)

        case_id = f"SOC-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}-{abs(hash(source_text)) % 10000}"
        priority = self.workflow.derive_priority(risk["score"])
        final_status = self.workflow.derive_status(risk["score"], assignee)

        case_record = {
            "case_id": case_id,
            "title": f"{risk['severity']} model abuse case",
            "priority": priority,
            "status": final_status,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "updated_at": datetime.now(timezone.utc).isoformat(),
            "risk_score": risk["score"],
            "severity": risk["severity"],
            "summary": summary,
            "indicators": [f"{ind.type}:{ind.value}" for ind in indicators],
            "source_text_snippet": source_text[:220],
            "related_cases": [],
            "assignee": assignee or "unassigned",
            "notes": [],
            "customer": "internal-users",
            "type": "adversarial-model-abuse",
            "source": "analyst-intake",
        }

        if notes:
            case_record["notes"] = [{
                "analyst": assignee or "analyst",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "text": note
            } for note in notes if note and note.strip()]

        related_cases = self.archive.find_related(case_record)
        case_record["related_cases"] = [match["case_id"] for match in related_cases]
        self.archive.add_case(case_record)

        if assignee and assignee != "unassigned":
            self.archive.update_status(case_id, "assigned")
            case_record["status"] = "assigned"

        return {
            "case_id": case_id,
            "title": case_record["title"],
            "priority": priority,
            "status": case_record["status"],
            "assignee": assignee or "unassigned",
            "risk": risk,
            "summary": summary,
            "indicators": [asdict(indicator) for indicator in indicators],
            "alerts": alerts,
            "related_cases": related_cases,
            "notes": case_record["notes"],
            "customer": case_record["customer"],
            "type": case_record["type"],
            "source": case_record["source"],
            "case_queue": self.archive.load()[:10],
        }


if __name__ == "__main__":
    result = ModelAbuseHunter().analyze(SAMPLE_ABUSE_REPORT, assignee="Analyst A", notes=["Initial triage."])
    print(json.dumps(result, indent=2, ensure_ascii=False))
