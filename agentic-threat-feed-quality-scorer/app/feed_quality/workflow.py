from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any


class ThreatFeedQualityWorkflow:
    """Scores observable feed quality signals and explains its routing decision."""

    REQUIRED_FIELDS = ("type", "id", "spec_version", "created", "modified")
    STIX_INDICATOR_FIELDS = ("pattern", "pattern_type", "valid_from")

    def run(self, feed: dict[str, Any]) -> dict[str, Any]:
        objects = feed.get("objects", []) if feed.get("type") == "bundle" else feed.get("indicators", [])
        indicators = [item for item in objects if isinstance(item, dict) and item.get("type") == "indicator"]
        dimensions = {
            "completeness": self._completeness(indicators),
            "accuracy": self._accuracy(indicators),
            "enrichment_depth": self._enrichment_depth(indicators),
            "stix_compliance": self._stix_compliance(feed, indicators),
            "redundancy": self._redundancy(indicators),
            "timeliness": self._timeliness(indicators),
        }
        average = round(sum(result["score"] for result in dimensions.values()) / len(dimensions))
        recommendation, rationale = self._recommend(dimensions, average, len(indicators))
        return {
            "report_type": "threat_feed_quality_assessment",
            "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
            "feed_summary": {"bundle_id": feed.get("id"), "indicator_count": len(indicators), "overall_score": average},
            "dimensions": dimensions,
            "recommendation": recommendation,
            "rationale": rationale,
            "agent_trace": [
                {"agent": "CompletenessAgent", "result": f"{dimensions['completeness']['score']}/100"},
                {"agent": "AccuracyAgent", "result": f"{dimensions['accuracy']['score']}/100"},
                {"agent": "EnrichmentAgent", "result": f"{dimensions['enrichment_depth']['score']}/100"},
                {"agent": "STIXComplianceAgent", "result": f"{dimensions['stix_compliance']['score']}/100"},
                {"agent": "RedundancyAgent", "result": f"{dimensions['redundancy']['score']}/100"},
                {"agent": "TimelinessAgent", "result": f"{dimensions['timeliness']['score']}/100"},
                {"agent": "DecisionAgent", "result": recommendation},
            ],
        }

    def _completeness(self, indicators: list[dict[str, Any]]) -> dict[str, Any]:
        fields = self.REQUIRED_FIELDS + self.STIX_INDICATOR_FIELDS
        expected = len(indicators) * len(fields)
        present = sum(1 for item in indicators for field in fields if item.get(field))
        score = round(100 * present / expected) if expected else 0
        missing = sorted({field for item in indicators for field in fields if not item.get(field)})
        return self._dimension(score, "Required STIX fields are populated." if not missing else f"Missing fields observed: {', '.join(missing)}.")

    def _accuracy(self, indicators: list[dict[str, Any]]) -> dict[str, Any]:
        valid = 0
        invalid = 0
        for item in indicators:
            pattern = str(item.get("pattern", ""))
            if re.fullmatch(r"\[[^\[\]]+\]", pattern) and " = '" in pattern and pattern.endswith("']"):
                valid += 1
            else:
                invalid += 1
        score = round(100 * valid / len(indicators)) if indicators else 0
        return self._dimension(score, "All indicators use a recognizable STIX pattern." if not invalid else f"{invalid} indicator(s) have malformed or absent patterns.")

    def _enrichment_depth(self, indicators: list[dict[str, Any]]) -> dict[str, Any]:
        enriched = sum(1 for item in indicators if item.get("labels") and item.get("confidence") is not None and item.get("external_references"))
        score = round(100 * enriched / len(indicators)) if indicators else 0
        return self._dimension(score, "Indicators include labels, confidence, and provenance." if score == 100 else f"Only {enriched}/{len(indicators)} indicator(s) include labels, confidence, and provenance.")

    def _stix_compliance(self, feed: dict[str, Any], indicators: list[dict[str, Any]]) -> dict[str, Any]:
        bundle_valid = feed.get("type") == "bundle" and str(feed.get("id", "")).startswith("bundle--")
        object_valid = sum(1 for item in indicators if item.get("spec_version") == "2.1" and str(item.get("id", "")).startswith("indicator--"))
        score = round(100 * object_valid / len(indicators)) if indicators else 0
        if not bundle_valid:
            score = min(score, 50)
        evidence = "Bundle and indicator identities conform to the expected STIX 2.1 shape." if score == 100 else "Bundle or indicator identifiers/specification versions do not meet the expected STIX 2.1 shape."
        return self._dimension(score, evidence)

    def _redundancy(self, indicators: list[dict[str, Any]]) -> dict[str, Any]:
        patterns = [str(item.get("pattern", "")) for item in indicators]
        duplicates = len(patterns) - len(set(patterns))
        score = round(100 * (1 - duplicates / len(patterns))) if patterns else 0
        return self._dimension(score, "No duplicate indicator patterns found." if not duplicates else f"{duplicates} duplicate indicator pattern(s) found.")

    def _timeliness(self, indicators: list[dict[str, Any]]) -> dict[str, Any]:
        now = datetime.now(timezone.utc)
        fresh = 0
        stale = 0
        for item in indicators:
            timestamp = str(item.get("modified") or item.get("created") or "").replace("Z", "+00:00")
            try:
                age_days = (now - datetime.fromisoformat(timestamp).astimezone(timezone.utc)).days
                if age_days <= 30:
                    fresh += 1
                else:
                    stale += 1
            except ValueError:
                stale += 1
        score = round(100 * fresh / len(indicators)) if indicators else 0
        return self._dimension(score, "All indicators were updated within 30 days." if not stale else f"{stale} indicator(s) are stale or have unparseable timestamps.")

    @staticmethod
    def _dimension(score: int, evidence: str) -> dict[str, Any]:
        return {"score": score, "evidence": evidence}

    @staticmethod
    def _recommend(dimensions: dict[str, dict[str, Any]], average: int, indicator_count: int) -> tuple[str, str]:
        if not indicator_count or dimensions["stix_compliance"]["score"] < 50 or dimensions["accuracy"]["score"] < 50:
            return "Reject", "The feed lacks a minimally reliable STIX structure or has invalid indicator patterns. Do not ingest it automatically."
        if dimensions["redundancy"]["score"] < 60 or dimensions["timeliness"]["score"] < 40:
            return "Quarantine for manual review", "Duplicate or stale intelligence needs analyst review before it changes collection quality."
        if dimensions["enrichment_depth"]["score"] < 70 or dimensions["completeness"]["score"] < 80:
            return "Enrich before ingest", "The core feed is structurally usable, but it needs additional context or mapped fields for reliable analyst use."
        if average >= 80:
            return "Accept", "The feed meets the automated quality thresholds across structural, enrichment, duplication, and freshness checks."
        return "Quarantine for manual review", "The feed has mixed quality signals that do not support an automatic decision."