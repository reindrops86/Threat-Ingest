from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from typing import Any


class CTIPipelineSimulator:
    """Runs a scenario through ingestion, enrichment, connector, and TAXII stages."""

    REQUIRED_FIELDS = ("id", "type", "value")

    def run(self, scenario: dict[str, Any]) -> dict[str, Any]:
        indicators = scenario.get("feed", [])
        outcomes = {item.get("indicator_id"): item.get("outcome", "success") for item in scenario.get("connector_outcomes", [])}
        events: list[dict[str, Any]] = []
        ingested: list[dict[str, Any]] = []
        transported: list[dict[str, Any]] = []
        counters: Counter[str] = Counter()

        for indicator in indicators:
            identifier = str(indicator.get("id", "unknown"))
            missing = [field for field in self.REQUIRED_FIELDS if not indicator.get(field)]
            if missing:
                counters["ingestion_failed"] += 1
                events.append(self._event("IngestionAgent", identifier, "failed", f"missing required fields: {', '.join(missing)}"))
                continue
            ingested.append(indicator)
            counters["ingested"] += 1
            events.append(self._event("IngestionAgent", identifier, "accepted", "feed record accepted"))

        enriched: list[dict[str, Any]] = []
        for indicator in ingested:
            identifier = str(indicator["id"])
            enrichment = self._enrich(indicator)
            enriched_indicator = {**indicator, "enrichment": enrichment}
            enriched.append(enriched_indicator)
            counters["enriched"] += 1
            events.append(self._event("EnrichmentAgent", identifier, "enriched", f"added {', '.join(enrichment['sources'])} context"))

        for indicator in enriched:
            identifier = str(indicator["id"])
            outcome = outcomes.get(identifier, "success")
            if outcome == "auth_failure":
                counters["connector_failed"] += 1
                events.append(self._event("ConnectorAgent", identifier, "failed", "401 simulated: token rejected"))
                continue
            if outcome == "schema_mismatch":
                counters["connector_failed"] += 1
                events.append(self._event("ConnectorAgent", identifier, "failed", "422 simulated: destination schema mismatch"))
                continue
            if outcome == "collection_not_found":
                counters["connector_failed"] += 1
                events.append(self._event("ConnectorAgent", identifier, "failed", "404 simulated: TAXII collection not found"))
                continue
            counters["connector_passed"] += 1
            events.append(self._event("ConnectorAgent", identifier, "passed", "connector accepted enriched record"))
            stix_object = self._to_stix(indicator)
            transported.append(stix_object)
            counters["transported"] += 1
            events.append(self._event("STIXTransportAgent", identifier, "delivered", "STIX 2.1 indicator delivered to simulated TAXII collection"))

        stages = {
            "ingestion": self._stage(counters["ingested"], len(indicators)),
            "enrichment": self._stage(counters["enriched"], counters["ingested"]),
            "connector": self._stage(counters["connector_passed"], counters["enriched"]),
            "transport": self._stage(counters["transported"], counters["connector_passed"]),
        }
        health = round(sum(stage["health"] for stage in stages.values()) / len(stages))
        investigation = self._build_investigation(enriched)
        return {
            "report_type": "cti_pipeline_simulation",
            "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
            "scenario": scenario.get("name", "unnamed scenario"),
            "pipeline_health": health,
            "pipeline_status": "healthy" if health >= 90 else "degraded" if health >= 60 else "critical",
            "stages": stages,
            "metrics": dict(counters),
            "events": events,
            "transported_stix_objects": transported,
            **investigation,
            "analyst_decisions": [],
            "agent_trace": [
                {"agent": "IngestionAgent", "result": f"{counters['ingested']}/{len(indicators)} accepted"},
                {"agent": "EnrichmentAgent", "result": f"{counters['enriched']} enriched"},
                {"agent": "ConnectorAgent", "result": f"{counters['connector_passed']} passed, {counters['connector_failed']} failed"},
                {"agent": "STIXTransportAgent", "result": f"{counters['transported']} delivered"},
                {"agent": "PipelineHealthAgent", "result": f"{health}/100 ({'healthy' if health >= 90 else 'degraded' if health >= 60 else 'critical'})"},
            ],
        }

    @staticmethod
    def _build_investigation(indicators: list[dict[str, Any]]) -> dict[str, Any]:
        """Create a deterministic cloud attack path and infrastructure cluster for the demo."""
        indicator_ids = [str(indicator["id"]) for indicator in indicators]
        values = [str(indicator["value"]) for indicator in indicators]
        return {
            "cloud_attack_path": {
                "nodes": [
                    {"id": "dependency", "label": "Poisoned dependency", "kind": "initial access", "evidence": indicator_ids[:1]},
                    {"id": "ci_runner", "label": "CI runner", "kind": "build system", "evidence": indicator_ids[:1]},
                    {"id": "secret", "label": "Deployment secret", "kind": "credential", "evidence": indicator_ids[:2]},
                    {"id": "iam_role", "label": "Overprivileged IAM role", "kind": "identity", "evidence": indicator_ids[:2]},
                    {"id": "workload", "label": "Production workload", "kind": "cloud workload", "evidence": indicator_ids[:2]},
                    {"id": "compute", "label": "Unexpected compute", "kind": "resource hijack", "evidence": indicator_ids[-1:]},
                    {"id": "c2", "label": "Rotating C2 infrastructure", "kind": "external infrastructure", "evidence": indicator_ids[:1]},
                ],
                "edges": [
                    {"from": "dependency", "to": "ci_runner", "relationship": "executes in"},
                    {"from": "ci_runner", "to": "secret", "relationship": "reads"},
                    {"from": "secret", "to": "iam_role", "relationship": "assumes"},
                    {"from": "iam_role", "to": "workload", "relationship": "controls"},
                    {"from": "workload", "to": "compute", "relationship": "launches"},
                    {"from": "compute", "to": "c2", "relationship": "beacons to"},
                ],
            },
            "infrastructure_clusters": [
                {
                    "cluster_id": "cluster-01",
                    "assessment": "Suspected campaign infrastructure",
                    "confidence": 72,
                    "pivots": ["domain and URL behavior", "hosting or ASN", "TLS certificate", "timing"],
                    "indicators": [{"id": indicator_id, "value": value} for indicator_id, value in zip(indicator_ids, values)],
                }
            ],
        }

    @staticmethod
    def _enrich(indicator: dict[str, Any]) -> dict[str, Any]:
        value = str(indicator["value"])
        return {
            "sources": ["passive_dns", "reputation_index"],
            "confidence": 80 if value.startswith(("http", "198.", "203.")) else 65,
            "tags": indicator.get("tags", ["threat-intel"]),
        }

    @staticmethod
    def _to_stix(indicator: dict[str, Any]) -> dict[str, Any]:
        value = str(indicator["value"]).replace("'", "\\'")
        object_type = {"ipv4": "ipv4-addr", "domain": "domain-name", "url": "url"}.get(str(indicator.get("type")), "domain-name")
        timestamp = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
        return {
            "type": "indicator",
            "spec_version": "2.1",
            "id": f"indicator--sim-{indicator['id']}",
            "created": timestamp,
            "modified": timestamp,
            "pattern": f"[{object_type}:value = '{value}']",
            "pattern_type": "stix",
            "valid_from": timestamp,
            "labels": indicator.get("tags", ["threat-intel"]),
            "confidence": indicator.get("confidence", 50),
        }

    @staticmethod
    def _stage(successful: int, attempted: int) -> dict[str, int | str]:
        health = round(100 * successful / attempted) if attempted else 100
        return {"health": health, "successful": successful, "attempted": attempted, "status": "healthy" if health >= 90 else "degraded" if health >= 60 else "critical"}

    @staticmethod
    def _event(agent: str, indicator_id: str, status: str, detail: str) -> dict[str, str]:
        return {"agent": agent, "indicator_id": indicator_id, "status": status, "detail": detail}