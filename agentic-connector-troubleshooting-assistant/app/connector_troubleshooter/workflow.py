from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


class ConnectorTroubleshootingWorkflow:
    """Coordinates evidence collection and diagnoses without mutating a connector."""

    def run(self, connector: dict[str, Any], attempts: list[dict[str, Any]]) -> dict[str, Any]:
        findings: list[dict[str, Any]] = []
        trace: list[dict[str, str]] = []
        if connector.get("endpoint"):
            connectivity = self._probe_connectivity(connector)
            trace.append({"agent": "ConnectivityAgent", "result": connectivity["status"]})
            if connectivity["status"] != "reachable":
                findings.append(connectivity)
        else:
            trace.append({"agent": "ConnectivityAgent", "result": "skipped: replay-only mode"})

        for index, attempt in enumerate(attempts, start=1):
            replay = self._replay_attempt(attempt, connector, index)
            findings.extend(replay)
        trace.extend(
            [
                {"agent": "AuthenticationAgent", "result": self._summary(findings, "authentication")},
                {"agent": "CollectionRoutingAgent", "result": self._summary(findings, "collection")},
                {"agent": "SchemaAgent", "result": self._summary(findings, "schema")},
                {"agent": "ReplayAgent", "result": f"replayed {len(attempts)} captured attempts"},
            ]
        )
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        findings.sort(key=lambda finding: severity_order[finding["severity"]])
        return {
            "report_type": "connector_diagnostic",
            "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
            "connector": {key: connector.get(key) for key in ("name", "connector_type", "endpoint", "collection_id")},
            "attempts_replayed": len(attempts),
            "status": "healthy" if not findings else "action_required",
            "findings": findings,
            "agent_trace": trace,
        }

    @staticmethod
    def _probe_connectivity(connector: dict[str, Any]) -> dict[str, Any]:
        endpoint = str(connector["endpoint"])
        request = Request(endpoint, method="GET", headers={"Accept": "application/json"})
        try:
            with urlopen(request, timeout=5) as response:  # nosec B310 - explicit operator-provided connector URL
                return {"category": "connectivity", "severity": "low", "status": "reachable", "evidence": f"HTTP {response.status}", "suggestion": "No network remediation required."}
        except HTTPError as error:
            return {"category": "connectivity", "severity": "medium", "status": "http_error", "evidence": f"HTTP {error.code} from {endpoint}", "suggestion": "Confirm the endpoint path and service availability."}
        except (URLError, TimeoutError) as error:
            return {"category": "connectivity", "severity": "high", "status": "unreachable", "evidence": f"Connection failed: {error.reason if isinstance(error, URLError) else error}", "suggestion": "Check DNS, proxy/firewall policy, and the connector endpoint."}

    @staticmethod
    def _replay_attempt(attempt: dict[str, Any], connector: dict[str, Any], index: int) -> list[dict[str, Any]]:
        response_code = int(attempt.get("response_status", 0))
        findings: list[dict[str, Any]] = []
        if response_code in {401, 403}:
            findings.append(
                ConnectorTroubleshootingWorkflow._finding(
                    "authentication", "high", index, response_code,
                    "The server rejected connector credentials.",
                    "Refresh the token, verify its scope, and confirm it is sent in the expected authorization header.",
                )
            )
        if response_code == 404 or (connector.get("collection_id") and str(connector["collection_id"]) not in str(attempt.get("request_url", ""))):
            findings.append(
                ConnectorTroubleshootingWorkflow._finding(
                    "collection", "high", index, response_code,
                    "The configured TAXII collection id is absent from the replayed request or the server returned 404.",
                    "Retrieve the server discovery document and replace the collection id with an accessible collection identifier.",
                )
            )
        expected = set(connector.get("required_fields", ["type", "id", "spec_version"]))
        payload = attempt.get("payload", {})
        if isinstance(payload, str):
            try:
                payload = json.loads(payload)
            except json.JSONDecodeError:
                payload = {}
        objects = payload.get("objects", [payload]) if isinstance(payload, dict) else []
        for object_index, item in enumerate(objects, start=1):
            if not isinstance(item, dict):
                findings.append(ConnectorTroubleshootingWorkflow._finding("schema", "high", index, response_code, f"Payload object {object_index} is not a JSON object.", "Serialize the ingestion payload as JSON objects before replaying."))
                continue
            missing = sorted(expected - set(item))
            if missing:
                findings.append(ConnectorTroubleshootingWorkflow._finding("schema", "high", index, response_code, f"Payload object {object_index} is missing required fields: {', '.join(missing)}.", "Map the missing source fields before sending the object; do not retry this payload unchanged."))
        if response_code >= 500:
            findings.append(ConnectorTroubleshootingWorkflow._finding("service", "medium", index, response_code, "The remote service returned a server error.", "Retry with exponential backoff after verifying the same payload succeeds against a staging collection."))
        return findings

    @staticmethod
    def _finding(category: str, severity: str, attempt: int, response_code: int, evidence: str, suggestion: str) -> dict[str, Any]:
        return {"category": category, "severity": severity, "attempt": attempt, "response_status": response_code, "evidence": evidence, "suggestion": suggestion}

    @staticmethod
    def _summary(findings: list[dict[str, Any]], category: str) -> str:
        count = sum(1 for finding in findings if finding["category"] == category)
        return "no issue found" if not count else f"{count} finding(s)"