from __future__ import annotations

import json
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable

# Parameters that accept attacker-controlled input and are logged by CloudTrail.
FINGERPRINT_PARAMETERS = ("clusterName", "keyName", "publicKeyMaterial", "userName", "functionName", "roleName")

DEFAULT_PARAMETER_BASELINE = {"clusterName": {"default", "prod-services"}}

SCRIPTED_AGENTS = ("boto3", "python-requests", "aws-sdk-go", "curl")

SEQUENCE_SIGNATURES: list[dict[str, Any]] = [
    {
        "id": "bapak-foothold",
        "name": "Bapak credential abuse chain",
        "kind": "actor",
        "sequence": ["ImportKeyPair", "GetCallerIdentity", "DescribeSubnets", "DescribeInstances", "CreateCluster"],
        "window_minutes": 30,
        "severity": "critical",
        "reference": "Wiz Research: tracking cloud-fluent threat actors, part two",
        "detail": "Key import for persistence, environment discovery, then ECS cluster creation for resource hijacking.",
    },
    {
        "id": "androxgh0st-ses",
        "name": "AndroxGh0st SES abuse",
        "kind": "actor",
        "sequence": ["GetSendQuota", "CreateUser"],
        "window_minutes": 15,
        "severity": "high",
        "reference": "Wiz Research: behavioral cloud IOCs",
        "detail": "SES quota check followed by IAM user creation, typically repeated across regions.",
    },
    {
        "id": "generic-cred-recon",
        "name": "Compromised credential reconnaissance",
        "kind": "generic",
        "sequence": ["GetCallerIdentity", "ListAttachedUserPolicies"],
        "window_minutes": 10,
        "severity": "medium",
        "reference": "Generic TTP pattern",
        "detail": "Scripted identity and permission enumeration immediately after initial access.",
    },
    {
        "id": "llmjacking",
        "name": "LLMjacking model access abuse",
        "kind": "generic",
        "sequence": ["PutUseCaseForModelAccess", "InvokeModel"],
        "window_minutes": 30,
        "severity": "high",
        "reference": "Wiz Research: JINX-2401 LLM hijacking",
        "detail": "Model access request followed by inference calls on a compromised identity.",
    },
]


def load_events(path: str | Path) -> list[dict[str, Any]]:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    events = payload.get("events", payload) if isinstance(payload, dict) else payload
    return sorted(events, key=lambda event: event["eventTime"])


def _parsed_time(event: dict[str, Any]) -> datetime:
    return datetime.strptime(event["eventTime"], "%Y-%m-%dT%H:%M:%SZ")


def _identity_key(event: dict[str, Any]) -> tuple[str, str]:
    return (event.get("accessKeyId", "unknown"), event.get("sourceIPAddress", "unknown"))


def group_by_identity(events: Iterable[dict[str, Any]]) -> dict[tuple[str, str], list[dict[str, Any]]]:
    grouped: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for event in events:
        grouped[_identity_key(event)].append(event)
    return grouped


def detect_sequences(events: Iterable[dict[str, Any]], signatures: list[dict[str, Any]] | None = None) -> list[dict[str, Any]]:
    """Match ordered API call sequences within a time window per credential and source IP."""
    signatures = signatures or SEQUENCE_SIGNATURES
    detections: list[dict[str, Any]] = []

    for (access_key, source_ip), group in group_by_identity(events).items():
        ordered = sorted(group, key=_parsed_time)
        names = [event["eventName"] for event in ordered]

        for signature in signatures:
            wanted = signature["sequence"]
            cursor = 0
            matched: list[dict[str, Any]] = []
            for index, name in enumerate(names):
                if name == wanted[cursor]:
                    matched.append(ordered[index])
                    cursor += 1
                    if cursor == len(wanted):
                        break
            if cursor != len(wanted):
                continue

            span = (_parsed_time(matched[-1]) - _parsed_time(matched[0])).total_seconds() / 60
            if span > signature["window_minutes"]:
                continue

            regions = sorted({event["awsRegion"] for event in ordered if event["eventName"] in wanted})
            detections.append(
                {
                    "signature_id": signature["id"],
                    "name": signature["name"],
                    "kind": signature["kind"],
                    "severity": signature["severity"],
                    "access_key": access_key,
                    "source_ip": source_ip,
                    "principal": ordered[0].get("principal", "unknown"),
                    "country": ordered[0].get("country", "unknown"),
                    "asn": ordered[0].get("asn", "unknown"),
                    "first_seen": matched[0]["eventTime"],
                    "last_seen": matched[-1]["eventTime"],
                    "span_minutes": round(span, 1),
                    "regions": regions,
                    "multi_region": len(regions) > 1,
                    "sequence": wanted,
                    "detail": signature["detail"],
                    "reference": signature["reference"],
                }
            )

    return sorted(detections, key=lambda item: (item["severity"] != "critical", item["first_seen"]))


def extract_parameter_iocs(
    events: Iterable[dict[str, Any]],
    baseline: dict[str, set[str]] | None = None,
) -> list[dict[str, Any]]:
    """Pull attacker-controlled parameter values that are unique enough to hunt on."""
    baseline = baseline or DEFAULT_PARAMETER_BASELINE
    observed: dict[tuple[str, str, str], dict[str, Any]] = {}

    for event in events:
        parameters = event.get("requestParameters") or {}
        for name, value in parameters.items():
            if name not in FINGERPRINT_PARAMETERS or not isinstance(value, str):
                continue
            if value in baseline.get(name, set()):
                continue
            key = (event["eventName"], name, value)
            record = observed.setdefault(
                key,
                {
                    "api": event["eventName"],
                    "parameter": name,
                    "value": value,
                    "observations": 0,
                    "access_keys": set(),
                    "source_ips": set(),
                    "accounts": set(),
                    "regions": set(),
                },
            )
            record["observations"] += 1
            record["access_keys"].add(event.get("accessKeyId", "unknown"))
            record["source_ips"].add(event.get("sourceIPAddress", "unknown"))
            record["accounts"].add(str(event.get("principal", "unknown")).split(":")[4] if ":" in str(event.get("principal", "")) else "unknown")
            record["regions"].add(event.get("awsRegion", "unknown"))

    results = []
    for record in observed.values():
        record["access_keys"] = sorted(record["access_keys"])
        record["source_ips"] = sorted(record["source_ips"])
        record["accounts"] = sorted(record["accounts"])
        record["regions"] = sorted(record["regions"])
        # A value reused across distinct identities is far stronger than a one-off string.
        record["cross_identity"] = len(record["access_keys"]) > 1
        record["confidence"] = "high" if record["cross_identity"] else "medium"
        record["hunt_query"] = (
            f'eventName = "{record["api"]}" AND requestParameters.{record["parameter"]} = "{record["value"]}"'
        )
        results.append(record)

    return sorted(results, key=lambda item: (not item["cross_identity"], -item["observations"], item["value"]))


def cluster_actors(events: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """Group activity by API call set and source metadata, mirroring the honeypot pivot method."""
    grouped: dict[tuple[str, str, str], dict[str, Any]] = {}

    for (access_key, source_ip), group in group_by_identity(events).items():
        api_set = tuple(sorted({event["eventName"] for event in group}))
        sample = group[0]
        key = (sample.get("asn", "unknown"), sample.get("country", "unknown"), "|".join(api_set))
        cluster = grouped.setdefault(
            key,
            {
                "asn": sample.get("asn", "unknown"),
                "country": sample.get("country", "unknown"),
                "api_calls": list(api_set),
                "access_keys": set(),
                "source_ips": set(),
                "principals": set(),
                "event_count": 0,
            },
        )
        cluster["access_keys"].add(access_key)
        cluster["source_ips"].add(source_ip)
        cluster["principals"].add(sample.get("principal", "unknown"))
        cluster["event_count"] += len(group)

    clusters = []
    for index, cluster in enumerate(grouped.values(), start=1):
        cluster["cluster_id"] = f"cluster-{index:02d}"
        cluster["access_keys"] = sorted(cluster["access_keys"])
        cluster["source_ips"] = sorted(cluster["source_ips"])
        cluster["principals"] = sorted(cluster["principals"])
        cluster["identity_count"] = len(cluster["access_keys"])
        clusters.append(cluster)

    return sorted(clusters, key=lambda item: (-item["identity_count"], -item["event_count"]))


def contextual_signals(events: Iterable[dict[str, Any]], known_countries: set[str] | None = None) -> list[dict[str, Any]]:
    """Flag contextual anomalies such as scripted agents, unusual geography, and failed enumeration."""
    known_countries = known_countries if known_countries is not None else {"US"}
    signals: list[dict[str, Any]] = []

    for (access_key, source_ip), group in group_by_identity(events).items():
        sample = group[0]
        agents = {str(event.get("userAgent", "")).lower() for event in group}
        scripted = [agent for agent in agents if any(marker in agent for marker in SCRIPTED_AGENTS)]
        denials = [event for event in group if event.get("errorCode")]
        regions = {event["awsRegion"] for event in group}

        findings = []
        if scripted:
            findings.append(f"scripted user agent ({', '.join(sorted(scripted))})")
        if sample.get("country") not in known_countries:
            findings.append(f"unusual source geography ({sample.get('country')})")
        if "tor" in str(sample.get("asn", "")).lower():
            findings.append("source ASN associated with anonymizing infrastructure")
        if len(denials) >= 1:
            findings.append(f"{len(denials)} access-denied response(s) indicating permission probing")
        if len(regions) > 1:
            findings.append(f"activity spans {len(regions)} regions")

        if findings:
            signals.append(
                {
                    "access_key": access_key,
                    "source_ip": source_ip,
                    "principal": sample.get("principal", "unknown"),
                    "country": sample.get("country", "unknown"),
                    "asn": sample.get("asn", "unknown"),
                    "signal_count": len(findings),
                    "signals": findings,
                }
            )

    return sorted(signals, key=lambda item: -item["signal_count"])


def hunt(path: str | Path, known_countries: set[str] | None = None) -> dict[str, Any]:
    events = load_events(path)
    detections = detect_sequences(events)
    parameter_iocs = extract_parameter_iocs(events)
    clusters = cluster_actors(events)
    signals = contextual_signals(events, known_countries)

    compromised = sorted({detection["access_key"] for detection in detections})
    return {
        "event_count": len(events),
        "api_distribution": Counter(event["eventName"] for event in events).most_common(),
        "detections": detections,
        "parameter_iocs": parameter_iocs,
        "clusters": clusters,
        "contextual_signals": signals,
        "suspected_compromised_credentials": compromised,
        "critical_count": sum(1 for detection in detections if detection["severity"] == "critical"),
    }
