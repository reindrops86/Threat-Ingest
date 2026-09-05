from __future__ import annotations

import csv
import ipaddress
import json
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class FeedNormalizationWorkflow:
    """Coordinates specialist agents while retaining a trace for every decision."""

    def run(self, source: str | Path) -> dict[str, Any]:
        source_path = Path(source)
        feed_type, records = self._detect_and_ingest(source_path)
        normalized, corrections, skipped = self._normalize(records)
        bundle = self._to_stix_bundle(normalized, feed_type, source_path.name)
        validation_errors = self._validate_bundle(bundle)
        return {
            "feed_type": feed_type,
            "source": str(source_path),
            "input_records": len(records),
            "normalized_records": len(normalized),
            "skipped_records": skipped,
            "corrections": corrections,
            "bundle": bundle,
            "validation_errors": validation_errors,
            "agent_trace": [
                {"agent": "FeedDetectionAgent", "result": feed_type},
                {"agent": "FieldMappingAgent", "result": f"mapped {len(normalized)} records"},
                {"agent": "SchemaValidationAgent", "result": "valid" if not validation_errors else validation_errors},
            ],
        }

    def _detect_and_ingest(self, source_path: Path) -> tuple[str, list[dict[str, Any]]]:
        content = source_path.read_text(encoding="utf-8-sig")
        if source_path.suffix.lower() == ".csv":
            return "csv", list(csv.DictReader(content.splitlines()))

        payload = json.loads(content)
        if isinstance(payload, dict) and "Event" in payload:
            attributes = payload["Event"].get("Attribute", [])
            return "misp", [attribute for attribute in attributes if isinstance(attribute, dict)]
        if isinstance(payload, dict) and "data" in payload and isinstance(payload["data"], list):
            return "opencti", [item.get("node", item) for item in payload["data"] if isinstance(item, dict)]
        if isinstance(payload, dict) and isinstance(payload.get("indicators"), list):
            return "vendor_json", [item for item in payload["indicators"] if isinstance(item, dict)]
        if isinstance(payload, list):
            return "json_api", [item for item in payload if isinstance(item, dict)]
        raise ValueError("Unsupported JSON feed: expected MISP Event, OpenCTI data, indicators, or a record list.")

    def _normalize(self, records: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, str]], int]:
        normalized: list[dict[str, Any]] = []
        corrections: list[dict[str, str]] = []
        skipped = 0
        for index, record in enumerate(records, start=1):
            raw_type = str(record.get("type") or record.get("indicator_type") or record.get("category") or "").lower()
            raw_value = record.get("value") or record.get("ioc") or record.get("indicator") or record.get("observable_value")
            if not raw_value:
                skipped += 1
                continue
            value = str(raw_value).strip().replace("[.]", ".")
            value = re.sub(r"^hxxps?://", lambda match: "https://" if "hxxps" in match.group(0) else "http://", value, flags=re.I)
            if value != str(raw_value).strip():
                corrections.append({"record": str(index), "field": "value", "from": str(raw_value), "to": value})

            object_type = self._object_type(raw_type, value)
            if not object_type:
                skipped += 1
                continue
            if object_type == "file":
                value = value.lower()
            normalized.append(
                {
                    "object_type": object_type,
                    "value": value,
                    "labels": self._labels(record),
                    "confidence": self._confidence(record.get("confidence")),
                    "timestamp": self._timestamp(record.get("timestamp") or record.get("date") or record.get("created")),
                }
            )
        return normalized, corrections, skipped

    @staticmethod
    def _object_type(raw_type: str, value: str) -> str | None:
        if raw_type in {"ip-src", "ip-dst", "ip", "ipv4", "ipv6"}:
            try:
                return "ipv6-addr" if ipaddress.ip_address(value).version == 6 else "ipv4-addr"
            except ValueError:
                return None
        if raw_type in {"domain", "hostname", "domain-name"}:
            return "domain-name"
        if raw_type in {"url", "uri"}:
            return "url"
        if raw_type in {"md5", "sha1", "sha-1", "sha256", "sha-256", "hash"}:
            return "file"
        if re.fullmatch(r"[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64}", value):
            return "file"
        if re.match(r"^https?://", value, flags=re.I):
            return "url"
        try:
            return "ipv6-addr" if ipaddress.ip_address(value).version == 6 else "ipv4-addr"
        except ValueError:
            return "domain-name" if "." in value and " " not in value else None

    @staticmethod
    def _labels(record: dict[str, Any]) -> list[str]:
        tags = record.get("tags") or record.get("Tag") or []
        if isinstance(tags, str):
            tags = re.split(r"[,;]", tags)
        labels = [str(tag.get("name", "")) if isinstance(tag, dict) else str(tag) for tag in tags]
        return [label.strip().lower() for label in labels if label.strip()] or ["threat-intel"]

    @staticmethod
    def _confidence(value: Any) -> int:
        try:
            confidence = float(value)
            return max(0, min(100, round(confidence * 100 if confidence <= 1 else confidence)))
        except (TypeError, ValueError):
            return 50

    @staticmethod
    def _timestamp(value: Any) -> str:
        if value:
            text = str(value).replace("Z", "+00:00").replace("/", "-")
            try:
                return datetime.fromisoformat(text).astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
            except ValueError:
                pass
        return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")

    def _to_stix_bundle(self, records: list[dict[str, Any]], feed_type: str, source_name: str) -> dict[str, Any]:
        objects = []
        for record in records:
            pattern = self._pattern(record["object_type"], record["value"])
            timestamp = record["timestamp"]
            objects.append(
                {
                    "type": "indicator",
                    "spec_version": "2.1",
                    "id": f"indicator--{uuid.uuid4()}",
                    "created": timestamp,
                    "modified": timestamp,
                    "name": f"Normalized {record['object_type']} indicator",
                    "pattern": pattern,
                    "pattern_type": "stix",
                    "valid_from": timestamp,
                    "confidence": record["confidence"],
                    "labels": record["labels"],
                    "external_references": [{"source_name": source_name, "description": f"Normalized from {feed_type} feed"}],
                }
            )
        return {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": objects}

    @staticmethod
    def _pattern(object_type: str, value: str) -> str:
        escaped = value.replace("\\", "\\\\").replace("'", "\\'")
        if object_type == "file":
            algorithm = {32: "MD5", 40: "SHA-1", 64: "SHA-256"}.get(len(value), "MD5")
            return f"[file:hashes.'{algorithm}' = '{escaped}']"
        return f"[{object_type}:value = '{escaped}']"

    @staticmethod
    def _validate_bundle(bundle: dict[str, Any]) -> list[str]:
        errors: list[str] = []
        if bundle.get("type") != "bundle" or not str(bundle.get("id", "")).startswith("bundle--"):
            errors.append("Bundle must have type 'bundle' and a STIX bundle id.")
        for index, obj in enumerate(bundle.get("objects", []), start=1):
            required = ("type", "spec_version", "id", "created", "modified", "pattern", "pattern_type", "valid_from")
            missing = [field for field in required if not obj.get(field)]
            if missing:
                errors.append(f"Object {index} is missing: {', '.join(missing)}.")
            if obj.get("type") != "indicator" or obj.get("spec_version") != "2.1":
                errors.append(f"Object {index} is not a STIX 2.1 indicator.")
            if not re.fullmatch(r"\[[^\]]+\]", str(obj.get("pattern", ""))):
                errors.append(f"Object {index} has an invalid STIX pattern envelope.")
        return errors