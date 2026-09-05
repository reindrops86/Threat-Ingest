from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

# Evidence weights. A reused attacker-controlled value is far stronger than shared hosting.
EVIDENCE_WEIGHTS = {
    "fingerprint": 60,
    "source_ip": 25,
    "signature": 20,
    "asn": 15,
}

LINK_THRESHOLD = 50
HALF_LIFE_DAYS = 90


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _parse(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def build_observations(hunt_result: dict[str, Any], source_label: str) -> list[dict[str, Any]]:
    """Convert a behavioral hunt result into per-credential activity observations."""
    fingerprints_by_key: dict[str, list[dict[str, str]]] = {}
    for ioc in hunt_result.get("parameter_iocs", []):
        for access_key in ioc["access_keys"]:
            fingerprints_by_key.setdefault(access_key, []).append(
                {"parameter": ioc["parameter"], "value": ioc["value"], "api": ioc["api"]}
            )

    grouped: dict[tuple[str, str], dict[str, Any]] = {}
    for detection in hunt_result.get("detections", []):
        key = (detection["access_key"], detection["source_ip"])
        observation = grouped.setdefault(
            key,
            {
                "source_label": source_label,
                "access_key": detection["access_key"],
                "source_ip": detection["source_ip"],
                "asn": detection["asn"],
                "country": detection["country"],
                "victim": detection["principal"],
                "first_seen": detection["first_seen"],
                "last_seen": detection["last_seen"],
                "signatures": [],
                "fingerprints": fingerprints_by_key.get(detection["access_key"], []),
                "severities": [],
            },
        )
        observation["signatures"].append(detection["signature_id"])
        observation["severities"].append(detection["severity"])
        observation["first_seen"] = min(observation["first_seen"], detection["first_seen"])
        observation["last_seen"] = max(observation["last_seen"], detection["last_seen"])

    return list(grouped.values())


def score_link(observation: dict[str, Any], profile: dict[str, Any]) -> tuple[int, list[str]]:
    """Score how strongly an observation links to a tracked actor."""
    score = 0
    reasons: list[str] = []

    profile_fingerprints = {(item["parameter"], item["value"]) for item in profile["fingerprints"]}
    shared = [item for item in observation["fingerprints"] if (item["parameter"], item["value"]) in profile_fingerprints]
    if shared:
        score += EVIDENCE_WEIGHTS["fingerprint"]
        reasons.append(
            "shared fingerprint: " + ", ".join(f"{item['parameter']}={item['value']}" for item in shared)
        )

    if observation["source_ip"] in profile["infrastructure"]["source_ips"]:
        score += EVIDENCE_WEIGHTS["source_ip"]
        reasons.append(f"source IP reuse: {observation['source_ip']}")

    shared_signatures = sorted(set(observation["signatures"]) & set(profile["signatures"]))
    if shared_signatures:
        score += EVIDENCE_WEIGHTS["signature"]
        reasons.append("shared behavior: " + ", ".join(shared_signatures))

    if observation["asn"] in profile["infrastructure"]["asns"]:
        score += EVIDENCE_WEIGHTS["asn"]
        reasons.append(f"shared ASN: {observation['asn']}")

    return min(100, score), reasons


def decayed_confidence(profile: dict[str, Any], as_of: datetime | None = None) -> int:
    """Reduce confidence as an actor goes quiet, since stale clusters are weaker evidence."""
    as_of = as_of or _now()
    days_quiet = max(0.0, (as_of - _parse(profile["last_seen"])).total_seconds() / 86400)
    decay = 0.5 ** (days_quiet / HALF_LIFE_DAYS)
    return max(10, int(profile["evidence_confidence"] * decay))


def _evidence_confidence(profile: dict[str, Any]) -> int:
    score = 30
    score += 25 if profile["fingerprints"] else 0
    score += min(20, 5 * len(set(profile["signatures"])))
    score += min(15, 5 * len(profile["victims"]))
    score += 10 if len(profile["infrastructure"]["asns"]) > 1 else 0
    return min(100, score)


class ActorRegistry:
    """Persistent registry of tracked cloud threat actors."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def load(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        payload = json.loads(self.path.read_text(encoding="utf-8"))
        return payload.get("actors", []) if isinstance(payload, dict) else payload

    def save(self, actors: list[dict[str, Any]]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(
            json.dumps({"updated_at": _now().isoformat(timespec="seconds"), "actors": actors}, indent=2),
            encoding="utf-8",
        )

    def _new_profile(self, observation: dict[str, Any], index: int) -> dict[str, Any]:
        return {
            "actor_id": f"UNC-{index:04d}",
            "name": None,
            "status": "candidate",
            "first_seen": observation["first_seen"],
            "last_seen": observation["last_seen"],
            "signatures": sorted(set(observation["signatures"])),
            "fingerprints": list(observation["fingerprints"]),
            "infrastructure": {
                "source_ips": [observation["source_ip"]],
                "asns": [observation["asn"]],
                "countries": [observation["country"]],
            },
            "victims": [observation["victim"]],
            "compromised_credentials": [observation["access_key"]],
            "timeline": [
                {
                    "observed": observation["last_seen"],
                    "source": observation["source_label"],
                    "event": "cluster created",
                    "source_ip": observation["source_ip"],
                    "asn": observation["asn"],
                    "country": observation["country"],
                }
            ],
            "notes": [],
            "evidence_confidence": 30,
        }

    @staticmethod
    def _absorb(profile: dict[str, Any], observation: dict[str, Any], reasons: list[str]) -> None:
        rotated = observation["asn"] not in profile["infrastructure"]["asns"]

        profile["first_seen"] = min(profile["first_seen"], observation["first_seen"])
        profile["last_seen"] = max(profile["last_seen"], observation["last_seen"])
        profile["signatures"] = sorted(set(profile["signatures"]) | set(observation["signatures"]))

        known = {(item["parameter"], item["value"]) for item in profile["fingerprints"]}
        for item in observation["fingerprints"]:
            if (item["parameter"], item["value"]) not in known:
                profile["fingerprints"].append(item)

        for field, value in (
            ("source_ips", observation["source_ip"]),
            ("asns", observation["asn"]),
            ("countries", observation["country"]),
        ):
            if value not in profile["infrastructure"][field]:
                profile["infrastructure"][field].append(value)

        if observation["victim"] not in profile["victims"]:
            profile["victims"].append(observation["victim"])
        if observation["access_key"] not in profile["compromised_credentials"]:
            profile["compromised_credentials"].append(observation["access_key"])

        profile["timeline"].append(
            {
                "observed": observation["last_seen"],
                "source": observation["source_label"],
                "event": "infrastructure rotation" if rotated else "activity linked",
                "source_ip": observation["source_ip"],
                "asn": observation["asn"],
                "country": observation["country"],
                "basis": "; ".join(reasons),
            }
        )
        profile["timeline"].sort(key=lambda item: item["observed"])

    def ingest(self, hunt_result: dict[str, Any], source_label: str) -> dict[str, Any]:
        """Fold a hunt result into the registry, linking to known actors where evidence supports it."""
        actors = self.load()
        created: list[str] = []
        linked: list[dict[str, Any]] = []

        for observation in build_observations(hunt_result, source_label):
            best_profile = None
            best_score = 0
            best_reasons: list[str] = []
            for profile in actors:
                score, reasons = score_link(observation, profile)
                if score > best_score:
                    best_profile, best_score, best_reasons = profile, score, reasons

            if best_profile and best_score >= LINK_THRESHOLD:
                self._absorb(best_profile, observation, best_reasons)
                best_profile["evidence_confidence"] = _evidence_confidence(best_profile)
                linked.append(
                    {
                        "actor_id": best_profile["actor_id"],
                        "score": best_score,
                        "reasons": best_reasons,
                        "access_key": observation["access_key"],
                    }
                )
            else:
                profile = self._new_profile(observation, len(actors) + 1)
                profile["evidence_confidence"] = _evidence_confidence(profile)
                actors.append(profile)
                created.append(profile["actor_id"])

        self.save(actors)
        return {"created": created, "linked": linked, "actor_count": len(actors)}

    def promote(self, actor_id: str, name: str, analyst: str = "analyst") -> dict[str, Any] | None:
        actors = self.load()
        for profile in actors:
            if profile["actor_id"] == actor_id:
                profile["name"] = name
                profile["status"] = "tracked"
                profile["notes"].append(
                    {"analyst": analyst, "timestamp": _now().isoformat(timespec="seconds"), "text": f"Promoted to tracked actor as {name}."}
                )
                self.save(actors)
                return profile
        return None

    def add_note(self, actor_id: str, text: str, analyst: str = "analyst") -> dict[str, Any] | None:
        actors = self.load()
        for profile in actors:
            if profile["actor_id"] == actor_id:
                profile["notes"].append({"analyst": analyst, "timestamp": _now().isoformat(timespec="seconds"), "text": text})
                self.save(actors)
                return profile
        return None

    def merge(self, primary_id: str, secondary_id: str, analyst: str = "analyst") -> dict[str, Any] | None:
        actors = self.load()
        primary = next((item for item in actors if item["actor_id"] == primary_id), None)
        secondary = next((item for item in actors if item["actor_id"] == secondary_id), None)
        if not primary or not secondary or primary_id == secondary_id:
            return None

        primary["first_seen"] = min(primary["first_seen"], secondary["first_seen"])
        primary["last_seen"] = max(primary["last_seen"], secondary["last_seen"])
        primary["signatures"] = sorted(set(primary["signatures"]) | set(secondary["signatures"]))

        known = {(item["parameter"], item["value"]) for item in primary["fingerprints"]}
        primary["fingerprints"].extend(
            item for item in secondary["fingerprints"] if (item["parameter"], item["value"]) not in known
        )
        for field in ("source_ips", "asns", "countries"):
            for value in secondary["infrastructure"][field]:
                if value not in primary["infrastructure"][field]:
                    primary["infrastructure"][field].append(value)
        for field in ("victims", "compromised_credentials"):
            for value in secondary[field]:
                if value not in primary[field]:
                    primary[field].append(value)

        primary["timeline"] = sorted(primary["timeline"] + secondary["timeline"], key=lambda item: item["observed"])
        primary["notes"].append(
            {"analyst": analyst, "timestamp": _now().isoformat(timespec="seconds"), "text": f"Merged {secondary_id} into {primary_id}."}
        )
        primary["evidence_confidence"] = _evidence_confidence(primary)

        actors = [item for item in actors if item["actor_id"] != secondary_id]
        self.save(actors)
        return primary

    def split(self, actor_id: str, credentials: Iterable[str], analyst: str = "analyst") -> dict[str, Any] | None:
        """Break contested credentials out into a new candidate cluster."""
        actors = self.load()
        source = next((item for item in actors if item["actor_id"] == actor_id), None)
        moving = [item for item in credentials if item in (source or {}).get("compromised_credentials", [])]
        if not source or not moving or len(moving) >= len(source["compromised_credentials"]):
            return None

        new_profile = {
            "actor_id": f"UNC-{len(actors) + 1:04d}",
            "name": None,
            "status": "candidate",
            "first_seen": source["first_seen"],
            "last_seen": source["last_seen"],
            "signatures": list(source["signatures"]),
            "fingerprints": [],
            "infrastructure": {"source_ips": [], "asns": [], "countries": []},
            "victims": [],
            "compromised_credentials": moving,
            "timeline": [
                {
                    "observed": _now().isoformat(timespec="seconds"),
                    "source": "analyst",
                    "event": "split from " + actor_id,
                    "source_ip": "",
                    "asn": "",
                    "country": "",
                }
            ],
            "notes": [
                {"analyst": analyst, "timestamp": _now().isoformat(timespec="seconds"), "text": f"Split from {actor_id} after contradicting evidence."}
            ],
            "evidence_confidence": 30,
        }

        source["compromised_credentials"] = [item for item in source["compromised_credentials"] if item not in moving]
        source["notes"].append(
            {"analyst": analyst, "timestamp": _now().isoformat(timespec="seconds"), "text": f"Split {', '.join(moving)} into {new_profile['actor_id']}."}
        )
        source["evidence_confidence"] = _evidence_confidence(source)

        actors.append(new_profile)
        self.save(actors)
        return new_profile

    def roster(self, as_of: datetime | None = None) -> list[dict[str, Any]]:
        actors = self.load()
        for profile in actors:
            profile["current_confidence"] = decayed_confidence(profile, as_of)
            profile["days_quiet"] = int(
                max(0.0, ((as_of or _now()) - _parse(profile["last_seen"])).total_seconds() / 86400)
            )
            profile["rotations"] = sum(1 for item in profile["timeline"] if item["event"] == "infrastructure rotation")
        return sorted(actors, key=lambda item: (-item["current_confidence"], item["actor_id"]))
