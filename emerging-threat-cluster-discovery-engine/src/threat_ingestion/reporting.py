from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from .persistence.models import (
    CollectionRunRecord,
    IndicatorRecord,
    ObservationRecord,
    RunSourceAttemptRecord,
)


def _top_rows(counter: Counter[str], limit: int = 10) -> list[tuple[str, int]]:
    return counter.most_common(limit)


def _markdown_table(rows: list[tuple[str, int]], heading: str) -> list[str]:
    lines = [f"### {heading}", "", "| Value | Count |", "|---|---:|"]
    lines.extend(f"| {value.replace('|', '\\|')} | {count} |" for value, count in rows)
    lines.append("")
    return lines


def _correlation_rows(
    observations: list[ObservationRecord], indicator_by_id: dict[int, IndicatorRecord]
) -> list[tuple[str, int, str, str, str]]:
    clusters: dict[str, dict[str, Any]] = {}
    for observation in observations:
        metadata: dict[str, Any] = observation.metadata_json or {}
        family = str(metadata.get("malware") or metadata.get("malware_family") or "unlabeled")
        cluster = clusters.setdefault(
            family, {"count": 0, "sources": set(), "types": set(), "tags": Counter()}
        )
        cluster["count"] += 1
        cluster["sources"].add(observation.source)
        indicator = indicator_by_id.get(observation.indicator_id)
        if indicator:
            cluster["types"].add(indicator.indicator_type)
        tags = metadata.get("tags") or []
        if isinstance(tags, list):
            cluster["tags"].update(str(tag) for tag in tags if tag)

    rows = []
    for family, cluster in clusters.items():
        top_tags = ", ".join(tag for tag, _ in cluster["tags"].most_common(3)) or "none"
        rows.append(
            (
                family,
                cluster["count"],
                ", ".join(sorted(cluster["sources"])),
                ", ".join(sorted(cluster["types"])),
                top_tags,
            )
        )
    return sorted(rows, key=lambda row: (-row[1], row[0]))[:15]


def build_report(session: Session, recent_limit: int = 20) -> str:
    indicators = session.scalars(select(IndicatorRecord)).all()
    observations = session.scalars(
        select(ObservationRecord).order_by(ObservationRecord.observed_at.desc())
    ).all()
    runs = session.scalars(select(CollectionRunRecord).order_by(CollectionRunRecord.started_at.desc())).all()
    attempts = session.scalars(select(RunSourceAttemptRecord)).all()

    indicator_by_id = {indicator.id: indicator for indicator in indicators}
    source_counts = Counter(observation.source for observation in observations)
    type_counts = Counter(
        indicator_by_id[observation.indicator_id].indicator_type
        for observation in observations
        if observation.indicator_id in indicator_by_id
    )
    family_counts: Counter[str] = Counter()
    tag_counts: Counter[str] = Counter()
    for observation in observations:
        metadata: dict[str, Any] = observation.metadata_json or {}
        family = metadata.get("malware") or metadata.get("malware_family")
        if family:
            family_counts[str(family)] += 1
        tags = metadata.get("tags") or []
        if isinstance(tags, list):
            tag_counts.update(str(tag) for tag in tags if tag)

    successful_attempts = sum(attempt.status == "success" for attempt in attempts)
    failed_attempts = sum(attempt.status == "failed" for attempt in attempts)
    generated_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    lines = [
        "# Threat Intelligence Report",
        "",
        f"Generated: `{generated_at}`",
        "",
        "## Overview",
        "",
        f"- Indicators: **{len(indicators)}**",
        f"- Observations: **{len(observations)}**",
        f"- Collection runs: **{len(runs)}**",
        f"- Source attempts: **{len(attempts)}** ({successful_attempts} successful, {failed_attempts} failed)",
        "",
    ]
    lines.extend(_markdown_table(_top_rows(source_counts), "Observations by Source"))
    lines.extend(_markdown_table(_top_rows(type_counts), "Indicators by Type"))
    lines.extend(_markdown_table(_top_rows(family_counts), "Top Malware Families"))
    lines.extend(_markdown_table(_top_rows(tag_counts), "Top Tags"))

    lines.extend(
        [
            "### Correlation Clusters",
            "",
            "Clusters group observations by malware family and show their source and IOC-type spread.",
            "",
            "| Family | Observations | Sources | IOC Types | Top Tags |",
            "|---|---:|---|---|---|",
        ]
    )
    for family, count, sources, indicator_types, top_tags in _correlation_rows(
        observations, indicator_by_id
    ):
        lines.append(
            f"| {family.replace('|', '\\|')} | {count} | {sources} | {indicator_types} | {top_tags} |"
        )
    lines.append("")

    lines.extend(["## Recent Observations", "", "| Source | Type | Indicator | Observed At |", "|---|---|---|---|"])
    for observation in observations[:recent_limit]:
        indicator = indicator_by_id.get(observation.indicator_id)
        value = indicator.canonical_value if indicator else "unknown"
        indicator_type = indicator.indicator_type if indicator else "unknown"
        lines.append(
            f"| {observation.source} | {indicator_type} | `{value.replace('`', '')}` | {observation.observed_at.isoformat()} |"
        )
    lines.append("")
    return "\n".join(lines)


def write_report(session: Session, output_path: str, recent_limit: int = 20) -> Path:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(build_report(session, recent_limit=recent_limit), encoding="utf-8")
    return path
