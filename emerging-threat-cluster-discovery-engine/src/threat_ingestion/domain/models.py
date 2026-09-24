from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal
from uuid import UUID, uuid4

from pydantic import BaseModel, Field

SourceName = Literal["threatfox", "urlhaus", "malwarebazaar"]


class IocObservation(BaseModel):
    source: SourceName
    source_record_id: str
    indicator_type: str
    indicator_value: str
    observed_at: datetime
    tags: list[str] = Field(default_factory=list)
    confidence: int | None = None
    malware_family: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)

    @property
    def canonical_value(self) -> str:
        return self.indicator_value.strip().lower()


class SourceAttempt(BaseModel):
    source: SourceName
    fetched: int = 0
    accepted: int = 0
    inserted: int = 0
    updated: int = 0
    rejected: int = 0
    retries: int = 0
    status: Literal["success", "failed"]
    error: str | None = None


class CollectionRun(BaseModel):
    run_id: UUID = Field(default_factory=uuid4)
    started_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    ended_at: datetime | None = None
    dry_run: bool = False
    attempts: list[SourceAttempt] = Field(default_factory=list)


EnrichmentProviderName = Literal["rdap", "dns", "urlscan", "greynoise", "censys", "shodan", "otx", "abuseipdb"]


class EnrichmentResult(BaseModel):
    """A single provider's observation about an indicator, kept as an append-only event."""

    provider: EnrichmentProviderName
    indicator_type: str
    indicator_value: str
    observed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    asn: int | None = None
    asn_name: str | None = None
    country: str | None = None
    resolved_ips: list[str] = Field(default_factory=list)
    related_domains: list[str] = Field(default_factory=list)
    cert_fingerprints: list[str] = Field(default_factory=list)
    classification: str | None = None
    tags: list[str] = Field(default_factory=list)
    raw: dict[str, Any] = Field(default_factory=dict)
    error: str | None = None

    @property
    def canonical_value(self) -> str:
        return self.indicator_value.strip().lower()


class ClusterMember(BaseModel):
    indicator_type: str
    indicator_value: str


class ClusterEvidence(BaseModel):
    """A human-readable reason two or more indicators were grouped together."""

    kind: Literal["asn_overlap", "cert_reuse", "dns_overlap", "malware_family_overlap", "temporal_overlap"]
    detail: str
    members: list[str] = Field(default_factory=list)


class ClusterResult(BaseModel):
    cluster_key: str
    members: list[ClusterMember]
    evidence: list[ClusterEvidence] = Field(default_factory=list)
    confidence_score: float = 0.0
    confidence_label: Literal["low", "medium", "high"] = "low"
    first_observed: datetime | None = None
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def summary(self) -> str:
        return (
            f"{len(self.members)} indicators, {len(self.evidence)} correlated signals, "
            f"confidence {self.confidence_label}"
        )


class KevEntry(BaseModel):
    """One CISA Known Exploited Vulnerabilities catalog entry, enriched with the
    EPSS exploitation-probability score and (optionally) NVD's CVSS score."""

    cve_id: str
    vendor_project: str
    product: str
    vulnerability_name: str
    date_added: datetime
    short_description: str
    required_action: str
    due_date: datetime
    known_ransomware_use: bool = False
    cvss_score: float | None = None
    epss_score: float | None = None
    epss_percentile: float | None = None
    synced_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def priority_score(self) -> float:
        """Simple explainable ranking: KEV membership is already a strong exploitation
        signal, EPSS reflects near-term exploitation probability, CVSS reflects severity."""
        return (1.0 if self.known_ransomware_use else 0.5) + (self.epss_score or 0.0) + (
            (self.cvss_score or 0.0) / 10
        )


class CveLookup(BaseModel):
    """On-demand combined view of a single CVE, used by `vuln-lookup`."""

    cve_id: str
    in_kev: bool
    description: str | None = None
    cvss_score: float | None = None
    cvss_vector: str | None = None
    epss_score: float | None = None
    epss_percentile: float | None = None
    kev_due_date: datetime | None = None
    known_ransomware_use: bool = False


class AttackTechnique(BaseModel):
    """A single MITRE ATT&CK Enterprise technique associated with a malware family."""

    technique_id: str
    name: str
    tactic: str


class OsintReportItem(BaseModel):
    """A single item pulled from an OSINT research feed (Unit 42, DFIR Report, CISA)."""

    source: str
    title: str
    link: str
    published_at: datetime
    summary: str = ""
    fetched_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))