from __future__ import annotations

import argparse
import os
from typing import Any

from app.collectors.domain_collector import DomainCollector
from app.collectors.github_collector import GitHubCollector
from app.collectors.text_collector import TextCollector
from app.exporters.json_exporter import JsonExporter
from app.extractors.keyword_extractor import KeywordSignalExtractor
from app.normalizers.entity_normalizer import EntityNormalizer
from app.reporting import ThreatReportBuilder
from app.scorers.risk_scorer import RiskScorer


def run(query: str, limit: int = 10, output_path: str = "data/sample_signals.json") -> list[dict[str, Any]]:
    collector = GitHubCollector(timeout=int(os.getenv("REQUEST_TIMEOUT", "10")))
    domain_collector = DomainCollector(timeout=int(os.getenv("REQUEST_TIMEOUT", "10")))
    text_collector = TextCollector()

    results = collector.search_repositories(query=query, limit=limit)
    baseline_text = " ".join([item.get("name", "") + " " + (item.get("description") or "") for item in results])
    domain_hits = domain_collector.extract_domains(baseline_text)
    inline = text_collector.collect(baseline_text)

    extractor = KeywordSignalExtractor()
    signals = []
    for item in results:
        text = " ".join(filter(None, [item.get("name"), item.get("description")]))
        extracted = extractor.extract(text, item.get("url", "github"), item.get("source_type", "github_repo"))
        for signal in extracted:
            if signal.get("entity"):
                signals.append(signal)

    for domain in domain_hits:
        metadata = domain_collector.query_domain_metadata(domain)
        signals.append({
            "entity": domain,
            "signal_type": "domain",
            "source": f"https://{domain}",
            "source_type": "domain",
            "snippet": f"Domain associated with query: {domain}",
            "confidence": 0.63,
            "tags": ["domain", "osint"],
            "raw_metadata": metadata,
        })

    for entry in inline:
        text = entry.get("content", "")
        signals.extend(extractor.extract(text, entry.get("source", "inline_text"), entry.get("source_type", "text")))

    normalized = EntityNormalizer().deduplicate(signals)
    scored = RiskScorer().score_batch(normalized)
    report = ThreatReportBuilder().build(scored)
    JsonExporter().export(report["signals"], output_path)
    return report["signals"]


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="OSINT Signal Extractor")
    parser.add_argument("--query", default=os.getenv("DEFAULT_QUERY", "ransomware"), help="OSINT query")
    parser.add_argument("--limit", type=int, default=int(os.getenv("DEFAULT_LIMIT", "10")), help="Max GitHub results")
    parser.add_argument("--output", default="data/sample_signals.json", help="Output path for JSON intelligence")
    args = parser.parse_args()

    payload = run(args.query, args.limit, args.output)
    report = ThreatReportBuilder().build(payload)
    print({
        "summary": report["summary"],
        "top_signal": report["top_signal"],
        "signals": report["signals"][:5],
    })
