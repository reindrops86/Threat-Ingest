from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict

# Ensure wrappers module can be resolved regardless of execution directory
sys.path.append(str(Path(__file__).resolve().parent.parent))

from wrappers.abuseipdb_wrapper import AbuseIPDBWrapper
from wrappers.censys_wrapper import CensysWrapper
from wrappers.greynoise_wrapper import GreyNoiseWrapper
from wrappers.hybrid_analysis_wrapper import HybridAnalysisWrapper
from wrappers.misp_wrapper import MISPWrapper
from wrappers.otx_wrapper import AlienVaultOTXWrapper
from wrappers.shodan_wrapper import ShodanWrapper
from wrappers.virustotal_wrapper import VirusTotalWrapper


def detect_indicator_type(indicator: str) -> str:
    """Classify indicator into ip, hash, url, or domain."""
    indicator = indicator.strip()
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", indicator):
        return "ip"
    elif re.match(r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$", indicator):
        return "hash"
    elif indicator.startswith("http://") or indicator.startswith("https://"):
        return "url"
    else:
        return "domain"


class UnifiedEnricher:
    """Unified threat intelligence enrichment engine calling multi-source CTI services."""

    def __init__(self) -> None:
        self.vt = VirusTotalWrapper()
        self.ha = HybridAnalysisWrapper()
        self.abuseipdb = AbuseIPDBWrapper()
        self.greynoise = GreyNoiseWrapper()
        self.shodan = ShodanWrapper()
        self.censys = CensysWrapper()
        self.otx = AlienVaultOTXWrapper()
        self.misp = MISPWrapper()

    def enrich(self, indicator: str) -> Dict[str, Any]:
        ind_type = detect_indicator_type(indicator)
        results: Dict[str, Any] = {
            "indicator": indicator,
            "type": ind_type,
            "enrichments": {},
        }

        if ind_type == "ip":
            results["enrichments"]["virustotal"] = self.vt.ip_report(indicator)
            results["enrichments"]["abuseipdb"] = self.abuseipdb.check_ip(indicator)
            results["enrichments"]["greynoise"] = self.greynoise.ip_context(indicator)
            results["enrichments"]["shodan"] = self.shodan.host(indicator)
            results["enrichments"]["censys"] = self.censys.view_host(indicator)
            results["enrichments"]["otx"] = self.otx.get_indicator_details("IPv4", indicator)
            results["enrichments"]["misp"] = self.misp.search_attributes(indicator)

        elif ind_type == "hash":
            results["enrichments"]["virustotal"] = self.vt.hash_report(indicator)
            results["enrichments"]["hybrid_analysis"] = self.ha.hash_search(indicator)
            results["enrichments"]["otx"] = self.otx.get_indicator_details("hash", indicator)
            results["enrichments"]["misp"] = self.misp.search_attributes(indicator)

        elif ind_type == "url":
            results["enrichments"]["virustotal"] = self.vt.url_report(indicator)
            results["enrichments"]["hybrid_analysis"] = self.ha.url_quick_scan(indicator)
            results["enrichments"]["otx"] = self.otx.get_indicator_details("url", indicator)
            results["enrichments"]["misp"] = self.misp.search_attributes(indicator)

        elif ind_type == "domain":
            results["enrichments"]["virustotal"] = self.vt.domain_report(indicator)
            results["enrichments"]["censys"] = self.censys.search_certificates(indicator)
            results["enrichments"]["shodan"] = self.shodan.search(f"hostname:{indicator}")
            results["enrichments"]["otx"] = self.otx.get_indicator_details("domain", indicator)
            results["enrichments"]["misp"] = self.misp.search_attributes(indicator)

        return results


def main() -> None:
    parser = argparse.ArgumentParser(description="Unified CTI Indicator Enricher")
    parser.add_argument("--indicator", "-i", required=True, help="IP, Domain, URL, or File Hash to enrich")
    args = parser.parse_args()

    enricher = UnifiedEnricher()
    report = enricher.enrich(args.indicator)
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
