# CLI Examples

## Normalize IOCs from text

```bash
python scripts/ioc_normalizer.py --input sample.txt
```

## Stub hash lookup

```bash
python scripts/hash_lookup_stub.py --hash 44d88612fea8a8f36de82e1278abb02f
```

## Unified Multi-Source CTI Enrichment Engine

```bash
# Enrich an IP address across VirusTotal, AbuseIPDB, GreyNoise, Shodan, Censys, OTX, MISP
python scripts/unified_enrichment.py --indicator 198.51.100.45

# Enrich a SHA256 file hash across VirusTotal, Hybrid Analysis, OTX, MISP
python scripts/unified_enrichment.py --indicator 44d88612fea8a8f36de82e1278abb02f

# Enrich a suspicious URL across VirusTotal, Hybrid Analysis, OTX, MISP
python scripts/unified_enrichment.py --indicator http://login.secure-bank-update.com/login.php
```

## Modular Service Wrapper Usage

```python
from wrappers.virustotal_wrapper import VirusTotalWrapper
from wrappers.hybrid_analysis_wrapper import HybridAnalysisWrapper
from wrappers.abuseipdb_wrapper import AbuseIPDBWrapper
from wrappers.greynoise_wrapper import GreyNoiseWrapper
from wrappers.shodan_wrapper import ShodanWrapper
from wrappers.censys_wrapper import CensysWrapper
from wrappers.otx_wrapper import AlienVaultOTXWrapper
from wrappers.misp_wrapper import MISPWrapper

# VirusTotal & Hybrid Analysis (Hashes, URLs, Domains, IPs)
print(VirusTotalWrapper().hash_report("44d88612fea8a8f36de82e1278abb02f"))
print(HybridAnalysisWrapper().hash_search("44d88612fea8a8f36de82e1278abb02f"))

# AbuseIPDB & GreyNoise (IP reputation & Internet noise context)
print(AbuseIPDBWrapper().check_ip("198.51.100.45"))
print(GreyNoiseWrapper().ip_context("198.51.100.45"))

# Shodan & Censys (Infrastructure, ports & SSL certificates)
print(ShodanWrapper().host("198.51.100.45"))
print(CensysWrapper().view_host("198.51.100.45"))

# AlienVault OTX & MISP (Threat exchange pulses & community events)
print(AlienVaultOTXWrapper().get_indicator_details("IPv4", "198.51.100.45"))
print(MISPWrapper().search_attributes("198.51.100.45"))
```
