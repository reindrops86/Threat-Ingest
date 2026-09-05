# OSINT & CTI Service Ecosystem Notes

## Service Mapping & Primary Use Cases

| Service Category | Primary Services | Key Analyst Value |
|---|---|---|
| **Hash & URL Reputation** | **VirusTotal**, **Hybrid Analysis** | Detection ratio across 70+ AV engines, sandbox behavior execution reports, payload family identification. |
| **IP Scoring & Noise Filtering** | **AbuseIPDB**, **GreyNoise** | Distinguishing targeted infrastructure attack traffic vs internet-wide background scanning noise (scanning bots). |
| **Infrastructure Discovery** | **Shodan**, **Censys** | Uncovering open ports, banners, TLS/SSL certificate fingerprints, and adversary hosting infrastructure networks. |
| **Threat Exchange & Sharing** | **AlienVault OTX**, **MISP** | Community threat pulses, campaign correlation, structured STIX/MISP attribute matching. |

## Analyst Workflow

1. **Normalize**: Extract and defang raw indicators (IPs, MD5/SHA256, URLs, Domains).
2. **Filter Background Noise**: Run GreyNoise to verify whether an IP is just background scanner noise.
3. **Reputation Lookup**: Query AbuseIPDB, VirusTotal, and Hybrid Analysis for malice scores and malware families.
4. **Pivot Infrastructure**: Query Shodan and Censys for shared SSL certificates or co-hosted infrastructure.
5. **Correlate Community Intel**: Query AlienVault OTX and MISP for associated campaign threat pulses.
6. **Produce Output**: Synthesize findings into actionable triage or threat intelligence reports.

## Notes

Good CTI work is not just about having tools. It is about knowing which source answers which question, and when the confidence is too low to act on it.
