# Detection Engineering Lab

A compact repo showing SOC + TI hybrid skills with example detections, parsing, and triage workflow.

## Included

- Sigma rules
- YARA rules
- Log parsing examples
- Detection logic for common TTPs
- A notebook showing detection → enrichment → triage

## Structure

- `rules/` — example detection rules
- `logs/` — synthetic log samples
- `src/` — parsing and detection logic
- `notebooks/` — workflow walkthrough

## Included detections

### 1. Suspicious PowerShell Loader
- Sigma: `rules/sigma_powershell_loader.yml`
- YARA: `rules/yara_powershell_loader.yar`
- Detects encoded PowerShell, IEX, downloadstring, and base64 loader patterns

### 2. Potential Credential Dumping
- Sigma: `rules/sigma_credential_dumping.yml`
- YARA: `rules/yara_credential_access.yar`
- Detects LSASS/SAM access patterns tied to credential theft

### 3. Persistence via Scheduled Task
- Implemented in `src/detector.py`
- Detects `schtasks /create` persistence behavior

## Rule matrix

| Detection | Technique | Evidence | Output |
|---|---|---|---|
| Suspicious PowerShell Loader | Execution | Encoded command lines, downloader strings | High-confidence triage hit |
| Potential Credential Dumping | Credential Access | LSASS / SAM access patterns | Medium-to-high severity signal |
| Persistence via Scheduled Task | Persistence | `schtasks /create` | Persistence alert |

## Workflow

1. Parse logs
2. Run detection logic
3. Enrich detections with risk and confidence
4. Generate triage summary

## Sample report excerpt

The workflow can generate both JSON and Markdown triage summaries.

Example summary:

- Total detections: 3
- Suspicious PowerShell Loader: 1
- Potential Credential Dumping: 1
- Persistence via Scheduled Task: 1
- Highest confidence hit: Suspicious PowerShell Loader
- Risk: high
- Confidence: 0.84

## Review guide

If you are reviewing this repo, start here:

1. `README.md` — project overview
2. `rules/` — detection content
3. `logs/sample_security.log` — synthetic telemetry
4. `src/log_parser.py` — log normalization
5. `src/detector.py` — detection logic
6. `src/enricher.py` — enrichment
7. `src/triage.py` — report generation
8. `notebooks/detection_workflow.ipynb` — full walkthrough

## Suggested screenshots

Add screenshots here when publishing the repo:

- notebook overview
- triage summary output
- generated markdown report
- rule examples side by side

## Why this matters

This project demonstrates operational detection thinking: translating adversary behavior into detectable telemetry and then turning hits into enriched triage output.
