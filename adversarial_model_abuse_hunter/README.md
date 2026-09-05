# Adversarial Model Abuse Hunter

A compact SOC analyst workflow for triaging adversarial model abuse, phishing lures, credential theft attempts, malware indicators, and prompt override behavior.

## What the prototype does

- extracts indicators from raw incident text
- categorizes abuse behavior such as phishing, jailbreaks, credential theft, and malware
- enriches known indicators with local threat intelligence
- scores the incident for risk and severity
- stores and correlates related cases in a local archive
- exposes the workflow through a Streamlit analyst console

## Project structure

- `hunter.py` — triage engine, intelligence, case archive, and scoring logic
- `app.py` — Streamlit SOC dashboard
- `sample_cases.json` — archived investigation records
- `run_app.ps1` / `run_app.bat` — local launchers
- `demo_soc_workflow.py` — quick end-to-end demo of the analyst workflow

## Verified app launch

From a PowerShell session, this is the validated command:

```powershell
py -m streamlit run "C:\Users\downi\OneDrive\Documents\08metricsdemos_1786575674023\08_metrics_demos\artifacts\adversarial_model_abuse_hunter\app.py" --server.headless true --server.port 8503 --server.address 127.0.0.1
```

Open the dashboard here:

```text
http://127.0.0.1:8503
```

## Quick analyst demo

```powershell
cd "C:\Users\downi\OneDrive\Documents\08metricsdemos_1786575674023\08_metrics_demos\artifacts\adversarial_model_abuse_hunter"
py demo_soc_workflow.py
```

This script runs a short sample workflow and prints:

- case ID
- priority
- current status
- risk score and severity
- indicator count
- related cases

## Typical workflow

1. Analyst pastes a suspicious model interaction or phishing report.
2. The engine extracts domains, URLs, IPs, emails, and hashes.
3. Threat intel checks local reputation data for malicious infrastructure.
4. The classifier identifies attack patterns such as phishing, malware, or prompt override.
5. The case is scored, assigned a priority, stored in the archive, and compared against related incidents.
6. The analyst can update the status in the dashboard or through the archive API.

## Notes

- The prototype is intentionally offline and local-only.
- It does not require external APIs or secrets to run.
- If you are launching from a different working directory, always point Streamlit directly at the full path of `app.py` to avoid the common `File does not exist: app.py` issue.
