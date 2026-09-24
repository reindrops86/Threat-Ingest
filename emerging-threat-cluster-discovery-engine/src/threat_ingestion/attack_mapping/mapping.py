from __future__ import annotations

from threat_ingestion.domain.models import AttackTechnique

# Curated subset of well-documented MITRE ATT&CK Enterprise techniques for malware
# families commonly observed in ThreatFox/MalwareBazaar tags. This intentionally
# trades completeness for zero external dependencies; replace with a full
# mitre/cti STIX bundle ingestion if exhaustive coverage is needed.
_FAMILY_TECHNIQUES: dict[str, list[tuple[str, str, str]]] = {
    "emotet": [
        ("T1566.001", "Phishing: Spearphishing Attachment", "Initial Access"),
        ("T1059.005", "Command and Scripting Interpreter: Visual Basic", "Execution"),
        ("T1547.001", "Boot or Logon Autostart Execution: Registry Run Keys", "Persistence"),
    ],
    "trickbot": [
        ("T1055", "Process Injection", "Defense Evasion"),
        ("T1082", "System Information Discovery", "Discovery"),
        ("T1071.001", "Application Layer Protocol: Web Protocols", "Command and Control"),
    ],
    "qakbot": [
        ("T1566.001", "Phishing: Spearphishing Attachment", "Initial Access"),
        ("T1218.011", "System Binary Proxy Execution: Rundll32", "Defense Evasion"),
        ("T1071.001", "Application Layer Protocol: Web Protocols", "Command and Control"),
    ],
    "qbot": [
        ("T1566.001", "Phishing: Spearphishing Attachment", "Initial Access"),
        ("T1218.011", "System Binary Proxy Execution: Rundll32", "Defense Evasion"),
    ],
    "icedid": [
        ("T1027", "Obfuscated Files or Information", "Defense Evasion"),
        ("T1055", "Process Injection", "Defense Evasion"),
        ("T1071.001", "Application Layer Protocol: Web Protocols", "Command and Control"),
    ],
    "mirai": [
        ("T1078", "Valid Accounts", "Initial Access"),
        ("T1499", "Endpoint Denial of Service", "Impact"),
        ("T1071.001", "Application Layer Protocol: Web Protocols", "Command and Control"),
    ],
    "amos": [
        ("T1555", "Credentials from Password Stores", "Credential Access"),
        ("T1539", "Steal Web Session Cookie", "Credential Access"),
        ("T1005", "Data from Local System", "Collection"),
    ],
    "cobaltstrike": [
        ("T1071.001", "Application Layer Protocol: Web Protocols", "Command and Control"),
        ("T1055", "Process Injection", "Defense Evasion"),
        ("T1219", "Remote Access Software", "Command and Control"),
    ],
    "cobalt strike": [
        ("T1071.001", "Application Layer Protocol: Web Protocols", "Command and Control"),
        ("T1055", "Process Injection", "Defense Evasion"),
    ],
    "agenttesla": [
        ("T1056.001", "Input Capture: Keylogging", "Collection"),
        ("T1114", "Email Collection", "Collection"),
        ("T1041", "Exfiltration Over C2 Channel", "Exfiltration"),
    ],
    "redline": [
        ("T1555.003", "Credentials from Password Stores: Credentials from Web Browsers", "Credential Access"),
        ("T1082", "System Information Discovery", "Discovery"),
        ("T1041", "Exfiltration Over C2 Channel", "Exfiltration"),
    ],
    "redlinestealer": [
        ("T1555.003", "Credentials from Password Stores: Credentials from Web Browsers", "Credential Access"),
    ],
    "raccoon": [
        ("T1555.003", "Credentials from Password Stores: Credentials from Web Browsers", "Credential Access"),
        ("T1005", "Data from Local System", "Collection"),
    ],
    "formbook": [
        ("T1056.001", "Input Capture: Keylogging", "Collection"),
        ("T1055", "Process Injection", "Defense Evasion"),
    ],
    "amadey": [
        ("T1105", "Ingress Tool Transfer", "Command and Control"),
        ("T1082", "System Information Discovery", "Discovery"),
    ],
    "smokeloader": [
        ("T1027", "Obfuscated Files or Information", "Defense Evasion"),
        ("T1105", "Ingress Tool Transfer", "Command and Control"),
    ],
    "gootloader": [
        ("T1189", "Drive-by Compromise", "Initial Access"),
        ("T1059.007", "Command and Scripting Interpreter: JavaScript", "Execution"),
    ],
    "bumblebee": [
        ("T1204.002", "User Execution: Malicious File", "Execution"),
        ("T1055", "Process Injection", "Defense Evasion"),
    ],
    "lockbit": [
        ("T1486", "Data Encrypted for Impact", "Impact"),
        ("T1490", "Inhibit System Recovery", "Impact"),
        ("T1021.002", "Remote Services: SMB/Windows Admin Shares", "Lateral Movement"),
    ],
    "conti": [
        ("T1486", "Data Encrypted for Impact", "Impact"),
        ("T1490", "Inhibit System Recovery", "Impact"),
    ],
    "ryuk": [
        ("T1486", "Data Encrypted for Impact", "Impact"),
        ("T1489", "Service Stop", "Impact"),
    ],
    "akira": [
        ("T1486", "Data Encrypted for Impact", "Impact"),
        ("T1567.002", "Exfiltration to Cloud Storage", "Exfiltration"),
    ],
    "blackbasta": [
        ("T1486", "Data Encrypted for Impact", "Impact"),
        ("T1490", "Inhibit System Recovery", "Impact"),
    ],
    "njrat": [
        ("T1219", "Remote Access Software", "Command and Control"),
        ("T1056.001", "Input Capture: Keylogging", "Collection"),
    ],
    "remcos": [
        ("T1219", "Remote Access Software", "Command and Control"),
        ("T1056.001", "Input Capture: Keylogging", "Collection"),
    ],
    "azorult": [
        ("T1555.003", "Credentials from Password Stores: Credentials from Web Browsers", "Credential Access"),
        ("T1041", "Exfiltration Over C2 Channel", "Exfiltration"),
    ],
    "lumma": [
        ("T1555.003", "Credentials from Password Stores: Credentials from Web Browsers", "Credential Access"),
        ("T1082", "System Information Discovery", "Discovery"),
    ],
    "vidar": [
        ("T1555.003", "Credentials from Password Stores: Credentials from Web Browsers", "Credential Access"),
        ("T1005", "Data from Local System", "Collection"),
    ],
    "dridex": [
        ("T1204.002", "User Execution: Malicious File", "Execution"),
        ("T1055", "Process Injection", "Defense Evasion"),
    ],
}


def techniques_for_family(malware_family: str) -> list[AttackTechnique]:
    """Looks up curated ATT&CK techniques for a malware family name. Matching is
    case-insensitive and ignores spaces/hyphens/underscores so tag variants like
    'Cobalt-Strike', 'cobalt_strike', and 'CobaltStrike' all resolve. Also strips
    the platform prefix ThreatFox/MalwareBazaar attach to family tags (e.g.
    'win.cobalt_strike', 'elf.mirai', 'osx.amos') before matching."""
    candidates = {malware_family.lower()}
    if "." in malware_family:
        candidates.add(malware_family.split(".", 1)[1].lower())
    normalized_candidates = {"".join(ch for ch in candidate if ch.isalnum()) for candidate in candidates}

    for family, techniques in _FAMILY_TECHNIQUES.items():
        normalized_family = "".join(ch for ch in family if ch.isalnum())
        if normalized_family in normalized_candidates:
            return [AttackTechnique(technique_id=tid, name=name, tactic=tactic) for tid, name, tactic in techniques]
    return []
