from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pandas as pd
import streamlit as st


ROOT = Path(r"C:\Users\downi\OneDrive\Documents")
MODULE_PATH = ROOT / "CTIcode.py"
HISTORY_PATH = Path(__file__).resolve().parent / "cti_memory.json"


def priority_color(priority: str) -> str:
    palette = {"P1": "#ff4b4b", "P2": "#ffb703", "P3": "#2ec4b6"}
    return palette.get(priority, "#6c757d")


@st.cache_resource
def load_cti_module():
    spec = importlib.util.spec_from_file_location("cti_code_module", MODULE_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Could not load module from {MODULE_PATH}")

    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@st.cache_data
def load_history(path: str = str(HISTORY_PATH)):
    history_path = Path(path)
    if not history_path.exists():
        return []

    try:
        with history_path.open("r", encoding="utf-8") as fh:
            payload = json.load(fh)
    except Exception:
        return []

    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict):
        cases = payload.get("cases")
        return cases if isinstance(cases, list) else []
    return []


@st.cache_data
def analyze_text(text: str, assignee: str | None = None, notes: list[str] | None = None):
    module = load_cti_module()
    researcher = module.AgenticCTIResearcher()
    result = researcher.analyze(text, assignee=assignee, notes=notes or [])
    return result


SAMPLE_TEXTS = {
    "Credential phishing": (
        "Threat Notice: A payroll phishing email was sent to staff from helpdesk@secure-payroll.co. "
        "The lure directs users to https://payroll-login-secure.co/portal. Suspicious IP: 185.220.101.42. "
        "Hash: 9f1c4a2e5b6d7a88d0e9f9b2c1d3a4f5"
    ),
    "Ransomware / loader": (
        "Analysts identified lockfiles-update.net in a ransomware intrusion. Endpoint telemetry shows "
        "encoded PowerShell execution and a suspicious hash 9f1c4a2e5b6d7a88d0e9f9b2c1d3a4f5. "
        "Communication to 185.220.101.42 and URLs from https://payroll-login-secure.co/portal indicate linkage."
    ),
    "General CTI note": (
        "A malicious campaign is targeting healthcare staff with a fake payroll portal. "
        "The email lure was sent from helpdesk@secure-payroll.co and uses the domain payroll-login-secure.co. "
        "The associated IP 185.220.101.42 was seen as a C2 endpoint."
    ),
}


st.set_page_config(page_title="CTI Researcher Dashboard", page_icon="🛡️", layout="wide")

st.title("🛡️ CTI Researcher Dashboard")
st.caption("AI-assisted cyber threat intelligence triage and analyst review")

with st.sidebar:
    st.header("Sample reports")
    for label, sample in SAMPLE_TEXTS.items():
        if st.button(label, use_container_width=True):
            st.session_state["input_text"] = sample

    st.markdown("---")
    st.subheader("Queue overview")
    history = load_history()
    if history:
        for case in history[:5]:
            title = case.get("title") or case.get("case_id") or "Historical Case"
            risk = case.get("severity") or "Unknown"
            priority = case.get("priority") or "P3"
            st.markdown(
                f"<span style='color:{priority_color(priority)}'>[{priority}]</span> {title} — {risk}",
                unsafe_allow_html=True,
            )
    else:
        st.write("No saved cases yet.")


text_input = st.text_area(
    "Threat report text",
    value=st.session_state.get("input_text", SAMPLE_TEXTS["Credential phishing"]),
    height=220,
)

assigner = st.selectbox("Assign analyst", ["unassigned", "Analyst A", "Analyst B", "Analyst C"])
case_note = st.text_input("Analyst note", value="")

if st.button("Analyze report", type="primary"):
    if text_input.strip():
        with st.spinner("Assessing indicators and risk..."):
            notes = [case_note] if case_note.strip() else []
            report = analyze_text(text_input, assignee=assigner, notes=notes)
        st.session_state["report"] = report


report = st.session_state.get("report")
if report:
    risk = report.get("risk", {})
    indicators = report.get("indicators", [])
    summary = report.get("summary", "")
    related_cases = report.get("related_cases", [])
    alerts = report.get("alerts", [])
    case_id = report.get("case_id", "N/A")
    priority = report.get("priority", "P3")
    status = report.get("status", "new")
    assignee = report.get("assignee", "unassigned")
    notes = report.get("notes", [])

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Risk score", f"{risk.get('score', 0)}/100")
    col2.metric("Severity", risk.get("severity", "Unknown"))
    col3.metric("Indicators", len(indicators))
    col4.metric("Priority", priority)

    st.subheader("Case triage")
    st.markdown(f"**Case ID:** {case_id}  |  **Status:** {status}  |  **Assignee:** {assignee}  |  **Priority:** <span style='color:{priority_color(priority)}'>[{priority}]</span>", unsafe_allow_html=True)

    status_options = ["new", "assigned", "in_progress", "escalated", "closed"]
    current_state = status if status in status_options else "new"
    selected_status = st.selectbox("Move case state", status_options, index=status_options.index(current_state))
    status_note = st.text_input("Status update note", value="")
    if st.button("Apply status update"):
        module = load_cti_module()
        manager = module.CaseTriageManager(HISTORY_PATH)
        updated = manager.transition_case(case_id, selected_status, analyst=assignee, note_text=status_note)
        if updated:
            report["status"] = updated.get("status", selected_status)
            report["assignee"] = updated.get("assignee", assignee)
            report["notes"] = updated.get("notes", report.get("notes", []))
            st.session_state["report"] = report
            st.rerun()

    if notes:
        st.subheader("Case notes")
        for entry in notes:
            analyst = entry.get("analyst", "analyst")
            text = entry.get("text", "")
            st.markdown(f"- **{analyst}**: {text}")

    st.subheader("Analyst summary")
    st.code(summary, language="text")

    tab1, tab2, tab3 = st.tabs(["Alerts", "Indicators", "Queue"])

    with tab1:
        if alerts:
            for alert in alerts:
                st.markdown(f"- **{alert.get('title')}** [{alert.get('severity', 'Unknown')}] — {alert.get('summary', '')}")
        else:
            st.info("No alerts were generated for this report.")

    with tab2:
        df = pd.DataFrame(indicators)
        if not df.empty:
            display_df = df[["type", "value", "confidence", "tags", "mitre"]].copy()
            display_df["tags"] = display_df["tags"].apply(lambda values: ", ".join(values) if isinstance(values, list) else values)
            display_df["mitre"] = display_df["mitre"].apply(lambda values: ", ".join(values) if isinstance(values, list) else values)
            st.dataframe(display_df, use_container_width=True)
        else:
            st.info("No indicators were detected.")

    with tab3:
        queue = report.get("case_queue", [])
        if queue:
            queue_df = pd.DataFrame(queue)
            display_queue = queue_df[["case_id", "title", "priority", "severity", "status", "risk_score"]].copy()
            st.dataframe(display_queue, use_container_width=True)
        else:
            st.info("Case queue is empty.")

    st.subheader("Related cases")
    if related_cases:
        st.json(related_cases)
    else:
        st.info("No related historical cases were identified.")

    st.subheader("Raw JSON")
    st.json(report)

else:
    st.info("Paste a threat report or click a sample to begin analysis.")
