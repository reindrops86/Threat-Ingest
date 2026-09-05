from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd
import streamlit as st


def load_report(path: str) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def status_color(status: str) -> str:
    return {"healthy": "green", "degraded": "orange", "critical": "red"}.get(status, "gray")


def render_attack_path(report: dict) -> None:
    st.subheader("Cloud Attack Path")
    attack_path = report.get("cloud_attack_path", {})
    nodes = attack_path.get("nodes", [])
    edges = attack_path.get("edges", [])
    if not nodes:
        st.info("This report does not contain a cloud attack path.")
        return

    labels = {node["id"]: node["label"] for node in nodes}
    lines = ["```mermaid", "graph TD"]
    for edge in edges:
        source, target = edge["from"], edge["to"]
        lines.append(
            f'    {source}["{labels.get(source, source)}"] -->|{edge["relationship"]}| {target}["{labels.get(target, target)}"]'
        )
    lines.append("```")
    st.markdown("\n".join(lines))
    st.dataframe(
        pd.DataFrame([{**node, "evidence": ", ".join(node.get("evidence", []))} for node in nodes]),
        use_container_width=True,
        hide_index=True,
    )


def render_clusters(report: dict) -> None:
    st.subheader("Infrastructure Clustering")
    clusters = report.get("infrastructure_clusters", [])
    if not clusters:
        st.info("This report does not contain infrastructure clusters.")
        return
    for cluster in clusters:
        with st.container(border=True):
            st.markdown(f"**{cluster['cluster_id']}** · {cluster['assessment']}")
            confidence = int(cluster.get("confidence", 0))
            st.progress(min(100, confidence) / 100, text=f"Clustering confidence {confidence}%")
            st.caption("Pivots: " + ", ".join(cluster.get("pivots", [])))
            st.dataframe(pd.DataFrame(cluster.get("indicators", [])), use_container_width=True, hide_index=True)
    st.caption("Clustering supports a campaign hypothesis. It is not attribution on its own.")


def render_decisions(report: dict, report_path: str) -> None:
    st.subheader("Analyst Decision Workflow")
    decisions = report.get("analyst_decisions", [])

    with st.form("analyst_decision"):
        action = st.selectbox(
            "Action",
            [
                "Assign case",
                "Escalate case",
                "Revoke IAM role",
                "Isolate workload",
                "Block indicator",
                "Request enrichment",
                "Close case",
            ],
        )
        analyst = st.text_input("Analyst", value="analyst")
        confidence = st.select_slider("Confidence", options=["low", "medium", "high"], value="medium")
        rationale = st.text_area("Rationale", placeholder="State the evidence and what remains unknown.")
        submitted = st.form_submit_button("Record decision", type="primary")

    if submitted:
        if not rationale.strip():
            st.warning("Add a rationale so the decision remains auditable.")
        else:
            decisions.append(
                {
                    "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
                    "analyst": analyst.strip() or "analyst",
                    "action": action,
                    "confidence": confidence,
                    "rationale": rationale.strip(),
                }
            )
            report["analyst_decisions"] = decisions
            Path(report_path).write_text(json.dumps(report, indent=2), encoding="utf-8")
            st.success(f"Recorded: {action}")

    if decisions:
        st.dataframe(pd.DataFrame(decisions), use_container_width=True, hide_index=True)
    else:
        st.info("No analyst decisions have been recorded for this case.")


def main() -> None:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--report", default=str(Path("data") / "pipeline_health_report.json"))
    args, _ = parser.parse_known_args()

    st.set_page_config(page_title="CTI Pipeline Health", layout="wide")
    st.title("Autonomous CTI Pipeline Health")
    st.caption("Simulation telemetry for ingestion, enrichment, connector validation, and STIX/TAXII delivery")
    report_path = st.sidebar.text_input("Pipeline health report", value=args.report)
    try:
        report = load_report(report_path)
    except (OSError, json.JSONDecodeError) as error:
        st.error(f"Unable to load simulation report: {error}")
        st.stop()

    health = report.get("pipeline_health", 0)
    status = report.get("pipeline_status", "unknown")
    first, second, third = st.columns(3)
    first.metric("Pipeline health", f"{health}/100")
    second.metric("Pipeline status", status.title())
    third.metric("STIX objects delivered", report.get("metrics", {}).get("transported", 0))

    st.subheader("Stage Health")
    stages = pd.DataFrame(
        [{"stage": name.title(), **details} for name, details in report.get("stages", {}).items()]
    )
    if not stages.empty:
        st.bar_chart(stages.set_index("stage")["health"])
        st.dataframe(stages, use_container_width=True, hide_index=True)

    st.subheader("Pipeline Events")
    events = pd.DataFrame(report.get("events", []))
    if events.empty:
        st.info("No pipeline events are present in this report.")
    else:
        selected_statuses = st.multiselect("Event status", sorted(events["status"].unique()), default=sorted(events["status"].unique()))
        st.dataframe(events[events["status"].isin(selected_statuses)], use_container_width=True, hide_index=True)

    st.subheader("Agent Trace")
    trace = pd.DataFrame(report.get("agent_trace", []))
    st.dataframe(trace, use_container_width=True, hide_index=True)

    render_attack_path(report)
    render_clusters(report)
    render_decisions(report, report_path)

    st.subheader("Simulated TAXII Delivery")
    delivered = report.get("transported_stix_objects", [])
    if delivered:
        st.json(delivered)
    else:
        st.warning("No STIX objects reached the simulated TAXII collection.")


if __name__ == "__main__":
    main()