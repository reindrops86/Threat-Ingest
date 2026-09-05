from __future__ import annotations

import sys
from pathlib import Path

import pandas as pd
import streamlit as st

PACKAGE_ROOT = Path(__file__).resolve().parent
if str(PACKAGE_ROOT) not in sys.path:
    sys.path.insert(0, str(PACKAGE_ROOT))

from risk_graph import RISKS, build_environment, default_enabled_risks, summarize

SEVERITY_COLOR = {"critical": "#b91c1c", "high": "#c2410c", "medium": "#b45309", "low": "#0f766e"}


def render_graph(environment: dict, enabled: set[str], critical_path: list[str] | None) -> None:
    labels = {node["id"]: node["label"] for node in environment["nodes"]}
    on_path = set(critical_path or [])
    lines = ["```mermaid", "graph LR"]

    for edge in environment["edges"]:
        live = all(risk in enabled for risk in edge["requires"])
        arrow = "-->" if live else "-.->"
        lines.append(
            f'    {edge["from"]}["{labels[edge["from"]]}"] {arrow}|{edge["relationship"]}| {edge["to"]}["{labels[edge["to"]]}"]'
        )

    for node in environment["nodes"]:
        active = [risk for risk in node["risks"] if risk in enabled]
        if node["id"] in on_path:
            lines.append(f'    style {node["id"]} fill:#fee2e2,stroke:#b91c1c,stroke-width:3px')
        elif active:
            lines.append(f'    style {node["id"]} fill:#fef3c7,stroke:#c2410c,stroke-width:2px')
        elif node.get("crown_jewel"):
            lines.append(f'    style {node["id"]} fill:#dbeafe,stroke:#1d4ed8,stroke-width:2px')

    lines.append("```")
    st.markdown("\n".join(lines))
    st.caption("Solid edges are live attack routes. Dashed edges are blocked because the required risk is remediated.")


def main() -> None:
    st.set_page_config(page_title="Cloud & AI Security Risk Graph", layout="wide")
    st.title("Cloud & AI Security Risk Graph")
    st.caption("Toxic combinations, attack paths, and remediation priority across cloud and AI workloads")

    environment = build_environment()

    st.sidebar.header("Environment risks")
    st.sidebar.caption("Toggle a risk to see how the attack graph changes.")
    defaults = set(default_enabled_risks())
    enabled: set[str] = set()
    for risk_id, risk in RISKS.items():
        if st.sidebar.checkbox(risk["label"], value=risk_id in defaults, help=risk["detail"]):
            enabled.add(risk_id)

    result = summarize(environment, enabled)
    paths = result["attack_paths"]
    toxic = result["toxic_combinations"]
    critical_path = paths[0]["sequence"] if paths else None

    first, second, third, fourth = st.columns(4)
    first.metric("Attack paths to crown jewels", len(paths))
    second.metric("Toxic combinations", len(toxic))
    third.metric("AI-impacting paths", len(result["ai_paths"]))
    fourth.metric("Active risks", len(enabled))

    if not paths:
        st.success("No attack path reaches a crown-jewel asset with the current configuration.")
    else:
        top = paths[0]
        st.markdown(
            f"<div style='border-left: 6px solid {SEVERITY_COLOR[top['severity']]}; padding: 0.6rem 1rem; background: #f8fafc;'>"
            f"<strong>Critical path ({top['severity'].title()}, {top['severity_score']}/100)</strong><br>"
            f"{' &rarr; '.join(top['labels'])}</div>",
            unsafe_allow_html=True,
        )

    render_graph(environment, enabled, critical_path)

    st.subheader("Toxic Combinations")
    if not toxic:
        st.info("No path currently combines three or more risk categories.")
    for path in toxic:
        with st.container(border=True):
            st.markdown(f"**{path['target']}** · {path['severity'].title()} · {path['severity_score']}/100")
            st.write(" → ".join(path["labels"]))
            st.caption("Categories: " + ", ".join(path["categories"]))
            st.caption("Risks: " + ", ".join(RISKS[risk]["label"] for risk in path["risks"]))

    st.subheader("Remediation Priority")
    st.caption("Ranked by how many toxic paths each single fix eliminates, not by raw alert count.")
    remediations = result["remediations"]
    if remediations:
        st.dataframe(
            pd.DataFrame(remediations)[["label", "category", "toxic_paths_removed", "paths_removed", "detail"]],
            use_container_width=True,
            hide_index=True,
        )
        best = remediations[0]
        if best["toxic_paths_removed"] > 0:
            st.success(f"Highest-leverage fix: {best['label']} removes {best['toxic_paths_removed']} toxic combination(s).")
    else:
        st.info("No active risks to remediate.")

    st.subheader("All Attack Paths")
    if paths:
        st.dataframe(
            pd.DataFrame(
                [
                    {
                        "target": path["target"],
                        "severity": path["severity"],
                        "score": path["severity_score"],
                        "ai_impact": path["ai_impact"],
                        "hops": len(path["sequence"]) - 1,
                        "path": " → ".join(path["labels"]),
                    }
                    for path in paths
                ]
            ),
            use_container_width=True,
            hide_index=True,
        )


if __name__ == "__main__":
    main()
