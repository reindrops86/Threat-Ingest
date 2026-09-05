from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List

import pandas as pd
import streamlit as st

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.actors.actor_profiles import ActorProfileStore
from app.enrichment.enrichment import EnrichmentEngine
from app.attack.attack_mapper import AttackMapper

WIZ_SCENARIO = [
    {
        "stage": "01 / Scope",
        "title": "A workload identity is making unusual API calls",
        "brief": "A production container assumes a role it normally uses for object storage. The same role now enumerates IAM and launches short-lived compute in a new region.",
        "question": "What is your first CTI move?",
        "options": [
            "Attribute the activity to a named threat actor from the cloud region.",
            "Build a timeline from CloudTrail, identity context, workload metadata, and related resources before naming the actor.",
            "Block every workload using the cloud provider immediately.",
            "Search only for a matching malware hash.",
        ],
        "answer": 1,
        "why": "Start with an evidence-preserving timeline. Identity, token use, API sequence, and resource creation are stronger than geography or a hash alone.",
    },
    {
        "stage": "02 / Hypothesis",
        "title": "The access pattern points to credential theft",
        "brief": "The role session begins after a dependency update. The container image digest is new, and the CI runner that built it had permission to publish images and read deployment secrets.",
        "question": "Which hypothesis is most useful to test next?",
        "options": [
            "A compromised build or dependency path may have exposed deployment credentials and enabled cloud discovery.",
            "The region is known for crime, so the actor is probably local.",
            "The new image proves the vendor is malicious.",
            "No hypothesis is needed until attribution is certain.",
        ],
        "answer": 0,
        "why": "The temporal link between the dependency change, image digest, CI permissions, and role session creates a testable supply-chain hypothesis without overclaiming attribution.",
    },
    {
        "stage": "03 / Cluster",
        "title": "Ephemeral infrastructure appears across tenants",
        "brief": "Three unrelated tenants report identical user-agent strings, TLS certificate reuse, and a wallet address in compute billing anomalies. Domains rotate every few hours.",
        "question": "Which pivot best tests infrastructure clustering?",
        "options": [
            "Group only on domain names because they are the easiest indicator.",
            "Pivot across certificate fingerprints, registration patterns, API behavior, wallet reuse, and timing while recording confidence.",
            "Treat every tenant as a separate incident and discard shared context.",
            "Publish the wallet address as definitive attribution.",
        ],
        "answer": 1,
        "why": "Resilient clustering uses multiple independent pivots. Rotating domains are weak alone; repeated behavior and infrastructure relationships provide stronger analytic value.",
    },
    {
        "stage": "04 / Decision",
        "title": "Turn analysis into customer protection",
        "brief": "Engineering asks for a concise action brief. You have high confidence in the abused role and medium confidence in the compromised dependency, but actor attribution remains low confidence.",
        "question": "What should the brief emphasize?",
        "options": [
            "A confident actor label and a long list of speculative campaign links.",
            "The evidence-backed behavior, affected identities and workloads, immediate containment, detection opportunities, and explicit confidence gaps.",
            "Only the raw logs so the customer can interpret them themselves.",
            "Wait for attribution before sharing any defensive action.",
        ],
        "answer": 1,
        "why": "CTI is useful when it changes decisions. Separate facts from hypotheses, state confidence, and give defenders actions they can take now.",
    },
]


def render_wiz_lab() -> None:
    st.markdown("## Wiz CTI Interview Lab")
    st.caption("Practice the analyst loop: scope the evidence, test a hypothesis, cluster infrastructure, and drive a decision.")
    pillars = [
        ("Cloud TTPs", "IAM role abuse, IMDS, and container escape", "#0f766e"),
        ("Research mindset", "Trust boundaries, blast radius, and mitigations", "#c2410c"),
        ("Infrastructure tracking", "C2 nodes, miners, certificates, and reuse", "#1d4ed8"),
    ]
    for column, (label, summary, accent) in zip(st.columns(3), pillars):
        with column:
            st.markdown(
                f"<div style='border-top: 4px solid {accent}; padding: 0.8rem 0.2rem;'>"
                f"<div style='color: {accent}; font-weight: 700; text-transform: uppercase;'>{label}</div>"
                f"<div style='font-weight: 700; margin-top: 0.35rem;'>{summary}</div></div>",
                unsafe_allow_html=True,
            )
    st.divider()
    st.markdown("### Scenario: the poisoned build path")
    st.write("A dependency update is followed by cloud discovery, an unusual role session, and compute resource creation. Work the case in four decisions.")
    if "wiz_answers" not in st.session_state:
        st.session_state.wiz_answers = {}
    if "wiz_submitted" not in st.session_state:
        st.session_state.wiz_submitted = False
    for index, scenario in enumerate(WIZ_SCENARIO):
        with st.container(border=True):
            st.markdown(f"**{scenario['stage']}  ·  {scenario['title']}**")
            st.write(scenario["brief"])
            answer = st.radio(scenario["question"], scenario["options"], index=None, key=f"wiz_answer_{index}")
            if answer is not None:
                st.session_state.wiz_answers[index] = scenario["options"].index(answer)
    if st.button("Score my analysis", type="primary"):
        st.session_state.wiz_submitted = True
    if st.session_state.wiz_submitted:
        correct = sum(st.session_state.wiz_answers.get(index) == scenario["answer"] for index, scenario in enumerate(WIZ_SCENARIO))
        st.metric("Scenario score", f"{correct} / {len(WIZ_SCENARIO)}")
        for index, scenario in enumerate(WIZ_SCENARIO):
            if st.session_state.wiz_answers.get(index) == scenario["answer"]:
                st.success(f"{scenario['stage']}: Correct. {scenario['why']}")
            else:
                st.error(f"{scenario['stage']}: Best answer: {scenario['options'][scenario['answer']]} {scenario['why']}")
    st.divider()
    st.markdown("### High-probability interview prompts")
    prompts = [
        ("How would you investigate cloud credential theft?", "Start with identity and control-plane telemetry, reconstruct token and role use, inspect workload and CI/CD provenance, then scope affected resources and durable access."),
        ("How do you track an adversary's cloud infrastructure?", "Combine passive DNS, certificates, registration data, hosting changes, protocol fingerprints, and temporal relationships. Preserve confidence and provenance for every pivot."),
        ("How would you evaluate a cloud vulnerability before disclosure?", "Characterize the trust boundary, prerequisites, blast radius, exploitability, affected versions, telemetry, and mitigations. Reproduce only in an authorized environment."),
        ("What makes CTI actionable for a CNAPP team?", "Map behavior to identities, workloads, permissions, and cloud resources, then provide detections, prioritization context, and a concrete containment or hardening decision."),
    ]
    for prompt, answer in prompts:
        with st.expander(prompt):
            st.write(answer)
    st.caption("Interview habit: state what you know, what you infer, what would change your mind, and what the defender should do next.")


def load_signals(path: str) -> List[Dict[str, Any]]:
    signal_path = Path(path)
    if not signal_path.exists():
        return []
    return json.loads(signal_path.read_text(encoding="utf-8"))


def build_enriched_signals(signals: List[Dict[str, Any]]) -> pd.DataFrame:
    rows = []
    for signal in signals:
        rows.append(
            {
                "entity": signal.get("entity"),
                "signal_type": signal.get("signal_type"),
                "source": signal.get("source"),
                "confidence": signal.get("confidence"),
                "severity": signal.get("severity"),
                "tags": ", ".join(signal.get("tags", [])),
            }
        )
    return pd.DataFrame(rows)


def severity_badge(severity: str) -> str:
    mapping = {"high": "🔴 High", "medium": "🟠 Medium", "low": "🟢 Low"}
    return mapping.get(severity.lower(), severity.title())


def main() -> None:
    parser = argparse.ArgumentParser(description="CTI Dashboard")
    parser.add_argument("--signals", default=str(Path("data") / "sample_signals.json"), help="Path to OSINT signals JSON")
    args = parser.parse_args()

    st.set_page_config(page_title="CTI Dashboard", layout="wide")
    st.title("Cyber Threat Intelligence Dashboard")
    st.caption("IOC lookup, actor profiles, OSINT signal viewing, enrichment, and ATT&CK mapping")

    view = st.sidebar.radio("Workspace", ["Signal dashboard", "Wiz CTI interview lab"])
    if view == "Wiz CTI interview lab":
        render_wiz_lab()
        return

    signals = load_signals(args.signals)
    if not signals:
        st.warning("No signal file found. Point the dashboard at a valid signals JSON file.")
        st.stop()

    enrichment = EnrichmentEngine()
    actor_store = ActorProfileStore()
    attack_mapper = AttackMapper()

    signals_df = build_enriched_signals(signals)
    enriched = enrichment.enrich(signals)

    st.sidebar.header("Controls")
    selected_actor = st.sidebar.selectbox("Actor profile", [a["name"] for a in actor_store.list_profiles()])
    lookup_indicator = st.sidebar.text_input("IOC lookup", value="mail-verify[.]com")
    severity_filter = st.sidebar.multiselect("Severity", ["high", "medium", "low"], default=["high", "medium", "low"])
    signal_type_filter = st.sidebar.multiselect(
        "Signal type",
        sorted(signals_df["signal_type"].dropna().unique().tolist()),
        default=sorted(signals_df["signal_type"].dropna().unique().tolist()),
    )

    filtered_df = signals_df[
        signals_df["severity"].isin(severity_filter) & signals_df["signal_type"].isin(signal_type_filter)
    ]

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Signals", len(filtered_df))
    col2.metric("Enrichment matches", enriched["matched_count"])
    col3.metric("IOC index size", len(enriched["lookup_index"]))
    col4.metric("High severity", int((signals_df["severity"] == "high").sum()))

    st.subheader("OSINT Signal Viewer")
    display_df = filtered_df.copy()
    display_df["severity"] = display_df["severity"].fillna("unknown").map(severity_badge)
    st.dataframe(display_df, use_container_width=True)

    st.subheader("Signal Severity Breakdown")
    severity_counts = Counter(signals_df["severity"].fillna("unknown"))
    severity_df = pd.DataFrame(
        [{"severity": severity_badge(k), "count": v} for k, v in severity_counts.items()]
    ).sort_values("count", ascending=False)
    st.bar_chart(severity_df.set_index("severity"))

    st.subheader("Enrichment Results")
    st.json(enriched)

    st.subheader("IOC Lookup")
    lookup_result = enrichment.lookup(lookup_indicator)
    if lookup_result:
        st.success(f"Matched IOC: {lookup_result['indicator']}")
        st.json(lookup_result)
    else:
        st.info("No match found")

    st.subheader("Actor Profiles")
    profiles = actor_store.list_profiles()
    selected_profile = next(p for p in profiles if p["name"] == selected_actor)
    st.json(selected_profile)

    st.subheader("ATT&CK Mapping")
    mapped = attack_mapper.map_ttps(selected_profile["ttps"])
    if mapped:
        st.table(pd.DataFrame(mapped))
    else:
        st.write("No mapped techniques for the selected profile.")

    st.subheader("IOC Enrichment Index")
    st.dataframe(pd.DataFrame(enrichment.iocs), use_container_width=True)


if __name__ == "__main__":
    main()
