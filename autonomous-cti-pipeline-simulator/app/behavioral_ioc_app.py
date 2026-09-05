from __future__ import annotations

import argparse
import sys
from pathlib import Path

import pandas as pd
import streamlit as st

PACKAGE_ROOT = Path(__file__).resolve().parent
if str(PACKAGE_ROOT) not in sys.path:
    sys.path.insert(0, str(PACKAGE_ROOT))

from behavioral_ioc import hunt, load_events

SEVERITY_COLOR = {"critical": "#b91c1c", "high": "#c2410c", "medium": "#b45309", "low": "#0f766e"}


def render_detections(detections: list[dict]) -> None:
    st.subheader("Behavioral Detections")
    if not detections:
        st.success("No behavioral signatures matched in this log set.")
        return

    for detection in detections:
        color = SEVERITY_COLOR.get(detection["severity"], "#475569")
        with st.container(border=True):
            st.markdown(
                f"<span style='color:{color}; font-weight:700; text-transform:uppercase;'>{detection['severity']}</span> "
                f"&nbsp;<strong>{detection['name']}</strong> &nbsp;<code>{detection['kind']}</code>",
                unsafe_allow_html=True,
            )
            st.write(" → ".join(detection["sequence"]))
            st.caption(detection["detail"])
            left, middle, right = st.columns(3)
            left.markdown(f"**Credential**  \n`{detection['access_key']}`")
            middle.markdown(f"**Source**  \n{detection['source_ip']} · {detection['country']} · {detection['asn']}")
            right.markdown(f"**Window**  \n{detection['span_minutes']} min across {len(detection['regions'])} region(s)")
            if detection["multi_region"]:
                st.warning("Repeated across multiple regions, which is consistent with scripted automation.")
            st.caption(f"Reference: {detection['reference']}")


def render_parameter_iocs(iocs: list[dict]) -> None:
    st.subheader("Parameter-Level Cloud IOCs")
    st.caption(
        "Attacker-controlled values logged in the API call. A value reused across separate credentials is a strong actor link."
    )
    if not iocs:
        st.info("No fingerprintable parameter values were observed.")
        return

    frame = pd.DataFrame(
        [
            {
                "api": ioc["api"],
                "parameter": ioc["parameter"],
                "value": ioc["value"],
                "confidence": ioc["confidence"],
                "cross_identity": ioc["cross_identity"],
                "identities": len(ioc["access_keys"]),
                "observations": ioc["observations"],
            }
            for ioc in iocs
        ]
    )
    st.dataframe(frame, use_container_width=True, hide_index=True)

    linked = [ioc for ioc in iocs if ioc["cross_identity"]]
    if linked:
        st.markdown("**Cross-victim links**")
        for ioc in linked:
            st.markdown(
                f"- `{ioc['parameter']}={ioc['value']}` observed under {len(ioc['access_keys'])} credentials: "
                f"{', '.join(ioc['access_keys'])}"
            )

    st.markdown("**Generated hunting queries**")
    st.code("\n".join(ioc["hunt_query"] for ioc in iocs), language="sql")


def render_clusters(clusters: list[dict]) -> None:
    st.subheader("Actor Clustering")
    st.caption("Activity grouped by source metadata and API call set, mirroring the honeypot pivot method.")
    frame = pd.DataFrame(
        [
            {
                "cluster": cluster["cluster_id"],
                "asn": cluster["asn"],
                "country": cluster["country"],
                "identities": cluster["identity_count"],
                "events": cluster["event_count"],
                "api_calls": ", ".join(cluster["api_calls"]),
            }
            for cluster in clusters
        ]
    )
    st.dataframe(frame, use_container_width=True, hide_index=True)
    multi = [cluster for cluster in clusters if cluster["identity_count"] > 1]
    if multi:
        st.info(
            f"{len(multi)} cluster(s) span more than one credential, suggesting a single operator abusing multiple leaked keys."
        )


def render_signals(signals: list[dict]) -> None:
    st.subheader("Contextual Signals")
    st.caption("Context that raises or lowers suspicion for otherwise ordinary API calls.")
    if not signals:
        st.info("No contextual anomalies were detected.")
        return
    for signal in signals:
        with st.container(border=True):
            st.markdown(f"`{signal['access_key']}` · {signal['source_ip']} · {signal['principal']}")
            for item in signal["signals"]:
                st.markdown(f"- {item}")


def main() -> None:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--events", default=str(Path("data") / "cloudtrail_activity.json"))
    args, _ = parser.parse_known_args()

    st.set_page_config(page_title="Behavioral Cloud IOC Hunter", layout="wide")
    st.title("Behavioral Cloud IOC Hunter")
    st.caption("Detect cloud attackers by API call sequences, parameter fingerprints, and source context")

    events_path = st.sidebar.text_input("CloudTrail activity log", value=args.events)
    baseline_countries = st.sidebar.text_input("Expected source countries", value="US")
    known = {item.strip().upper() for item in baseline_countries.split(",") if item.strip()}

    try:
        events = load_events(events_path)
        result = hunt(events_path, known_countries=known)
    except (OSError, ValueError, KeyError) as error:
        st.error(f"Unable to analyze the activity log: {error}")
        st.stop()

    first, second, third, fourth = st.columns(4)
    first.metric("Events analyzed", result["event_count"])
    second.metric("Behavioral detections", len(result["detections"]))
    third.metric("Critical", result["critical_count"])
    fourth.metric("Suspect credentials", len(result["suspected_compromised_credentials"]))

    if result["suspected_compromised_credentials"]:
        st.error("Suspected compromised credentials: " + ", ".join(result["suspected_compromised_credentials"]))

    render_detections(result["detections"])
    render_parameter_iocs(result["parameter_iocs"])
    render_clusters(result["clusters"])
    render_signals(result["contextual_signals"])

    with st.expander("Raw activity log"):
        st.dataframe(
            pd.DataFrame(
                [
                    {
                        "time": event["eventTime"],
                        "api": event["eventName"],
                        "region": event["awsRegion"],
                        "source_ip": event["sourceIPAddress"],
                        "access_key": event.get("accessKeyId"),
                        "country": event.get("country"),
                        "error": event.get("errorCode") or "",
                        "parameters": ", ".join(f"{key}={value}" for key, value in (event.get("requestParameters") or {}).items()),
                    }
                    for event in events
                ]
            ),
            use_container_width=True,
            hide_index=True,
        )

    st.caption(
        "Atomic IOCs age quickly. Behavioral IOCs describe how an actor operates, so they survive infrastructure rotation."
    )


if __name__ == "__main__":
    main()
