from __future__ import annotations

import argparse
import sys
from pathlib import Path

import pandas as pd
import streamlit as st

PACKAGE_ROOT = Path(__file__).resolve().parent
if str(PACKAGE_ROOT) not in sys.path:
    sys.path.insert(0, str(PACKAGE_ROOT))

from actor_tracker import ActorRegistry
from behavioral_ioc import hunt

STATUS_COLOR = {"tracked": "#b91c1c", "candidate": "#b45309", "retired": "#64748b"}


def render_roster(actors: list[dict]) -> None:
    st.subheader("Tracked Actors")
    frame = pd.DataFrame(
        [
            {
                "actor": actor["name"] or actor["actor_id"],
                "id": actor["actor_id"],
                "status": actor["status"],
                "confidence": actor["current_confidence"],
                "days_quiet": actor["days_quiet"],
                "rotations": actor["rotations"],
                "victims": len(actor["victims"]),
                "credentials": len(actor["compromised_credentials"]),
                "first_seen": actor["first_seen"][:10],
                "last_seen": actor["last_seen"][:10],
            }
            for actor in actors
        ]
    )
    st.dataframe(frame, use_container_width=True, hide_index=True)


def render_profile(actor: dict) -> None:
    color = STATUS_COLOR.get(actor["status"], "#475569")
    st.markdown(
        f"### {actor['name'] or actor['actor_id']} "
        f"<span style='color:{color}; font-size:0.8rem; text-transform:uppercase;'>{actor['status']}</span>",
        unsafe_allow_html=True,
    )

    first, second, third, fourth = st.columns(4)
    first.metric("Current confidence", f"{actor['current_confidence']}/100")
    second.metric("Days quiet", actor["days_quiet"])
    third.metric("Infra rotations", actor["rotations"])
    fourth.metric("Victim accounts", len(actor["victims"]))

    if actor["days_quiet"] > 60:
        st.info("Confidence is decayed because this cluster has been dormant. Fresh activity would raise it again.")

    st.markdown("**Durable fingerprints**")
    if actor["fingerprints"]:
        st.dataframe(pd.DataFrame(actor["fingerprints"]), use_container_width=True, hide_index=True)
        st.caption("These survive infrastructure changes and are the strongest basis for linking new activity.")
    else:
        st.caption("No parameter-level fingerprints recorded for this cluster.")

    st.markdown("**Infrastructure history**")
    infrastructure = actor["infrastructure"]
    left, middle, right = st.columns(3)
    left.markdown("Source IPs  \n" + "  \n".join(f"`{item}`" for item in infrastructure["source_ips"]))
    middle.markdown("ASNs  \n" + "  \n".join(f"`{item}`" for item in infrastructure["asns"]))
    right.markdown("Countries  \n" + "  \n".join(f"`{item}`" for item in infrastructure["countries"]))

    if len(infrastructure["asns"]) > 1:
        st.warning(
            f"Infrastructure rotated across {len(infrastructure['asns'])} ASNs and "
            f"{len(infrastructure['countries'])} countries while behavior stayed consistent."
        )

    st.markdown("**Activity timeline**")
    timeline = pd.DataFrame(actor["timeline"])
    st.dataframe(timeline, use_container_width=True, hide_index=True)

    st.markdown("**Behavioral signatures**")
    st.write(", ".join(actor["signatures"]) or "none")

    st.markdown("**Impact**")
    st.write(f"Compromised credentials: {', '.join(actor['compromised_credentials'])}")
    st.write(f"Victim principals: {', '.join(actor['victims'])}")

    if actor["notes"]:
        st.markdown("**Analyst notes**")
        st.dataframe(pd.DataFrame(actor["notes"]), use_container_width=True, hide_index=True)


def main() -> None:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--registry", default=str(Path("data") / "actor_registry.json"))
    args, _ = parser.parse_known_args()

    st.set_page_config(page_title="Cloud Threat Actor Tracker", layout="wide")
    st.title("Cloud Threat Actor Tracker")
    st.caption("Persistent actor profiles built from behavioral evidence that survives infrastructure rotation")

    registry_path = st.sidebar.text_input("Actor registry", value=args.registry)
    registry = ActorRegistry(registry_path)

    st.sidebar.header("Ingest activity")
    log_path = st.sidebar.text_input("Activity log", value=str(Path("data") / "cloudtrail_activity.json"))
    label = st.sidebar.text_input("Wave label", value="wave-1")
    if st.sidebar.button("Ingest into registry", type="primary"):
        try:
            result = registry.ingest(hunt(log_path), label)
        except (OSError, ValueError, KeyError) as error:
            st.sidebar.error(f"Ingest failed: {error}")
        else:
            st.sidebar.success(f"{len(result['created'])} new, {len(result['linked'])} linked")
            for link in result["linked"]:
                st.sidebar.caption(f"{link['access_key']} → {link['actor_id']} ({link['score']}/100)")

    actors = registry.roster()
    if not actors:
        st.info("The registry is empty. Ingest an activity log from the sidebar to begin tracking.")
        st.stop()

    first, second, third = st.columns(3)
    first.metric("Actors tracked", len(actors))
    second.metric("Named actors", sum(1 for actor in actors if actor["name"]))
    third.metric("Rotating clusters", sum(1 for actor in actors if actor["rotations"] > 0))

    render_roster(actors)

    selected_id = st.selectbox(
        "Select an actor",
        [actor["actor_id"] for actor in actors],
        format_func=lambda value: next(
            f"{item['name'] or item['actor_id']} ({item['current_confidence']}/100)" for item in actors if item["actor_id"] == value
        ),
    )
    selected = next(actor for actor in actors if actor["actor_id"] == selected_id)
    render_profile(selected)

    st.divider()
    st.subheader("Analyst Actions")
    promote_tab, note_tab, merge_tab, split_tab = st.tabs(["Promote", "Add note", "Merge", "Split"])

    with promote_tab:
        st.caption("Promote a candidate cluster to a named actor once the evidence justifies it.")
        name = st.text_input("Actor name", value=selected["name"] or "")
        if st.button("Promote to tracked actor"):
            if name.strip():
                registry.promote(selected_id, name.strip())
                st.success(f"{selected_id} is now tracked as {name.strip()}.")
                st.rerun()
            else:
                st.warning("Provide a name before promoting.")

    with note_tab:
        note = st.text_area("Note", placeholder="Record the evidence and any competing hypothesis.")
        if st.button("Save note"):
            if note.strip():
                registry.add_note(selected_id, note.strip())
                st.success("Note saved.")
                st.rerun()
            else:
                st.warning("Enter note text first.")

    with merge_tab:
        st.caption("Merge when two clusters turn out to be the same operator.")
        others = [actor["actor_id"] for actor in actors if actor["actor_id"] != selected_id]
        if others:
            secondary = st.selectbox("Merge this cluster into the selected actor", others)
            if st.button("Merge clusters"):
                if registry.merge(selected_id, secondary):
                    st.success(f"Merged {secondary} into {selected_id}.")
                    st.rerun()
                else:
                    st.error("Merge failed.")
        else:
            st.info("No other clusters available to merge.")

    with split_tab:
        st.caption("Split when evidence shows a cluster actually contains more than one operator.")
        movable = st.multiselect("Credentials to move into a new cluster", selected["compromised_credentials"])
        if st.button("Split into new cluster"):
            created = registry.split(selected_id, movable)
            if created:
                st.success(f"Created {created['actor_id']}.")
                st.rerun()
            else:
                st.error("Select at least one credential, but not all of them.")

    st.caption(
        "Clustering is a hypothesis. Confidence reflects evidence strength and recency, and it is not a claim of attribution to a named entity."
    )


if __name__ == "__main__":
    main()
