from __future__ import annotations

import os
import streamlit as st


def build_strategy(domain: str) -> str:
    return f"""## GTM strategy: {domain.title()}

**Research Agent** identified a high-friction buyer workflow, demand for measurable ROI, and a crowded market of broad platforms.

**Analyst Agent** recommends a focused entry wedge: target mid-market operators who need faster execution, clearer reporting, and lower implementation effort.

**Strategy Agent** proposes an operator-led motion: run a five-customer pilot, publish measurable outcomes, then expand through partner referrals and targeted outbound.

**Head Planner** priority: validate time-to-value and pilot-to-paid conversion before expanding the target segment.
"""


def main() -> None:
    st.set_page_config(page_title="GTM Research Agents", page_icon="GTM", layout="wide")
    st.title("GTM Research Agents")
    st.caption("Multi-agent market research and go-to-market planning workspace")

    if "messages" not in st.session_state:
        st.session_state.messages = [
            {"role": "assistant", "content": "Name a market or product category and I will assemble a GTM research brief."}
        ]

    with st.sidebar:
        st.subheader("Active Team")
        st.markdown("**Head Planner**\nOrchestrates the brief and final memo")
        st.markdown("**Research Agent**\nFinds market and competitor signals")
        st.markdown("**Analyst Agent**\nSynthesizes opportunities and gaps")
        st.markdown("**Strategy Agent**\nBuilds positioning, channels, and milestones")
        st.divider()
        
        # Google Docs configuration status
        doc_id = os.getenv("GOOGLE_DOC_ID")
        creds_path = os.getenv("GOOGLE_APPLICATION_CREDENTIALS")
        
        if doc_id and creds_path:
            st.markdown("✅ **Google Docs Export Enabled**")
            st.caption(f"Doc ID: {doc_id[:30]}...")
            st.markdown("[Setup Instructions](https://github.com/your-repo/gtm_multi_agent#google-docs-export)")
        else:
            st.markdown("⚠️ **Google Docs Export Not Configured**")
            st.caption("Run `python setup_google_docs.py` to enable")
        
        st.divider()
        st.caption("Demo mode uses deterministic output. Configure the CrewAI CLI separately for live tool-backed research.")

    for message in st.session_state.messages:
        with st.chat_message(message["role"]):
            st.markdown(message["content"])

    prompt = st.chat_input("Example: Build a GTM plan for compliance automation in fintech")
    if prompt:
        st.session_state.messages.append({"role": "user", "content": prompt})
        with st.chat_message("user"):
            st.markdown(prompt)
        with st.chat_message("assistant"):
            with st.status("Four agents are preparing the strategy brief", expanded=True) as status:
                st.write("Research Agent: collecting market and competitor signals")
                st.write("Analyst Agent: identifying the strongest entry wedge")
                st.write("Strategy Agent: drafting channels, milestones, and KPIs")
                st.write("Head Planner: assembling the final recommendation")
                status.update(label="Strategy brief ready", state="complete")
            response = build_strategy(prompt)
            st.markdown(response)
            
            # Export options
            col1, col2 = st.columns(2)
            with col1:
                if st.button("📥 Download as Markdown"):
                    st.download_button(
                        "Download GTM Strategy",
                        response,
                        file_name=f"gtm_strategy_{prompt.replace(' ', '_')[:20]}.md",
                        mime="text/markdown"
                    )
            
            with col2:
                doc_id = os.getenv("GOOGLE_DOC_ID")
                creds_path = os.getenv("GOOGLE_APPLICATION_CREDENTIALS")
                if doc_id and creds_path:
                    if st.button("📝 Export to Google Docs"):
                        from gtm_project.exporters import export_to_google_docs
                        result = export_to_google_docs(response)
                        if result.get("status") == "exported":
                            st.success(f"✅ Exported! [Open Document](https://docs.google.com/document/d/{result.get('document_id')}/edit)")
                        else:
                            st.warning(f"⚠️ {result.get('detail')}")
        
        st.session_state.messages.append({"role": "assistant", "content": response})


if __name__ == "__main__":
    main()