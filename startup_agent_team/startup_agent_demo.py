from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, TypedDict

from langgraph.graph import END, StateGraph


class AgentState(TypedDict, total=False):
    domain: str
    research_findings: Dict[str, Any]
    funding_recommendations: Dict[str, Any]
    pitch_outline: Dict[str, Any]
    feedback: str
    trace: List[Dict[str, Any]]
    memory: Dict[str, Any]


def research_agent(state: AgentState) -> AgentState:
    domain = state["domain"]
    insights = {
        "market": {
            "domain": domain,
            "signals": [
                f"{domain.title()} demand is growing as operators seek more automation and lower-friction user experiences.",
                "Buyers increasingly reward outcomes tied to ROI, compliance, or operational efficiency.",
                "Early traction often comes from a narrow wedge with clear customer pain and measurable savings.",
            ],
            "customer_pain": [
                "Fragmented workflows",
                "High manual operating costs",
                "Lack of trust or visibility",
                "Poor integration options",
            ],
            "competitive_pattern": [
                "Point solutions win early pilots",
                "Platform plays require stronger distribution and trust",
                "Execution quality matters more than feature breadth in early stages",
            ],
            "regulatory_notes": [
                "Compliance and guardrails are important in regulated sectors.",
                "Data privacy and auditability are common buying criteria.",
            ],
        },
        "positioning": {
            "recommended_angle": f"Start with a focused wedge in {domain} where the pain is urgent and measurable.",
            "key_message": "Reduce operational friction while improving trust, speed, or compliance outcomes.",
        },
    }

    trace_entry = {
        "agent": "Research Agent",
        "step": "market_signal_generation",
        "input_domain": domain,
        "output_summary": insights["positioning"]["recommended_angle"],
    }

    state["research_findings"] = insights
    state["memory"] = {"research": insights}
    state["trace"] = state.get("trace", []) + [trace_entry]
    return state


def funding_agent(state: AgentState) -> AgentState:
    domain = state["domain"]
    research = state.get("research_findings", {})

    funding_map = {
        "fintech": {
            "programs": [
                "Fintech innovation grants",
                "Regional startup accelerator cohorts",
                "Banking and payments sandbox programs",
            ],
            "notes": [
                "Emphasize compliance, trust, and operational efficiency to appeal to fintech backers.",
                "Customer pilots with regulated partners can strengthen the story.",
            ],
        },
        "healthtech": {
            "programs": [
                "Digital health accelerator programs",
                "Clinical innovation grants",
                "Healthcare data and interoperability pilots",
            ],
            "notes": [
                "Highlight clinical outcomes, workflow value, and compliance readiness.",
                "Evidence of provider or patient engagement is critical.",
            ],
        },
        "climate": {
            "programs": [
                "Climate tech grants",
                "Sustainability innovation programs",
                "Public-private decarbonization pilots",
            ],
            "notes": [
                "Tie the story to measurable impact and cost or emissions reduction.",
                "Pilot programs with target customers can improve investor confidence.",
            ],
        },
    }

    programs = funding_map.get(domain, {
        "programs": [
            "Early-stage startup accelerators",
            "Impact and innovation grants",
            "Industry-specific pilot funding",
        ],
        "notes": [
            "Anchor the ask around urgency, measurable value, and a clear wedge.",
            "Support pathways are strongest when traction or pilot evidence is visible.",
        ],
    })

    recommendations = {
        "domain": domain,
        "recommended_programs": programs["programs"],
        "funding_thesis": "Lead with traction, operational value, and a defensible wedge in a meaningful pain point.",
        "angel_and_seed_guidance": [
            "Frame the ask around milestones, speed, and customer proof.",
            "Use early pilots and strategic partnerships to lengthen runway.",
        ],
        "notes": programs["notes"],
        "context_from_research": research.get("positioning", {}).get("recommended_angle", "Build early wins in a narrow wedge."),
    }

    trace_entry = {
        "agent": "Funding Advisor",
        "step": "funding_recommendation",
        "input_domain": domain,
        "output_summary": recommendations["recommended_programs"],
    }

    state["funding_recommendations"] = recommendations
    state["memory"] = {**state.get("memory", {}), "funding": recommendations}
    state["trace"] = state.get("trace", []) + [trace_entry]
    return state


def pitch_agent(state: AgentState) -> AgentState:
    domain = state["domain"]
    research = state.get("research_findings", {})
    funding = state.get("funding_recommendations", {})

    deck = {
        "title": f"{domain.title()} Startup Pitch Deck Outline",
        "slides": [
            {
                "slide": 1,
                "title": "Title & Problem",
                "content": f"{domain.title()} is facing fragmented workflows and rising operational costs. We help customers solve a painful, measurable problem with a focused software workflow.",
            },
            {
                "slide": 2,
                "title": "Pain / Why Now",
                "content": research.get("market", {}).get("signals", ["Market is growing and the pain is urgent."]),
            },
            {
                "slide": 3,
                "title": "Solution",
                "content": research.get("positioning", {}).get("key_message", "A low-friction workflow that improves trust, speed, or compliance across the user journey."),
            },
            {
                "slide": 4,
                "title": "Market Opportunity",
                "content": f"The {domain} market is attractive because buyers want measurable outcomes, stronger automation, and better compliance or trust controls.",
            },
            {
                "slide": 5,
                "title": "Product / Early Traction",
                "content": "Introduce the wedge, customer feedback, onboarding signal, partner pilots, and any efficiency or conversion improvements.",
            },
            {
                "slide": 6,
                "title": "Business Model",
                "content": "Describe revenue model, pricing logic, customer segments, and unit economics or gross margin potential.",
            },
            {
                "slide": 7,
                "title": "Go-to-Market",
                "content": "Outline the initial channel plan, partnerships, and acquisition motion tailored to the target buyer profile.",
            },
            {
                "slide": 8,
                "title": "Funding and Milestones",
                "content": funding.get("recommended_programs", ["Seed round", "Grant support", "Accelerator pathway"]),
            },
            {
                "slide": 9,
                "title": "Ask / Use of Funds",
                "content": "State the round amount, target milestones, and how operations, product, and go-to-market teams will expand.",
            },
        ],
    }

    feedback = (
        "Refine the story to focus on a narrow wedge, measurable problem, and strong operational proof before broader expansion."
    )

    trace_entry = {
        "agent": "Pitch Coach",
        "step": "pitch_outline_generation",
        "input_domain": domain,
        "output_summary": deck["title"],
    }

    state["pitch_outline"] = deck
    state["feedback"] = feedback
    state["memory"] = {**state.get("memory", {}), "pitch": deck, "feedback": feedback}
    state["trace"] = state.get("trace", []) + [trace_entry]
    return state


def refine_pitch(state: AgentState) -> AgentState:
    deck = state.get("pitch_outline", {})
    research = state.get("research_findings", {})
    funding = state.get("funding_recommendations", {})

    refined = deck.copy()
    refined["slides"][0]["content"] = (
        f"{state['domain'].title()} startup addressing a high-friction, high-cost workflow with measurable ROI. "
        "The founder is solving a defined pain point that aligns with current market demand and likely funding interest."
    )
    refined["slides"][5]["content"] = (
        "Focus on early revenue, pilot traction, and a simple repeatable monetization model grounded in customer value."
    )
    refined["slides"][8]["content"] = (
        "Use the funding strategy to support product delivery, go-to-market execution, and the proof points needed for the next equity or grant milestone. "
        f"Relevant paths: {', '.join(funding.get('recommended_programs', ['seed round']))}."
    )

    trace_entry = {
        "agent": "Pitch Coach",
        "step": "refinement_feedback",
        "input_domain": state["domain"],
        "output_summary": "Pitch tightened around wedge, traction, and funding fit.",
    }

    state["pitch_outline"] = refined
    state["trace"] = state.get("trace", []) + [trace_entry]
    state["memory"] = {
        **state.get("memory", {}),
        "refined_pitch": refined,
        "research_summary": research.get("positioning", {}).get("recommended_angle", ""),
        "funding_summary": funding.get("funding_thesis", ""),
    }
    return state


def build_graph():
    workflow = StateGraph(AgentState)
    workflow.add_node("research", research_agent)
    workflow.add_node("funding", funding_agent)
    workflow.add_node("pitch", pitch_agent)
    workflow.add_node("refine", refine_pitch)

    workflow.set_entry_point("research")
    workflow.add_edge("research", "funding")
    workflow.add_edge("funding", "pitch")
    workflow.add_edge("pitch", "refine")
    workflow.add_edge("refine", END)
    return workflow.compile()


def run_demo(domain: str = "fintech") -> Dict[str, Any]:
    app = build_graph()
    initial_state: AgentState = {
        "domain": domain,
        "trace": [],
        "memory": {},
    }
    final_state = app.invoke(initial_state)

    trace_path = Path(__file__).with_name("agent_trace.json")
    trace_path.write_text(json.dumps(final_state.get("trace", []), indent=2), encoding="utf-8")

    output = {
        "domain": final_state["domain"],
        "research_findings": final_state.get("research_findings", {}),
        "funding_recommendations": final_state.get("funding_recommendations", {}),
        "pitch_outline": final_state.get("pitch_outline", {}),
        "memory": final_state.get("memory", {}),
        "trace_log_path": str(trace_path),
    }
    return output


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Startup founder multi-agent pitch generator")
    parser.add_argument("--domain", default=None, help="Startup domain such as fintech, healthtech, climate, or b2b saas")
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    demo_domain = (args.domain or os.getenv("STARTUP_DOMAIN") or "").strip().lower()

    if not demo_domain and sys.stdin.isatty():
        demo_domain = input("Enter startup domain (e.g. fintech, healthtech, climate): ").strip().lower() or "fintech"
    if not demo_domain:
        demo_domain = "fintech"

    result = run_demo(demo_domain)

    print("\n=== Startup Founder Multi-Agent Output ===")
    print(json.dumps({
        "domain": result["domain"],
        "research_summary": result["research_findings"].get("positioning", {}).get("recommended_angle"),
        "funding_programs": result["funding_recommendations"].get("recommended_programs", []),
        "funding_thesis": result["funding_recommendations"].get("funding_thesis"),
        "pitch_preview": result["pitch_outline"].get("title"),
        "trace_log": result["trace_log_path"],
    }, indent=2))

    print("\n=== Memory Trace Summary ===")
    memory = result.get("memory", {})
    print(json.dumps({
        "research_summary": memory.get("research", {}).get("positioning", {}).get("recommended_angle"),
        "funding_summary": memory.get("funding", {}).get("funding_thesis"),
        "pitch_refinement": memory.get("refined_pitch", {}).get("slides", [{}])[0].get("content", "")
    }, indent=2))

    print("\n=== Pitch Deck Outline ===")
    for slide in result["pitch_outline"].get("slides", []):
        print(f"\nSlide {slide['slide']}: {slide['title']}")
        print(slide["content"])

    print("\n=== Trace Log ===")
    trace = json.loads(Path(result["trace_log_path"]).read_text(encoding="utf-8"))
    for item in trace:
        print(f"- {item['agent']} | {item['step']} | {item['output_summary']}")
