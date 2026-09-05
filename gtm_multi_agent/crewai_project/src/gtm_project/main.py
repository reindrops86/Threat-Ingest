import argparse
import sys
from pathlib import Path

from crewai import Crew

from gtm_project.agents import build_agents
from gtm_project.tasks import build_tasks


def run_demo(brief: str, output_dir: str) -> None:
    from gtm_project.evidence import load_evidence_catalog
    from gtm_project.exporters import write_outputs
    from gtm_project.pipeline import DeterministicGTMFlow

    evidence_path = Path(__file__).resolve().parents[2] / "data" / "evidence_catalog.json"
    result = DeterministicGTMFlow(load_evidence_catalog(evidence_path)).run(brief)
    paths = write_outputs(result, output_dir)
    print("\n=== Evidence-Backed GTM Demo ===")
    print(result["strategy_document"])
    print(f"\nArtifacts: {paths}")


def run_workflow(domain: str = "fintech", output_dir: str = "outputs", export_docs: bool = False):
    from gtm_project.exporters import write_outputs, export_to_google_docs
    
    agents = build_agents()
    tasks = build_tasks(agents, domain)

    crew = Crew(
        agents=[
            agents["research_agent"],
            agents["analyst_agent"],
            agents["strategy_agent"],
            agents["head_planner"],
        ],
        tasks=tasks,
        verbose=True,
    )

    result = crew.kickoff()
    print("\n=== Final GTM Strategy Summary ===")
    print(result)
    
    # Format the result for export
    if isinstance(result, str):
        strategy_document = result
    else:
        strategy_document = str(result)
    
    # Save to local files
    export_result = write_outputs({"strategy_document": strategy_document, "domain": domain}, output_dir)
    print(f"\n📁 Artifacts saved to {output_dir}:")
    for key, path in export_result.items():
        print(f"   {key}: {path}")
    
    # Export to Google Docs if enabled
    if export_docs:
        print("\n📝 Exporting to Google Docs...")
        docs_result = export_to_google_docs(strategy_document)
        if docs_result.get("status") == "exported":
            print(f"✅ Strategy exported to Google Doc: {docs_result.get('document_id')}")
            print(f"   Link: https://docs.google.com/document/d/{docs_result.get('document_id')}/edit")
        else:
            print(f"⚠️  Google Docs export: {docs_result.get('detail')}")
            print("   To enable export, run: python setup_google_docs.py")
    
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run the GTM multi-agent workflow")
    parser.add_argument("--domain", default="fintech", help="Startup or target domain to analyze")
    parser.add_argument("--mode", choices=("demo", "crewai"), default="demo", help="Use credential-free reference workflow or live CrewAI agents")
    parser.add_argument("--output-dir", default="outputs", help="Directory for demo artifacts")
    parser.add_argument("--export-docs", action="store_true", help="Export strategy to Google Docs (requires setup)")
    args = parser.parse_args()
    if args.mode == "demo":
        run_demo(f"Build a GTM plan for {args.domain}.", args.output_dir)
    else:
        run_workflow(args.domain, args.output_dir, args.export_docs)
