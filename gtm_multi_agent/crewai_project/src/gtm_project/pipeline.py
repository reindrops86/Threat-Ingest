from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Any

from .evidence import EvidenceRecord, assess_evidence


class DeterministicGTMFlow:
    """Offline reference implementation used for tests, demos, and n8n comparison."""

    def __init__(self, evidence: list[EvidenceRecord], implementation: str = "crewai_demo") -> None:
        self.evidence = evidence
        self.implementation = implementation
        self.events: list[dict[str, Any]] = []

    def run(self, brief: str, budget_cap_usd: float = 2.00) -> dict[str, Any]:
        started = time.perf_counter()
        research = self._run_stage("Research Agent", self._research)
        analysis = self._run_stage("Analyst Agent", self._analyze, research)
        strategy = self._run_stage("Strategy Agent", self._strategy, brief, research, analysis)
        document = self._run_stage("Head Planner", self._document, brief, research, analysis, strategy)
        latency_seconds = round(time.perf_counter() - started, 4)
        estimated_cost = round(sum(event["estimated_cost_usd"] for event in self.events), 4)
        kpis = assess_evidence(self.evidence, answered_questions=4, total_questions=4)
        kpis.update(
            {
                "latency_seconds": latency_seconds,
                "latency_target_minutes": 15,
                "estimated_cost_usd": estimated_cost,
                "budget_cap_usd": budget_cap_usd,
                "budget_within_cap": estimated_cost <= budget_cap_usd,
                "reproducibility_percent": 100,
                "uncited_claims": 0,
            }
        )
        return {
            "run_id": f"{self.implementation}-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}",
            "implementation": self.implementation,
            "brief": brief,
            "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
            "research": research,
            "analysis": analysis,
            "strategy": strategy,
            "strategy_document": document,
            "observability": {"events": self.events, "kpis": kpis},
        }

    def _run_stage(self, agent: str, action: Any, *args: Any) -> Any:
        started = time.perf_counter()
        result = action(*args)
        self.events.append(
            {
                "agent": agent,
                "status": "completed",
                "retry_count": 0,
                "latency_ms": round((time.perf_counter() - started) * 1000, 2),
                "estimated_cost_usd": 0.02,
            }
        )
        return result

    def _research(self) -> dict[str, Any]:
        return {
            "evidence": [record.to_dict() for record in self.evidence],
            "research_answers": [
                {"question": record.research_question, "answer": record.claim, "evidence_ids": [record.evidence_id]}
                for record in self.evidence
            ],
            "competitor_table": [
                {"competitor_type": "Broad compliance suite", "strength": "Wide feature coverage", "gap": "Slow implementation for focused workflows"},
                {"competitor_type": "Point workflow tool", "strength": "Simple initial adoption", "gap": "Limited audit evidence and enterprise controls"},
                {"competitor_type": "Internal spreadsheet process", "strength": "No incremental software cost", "gap": "Low traceability and unreliable handoffs"},
            ],
            "pricing_matrix": [
                {"model": "Pilot", "price_signal": "Fixed scope", "buyer_value": "Validate time-to-value before annual commitment"},
                {"model": "Platform subscription", "price_signal": "Annual recurring", "buyer_value": "Standardize controls and reporting"},
                {"model": "Implementation services", "price_signal": "One-time", "buyer_value": "Integrate existing compliance workflows"},
            ],
        }

    @staticmethod
    def _analyze(research: dict[str, Any]) -> dict[str, Any]:
        return {
            "opportunity": "Compliance-heavy mid-market finance operations need faster evidence collection and clearer workflow ownership.",
            "swot": {
                "strengths": ["Focused workflow wedge", "Measurable operational ROI"],
                "weaknesses": ["Requires trust and integration proof"],
                "opportunities": ["Growing auditability and documentation burden"],
                "threats": ["Broad suites can bundle adjacent capabilities"],
            },
            "four_ps": {"product": "Evidence and workflow automation", "price": "Pilot-to-platform", "place": "Direct plus integration partners", "promotion": "Compliance outcome proof points"},
            "seven_ps": {"people": "Compliance and operations champions", "process": "Pilot, instrument, expand", "physical_evidence": "Audit-ready evidence packs"},
            "citation_count": len(research["evidence"]),
        }

    @staticmethod
    def _strategy(brief: str, research: dict[str, Any], analysis: dict[str, Any]) -> dict[str, Any]:
        return {
            "brief": brief,
            "icps": ["Mid-market fintech compliance leaders", "Finance operations teams with recurring audit evidence work"],
            "value_proposition": "Reduce manual compliance handoffs while making evidence, ownership, and reporting visible.",
            "messaging": ["Turn fragmented compliance work into an auditable operating system.", "Prove time saved before expanding the deployment."],
            "channels": ["Targeted outbound to compliance operations leaders", "Referral partners in ERP, risk, and compliance ecosystems", "Pilot-led product demonstrations"],
            "launch_plan": ["Run five design-partner pilots", "Measure time-to-value and evidence-completion time", "Publish approved outcome stories", "Expand through partner referrals"],
            "kpis": ["Pilot-to-paid conversion", "Time-to-value", "Evidence completion time", "Net revenue retention", "CAC payback"],
            "evidence_ids": [item["evidence_id"] for item in research["evidence"]],
            "differentiation": analysis["opportunity"],
        }

    @staticmethod
    def _document(brief: str, research: dict[str, Any], analysis: dict[str, Any], strategy: dict[str, Any]) -> str:
        citations = "\n".join(f"- [{item['evidence_id']}] {item['source_title']} - {item['source_url']}" for item in research["evidence"])
        competitors = "\n".join(f"| {item['competitor_type']} | {item['strength']} | {item['gap']} |" for item in research["competitor_table"])
        return f"""# GTM Strategy Memo

## Project Brief
{brief}

## Executive Summary
{analysis['opportunity']}

## Ideal Customer Profiles
{chr(10).join(f'- {item}' for item in strategy['icps'])}

## Value Proposition
{strategy['value_proposition']}

## Competitor Scan
| Category | Strength | Gap |
| --- | --- | --- |
{competitors}

## Pricing Matrix
| Model | Price Signal | Buyer Value |
| --- | --- | --- |
{chr(10).join(f"| {item['model']} | {item['price_signal']} | {item['buyer_value']} |" for item in research['pricing_matrix'])}

## Strategic Synthesis
### SWOT
{chr(10).join(f"- **{key.title()}**: {', '.join(value)}" for key, value in analysis['swot'].items())}

### 4P
{chr(10).join(f"- **{key.title()}**: {value}" for key, value in analysis['four_ps'].items())}

### 7P Extensions
{chr(10).join(f"- **{key.title()}**: {value}" for key, value in analysis['seven_ps'].items())}

## Messaging and Channels
{chr(10).join(f'- {item}' for item in strategy['messaging'])}

{chr(10).join(f'- {item}' for item in strategy['channels'])}

## Launch Plan
{chr(10).join(f'1. {item}' for item in strategy['launch_plan'])}

## Measurement
{chr(10).join(f'- {item}' for item in strategy['kpis'])}

## Evidence Register
{citations}
"""