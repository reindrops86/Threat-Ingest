# Startup Founder Multi-Agent Team

This project demonstrates a lightweight founder-support orchestration system built with LangGraph. It simulates a startup accelerator environment in which a founder receives coordinated guidance from three specialized agents working together to translate a target domain into a pitch-ready storyline and funding narrative.

The system is intentionally simple, explainable, and stateful. A shared workflow keeps the agents aligned, captures memory between steps, and logs each handoff so the reasoning chain remains visible and debuggable.

## System architecture

The orchestration uses a graph-based workflow in LangGraph with explicit state passing between nodes. The shared state includes:

- startup domain
- research findings
- funding recommendations
- pitch outline
- feedback notes
- reasoning trace and memory context

Each agent operates on the same evolving state but owns a narrow responsibility. This creates a clean handoff pattern: research informs funding, funding shapes the story, and the pitch coach refines the narrative before delivery.

## Why LangGraph

LangGraph was selected because the workflow is naturally graph-shaped. The process is not a single monolithic prompt; it is a coordinated pipeline with dependencies, staged outputs, and brief recursive feedback. LangGraph makes that structure explicit and allows the project to model sequential execution and a small improvement loop without unnecessary complexity.

## Agent responsibilities

### 1. Research Agent
The Research Agent is responsible for market understanding. It surfaces:

- market growth and demand signals
- customer pain points
- competitive patterns
- regulatory and adoption context

It does not select grant programs or write the final deck. Instead, it provides the strategic evidence that later agents use to align the pitch and funding plan.

### 2. Funding Advisor
The Funding Advisor interprets market findings and recommends viable financing strategies. It can suggest:

- grant programs
- accelerator tracks
- seed- and early-stage funding pathways
- pilot opportunities and founder signals that increase investor confidence

Its role is to convert domain context into actionable fundraising guidance without taking over the narrative writing task.

### 3. Pitch Coach
The Pitch Coach turns the research and funding context into a founder-ready pitch deck outline. It builds the narrative around:

- problem statement
- solution framing
- growth opportunity
- traction and early validation
- business model and GTM
- funding ask and milestone plan

The coach also performs a refinement pass to tighten the message based on peer input and the combined state of the system.

## Coordination flow

1. The user enters a startup domain such as fintech, healthtech, climate, or SaaS.
2. The Research Agent generates domain-specific market insight.
3. The Funding Advisor interprets that insight and produces recommendations.
4. The Pitch Coach merges the research and funding context into a concrete pitch deck outline.
5. A lightweight refinement pass improves the deck according to the combined feedback.
6. The final output is saved as structured JSON, along with a trace of agent actions and state handoffs.

## Feedback loop

The workflow includes a refinement phase after the initial pitch draft. This simulates the real-world accelerator pattern where founders receive feedback from advisors and adjust the story to be sharper, more investor-credible, and more aligned with the likely funding narrative.

## Local logging and traceability

The script writes a local trace log to a JSON file so each agent contribution can be inspected. The log captures:

- execution order
- input domain
- agent-specific findings
- major pitch decisions
- refinement notes

This provides enough observability for a demo or prototype without requiring a full external LangSmith integration. It preserves explainability, which is especially valuable in founder-facing workflows where reasoning needs to be transparent.

## How to run

```bash
cd startup_agent_team
python startup_agent_demo.py --domain fintech
```

If no domain is supplied, the script falls back to `fintech` and still runs successfully. The workflow writes a trace log to `agent_trace.json` in the same folder.

## Example domain inputs

- fintech
- healthtech
- climate
- enterprise ai
- b2b saas

## Challenges and trade-offs

This is a lightweight prototype rather than a full production-grade research platform. To keep the demo practical and explainable, several trade-offs were made:

- domain logic is heuristic and template-based instead of live web research
- the workflow uses a shared state model rather than sprawling autonomous tool chains
- the memory layer is explicit and structured instead of opaque or deeply recursive
- the feedback loop is intentionally small and deterministic to make reasoning easier to follow

These choices make the system easier to run, debug, and present in an accelerator or founder-support setting while still demonstrating the core principles of multi-agent collaboration and traceable reasoning.
