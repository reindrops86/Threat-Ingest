# GTM Research Agents

CrewAI implementation of a four-role market-research and go-to-market planning system. The command-line workflow uses CrewAI agents and MCP-backed tools; the chatbot is an offline-capable interface for presenting the same workflow during a demo.

## Roles

- `Head Planner` orchestrates tasks and assembles the executive strategy memo.
- `Research Agent` uses market-research and competitor-scan tools.
- `Analyst Agent` converts research into a market wedge and opportunity narrative.
- `Strategy Agent` turns that narrative into positioning, channels, milestones, and KPIs.

## UV Setup

```bash
uv sync
```

For a live CrewAI run, set the model-provider credentials required by your CrewAI configuration, start the MCP server, and run:

```bash
uv run python src/gtm_project/main.py --domain fintech
```

## Chatbot Demo

The chatbot does not require credentials. It provides an inspectable four-agent demonstration with deterministic responses, making it appropriate for screenshots and offline demonstrations.

```bash
uv run streamlit run src/gtm_project/chatbot.py
```

## Source Layout

- `src/gtm_project/agents.py` - CrewAI role definitions and MCP tools
- `src/gtm_project/tasks.py` - research, analysis, strategy, and planner task sequence
- `src/gtm_project/main.py` - CrewAI execution entry point
- `src/gtm_project/mcp_tool_adapter.py` - MCP tools adapted to CrewAI
- `src/gtm_project/chatbot.py` - Streamlit demo interface
