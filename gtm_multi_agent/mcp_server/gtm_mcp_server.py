from __future__ import annotations

import json
from typing import Any

import requests
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("gtm-research")


@mcp.tool()
def market_research(domain: str, query: str | None = None) -> str:
    """Search public GitHub repositories as a lightweight market signal source."""
    q = query or f"{domain} market trends startup"
    response = requests.get(
        "https://api.github.com/search/repositories",
        params={"q": q, "per_page": 5},
        timeout=20,
    )
    response.raise_for_status()
    payload = response.json()
    results = []
    for item in payload.get("items", [])[:5]:
        results.append({
            "name": item.get("full_name"),
            "description": item.get("description"),
            "stars": item.get("stargazers_count"),
            "url": item.get("html_url"),
        })

    data = {
        "domain": domain,
        "query": q,
        "results": results,
    }
    return json.dumps(data, indent=2)


@mcp.tool()
def competitor_scan(domain: str) -> str:
    """Search for likely competitors in the target domain."""
    return market_research(domain, f"{domain} competitor startup")


@mcp.tool()
def gtm_plan(domain: str, research_summary: str) -> str:
    """Create a structured GTM plan based on research signals."""
    data = {
        "domain": domain,
        "positioning": f"Focus on a narrow wedge in {domain} with measurable ROI and clear buyer pain.",
        "audience": [
            "Operations leaders",
            "Finance and compliance teams",
            "Revenue operations and product managers",
        ],
        "channels": [
            "Outbound sales to target operators",
            "Partner referrals with adjacent SaaS vendors",
            "Pilot-led product adoption",
        ],
        "launch_phases": [
            "Pilot with 5-10 high-fit customers",
            "Publish proof points and outcomes",
            "Expand via partner distribution",
        ],
        "kpis": [
            "Pilot conversion rate",
            "Time to value",
            "Gross retention",
            "CAC payback",
        ],
        "research_summary": research_summary,
    }
    return json.dumps(data, indent=2)


if __name__ == "__main__":
    mcp.run(transport="stdio")
