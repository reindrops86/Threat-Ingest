from __future__ import annotations

import json
import os
import time
from typing import Any, Dict, List

import requests


class MarketResearchTool:
    """Simple real HTTP-backed tool for market research lookup."""

    def __init__(self, base_url: str = "https://api.github.com"):
        self.base_url = base_url

    def search_market(self, domain: str, query: str | None = None) -> str:
        q = query or f"{domain} market trends startup"
        response = requests.get(
            f"{self.base_url}/search/repositories",
            params={"q": q, "per_page": 3},
            timeout=20,
        )
        response.raise_for_status()
        payload = response.json()
        items = payload.get("items", [])
        summary = []
        for item in items[:3]:
            summary.append({
                "name": item.get("full_name"),
                "description": item.get("description"),
                "stars": item.get("stargazers_count"),
                "url": item.get("html_url"),
            })
        return json.dumps({
            "domain": domain,
            "query": q,
            "results": summary,
        }, indent=2)


class CompetitorScanTool:
    """Searches public repositories as a lightweight stand-in for competitor scanning."""

    def scan(self, domain: str) -> str:
        tool = MarketResearchTool()
        return tool.search_market(domain, f"{domain} competitor startup")


class SerpAPIResearchTool:
    """Optional SerpAPI connector with bounded retries and no embedded credentials."""

    endpoint = "https://serpapi.com/search.json"

    def search(self, query: str, retries: int = 2) -> str:
        api_key = os.getenv("SERPAPI_API_KEY")
        if not api_key:
            raise RuntimeError("SERPAPI_API_KEY is not configured. Use the deterministic evidence catalog for offline runs.")
        last_error: Exception | None = None
        for attempt in range(retries + 1):
            try:
                response = requests.get(self.endpoint, params={"q": query, "api_key": api_key, "engine": "google"}, timeout=20)
                response.raise_for_status()
                payload = response.json()
                results = [
                    {"title": item.get("title"), "link": item.get("link"), "snippet": item.get("snippet")}
                    for item in payload.get("organic_results", [])[:5]
                ]
                return json.dumps({"query": query, "results": results, "source": "serpapi"}, indent=2)
            except requests.RequestException as error:
                last_error = error
                if attempt == retries:
                    break
                time.sleep(2**attempt)
        raise RuntimeError(f"SerpAPI request failed after {retries + 1} attempts: {last_error}")


class GTMPlanningTool:
    """Generates a structured GTM plan from a domain and signal set."""

    def draft_plan(self, domain: str, research_summary: str) -> str:
        return json.dumps({
            "domain": domain,
            "positioning": f"Focus on a narrow wedge in {domain} with measurable ROI and clear buyer pain.",
            "audience": [
                "Operations leaders",
                "Finance and compliance teams",
                "First-line product and revenue managers",
            ],
            "channels": [
                "Outbound funnel to decision-makers",
                "Partner referrals with ERP and compliance software vendors",
                "Pilot-based product-led growth",
            ],
            "launch_phases": [
                "Pilot with 5-10 highly relevant customers",
                "Publish proof points and outcomes",
                "Expand through strategic partnerships",
            ],
            "kpis": [
                "Pilot conversion rate",
                "Time to value",
                "Customer retention",
                "CAC payback",
            ],
            "research_summary": research_summary,
        }, indent=2)
