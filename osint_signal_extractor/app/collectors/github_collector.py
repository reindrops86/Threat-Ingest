from __future__ import annotations

import os
from typing import Any, Dict, List

import requests


class GitHubCollector:
    def __init__(self, token: str | None = None, timeout: int = 10):
        self.token = token or os.getenv("GITHUB_TOKEN")
        self.timeout = timeout
        self.headers = {"Accept": "application/vnd.github+json"}
        if self.token:
            self.headers["Authorization"] = f"Bearer {self.token}"

    def search_repositories(self, query: str, limit: int = 10) -> List[Dict[str, Any]]:
        url = "https://api.github.com/search/repositories"
        params = {"q": query, "per_page": min(limit, 10), "sort": "updated"}
        response = requests.get(url, headers=self.headers, params=params, timeout=self.timeout)
        response.raise_for_status()
        payload = response.json()
        items = payload.get("items", [])
        results = []
        for item in items:
            results.append({
                "name": item.get("full_name"),
                "url": item.get("html_url"),
                "description": item.get("description"),
                "stargazers_count": item.get("stargazers_count", 0),
                "language": item.get("language"),
                "source_type": "github_repo",
            })
        return results
