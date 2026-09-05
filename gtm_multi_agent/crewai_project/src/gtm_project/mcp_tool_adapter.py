from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
from typing import Any

from crewai.tools import BaseTool
from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client


class MCPToolAdapter(BaseTool):
    """A CrewAI tool that wraps an MCP server tool over stdio."""

    name: str = "mcp_tool"
    description: str = "Calls a tool exposed by the local MCP server."

    tool_name: str = "market_research"
    def _run(self, **kwargs: Any) -> str:
        async def call():
            project_root = Path(__file__).resolve().parents[3]
            server_path = os.getenv("MCP_PYTHON_EXECUTABLE", os.sys.executable)
            script_path = os.getenv("MCP_SERVER_SCRIPT", str(project_root / "mcp_server" / "gtm_mcp_server.py"))
            params = StdioServerParameters(
                command=server_path,
                args=[script_path],
                cwd=str(project_root.parent),
            )
            async with stdio_client(params) as (read, write):
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    response = await session.call_tool(self.tool_name, kwargs)
                    content = getattr(response, "content", []) or []
                    if content and hasattr(content[0], "text"):
                        return content[0].text
                    structured = getattr(response, "structuredContent", {})
                    return json.dumps(structured, indent=2)

        return asyncio.run(call())


class MCPMarketResearchTool(MCPToolAdapter):
    name: str = "market_research"
    description: str = "Search the live MCP market research tool for startup signals in a target domain."
    tool_name: str = "market_research"


class MCPCompetitorScanTool(MCPToolAdapter):
    name: str = "competitor_scan"
    description: str = "Search the live MCP competitor scan tool for likely competitors in a target domain."
    tool_name: str = "competitor_scan"


class MCPGTMPlanningTool(MCPToolAdapter):
    name: str = "gtm_plan"
    description: str = "Use the live MCP GTM planning tool to create a strategy plan."
    tool_name: str = "gtm_plan"
