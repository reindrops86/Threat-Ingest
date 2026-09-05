from crewai import Agent

from gtm_project.mcp_tool_adapter import MCPCompetitorScanTool, MCPGTMPlanningTool, MCPMarketResearchTool


def build_agents():
    research_tool = MCPMarketResearchTool()
    competitor_tool = MCPCompetitorScanTool()
    planning_tool = MCPGTMPlanningTool()

    head_planner = Agent(
        role="Head Planner",
        goal="Coordinate the full GTM research workflow and synthesize the final strategy summary.",
        backstory="You lead the research and planning team, align all outputs, and ensure the final strategy document is actionable.",
        tools=[planning_tool],
        verbose=True,
    )

    research_agent = Agent(
        role="Research Agent",
        goal="Collect desk-research insights, market signals, and competitor information for the target domain.",
        backstory="You specialize in finding strong evidence about trends, customer pain, and the competitive landscape.",
        tools=[research_tool, competitor_tool],
        verbose=True,
    )

    analyst_agent = Agent(
        role="Analyst Agent",
        goal="Interpret the research and turn it into strategic themes, market gaps, and opportunity narratives.",
        backstory="You connect the evidence into clear strategic conclusions and highlight the most important growth levers.",
        verbose=True,
    )

    strategy_agent = Agent(
        role="Strategy Agent",
        goal="Draft a concrete GTM plan covering positioning, channels, launch, and KPIs.",
        backstory="You convert strategic insight into a practical go-to-market playbook for product and sales teams.",
        tools=[planning_tool],
        verbose=True,
    )

    return {
        "head_planner": head_planner,
        "research_agent": research_agent,
        "analyst_agent": analyst_agent,
        "strategy_agent": strategy_agent,
    }
