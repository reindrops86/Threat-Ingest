from crewai import Task


def build_tasks(agents, domain: str):
    research_task = Task(
        description=(
            f"Use the market research and competitor tools to collect data for the {domain} market. "
            "Identify demand signals, buyer pain points, and the top competitive patterns. "
            "Return structured output that includes market opportunity, customer pain, and competitive landscape."
        ),
        agent=agents["research_agent"],
        expected_output="A concise market research brief with trends, buyer pain, and competitor landscape.",
    )

    analyst_task = Task(
        description=(
            f"Analyze the research for {domain} and identify strategic themes, gaps, and likely entry points. "
            "Highlight the strongest wedge, segment priorities, and likely differentiation opportunities."
        ),
        agent=agents["analyst_agent"],
        expected_output="A strategic analysis summary with opportunity narrative and key findings.",
    )

    strategy_task = Task(
        description=(
            f"Use the GTM planning tool to turn strategic insight into a concrete plan for {domain}. "
            "Include positioning, target segments, acquisition channels, launch milestones, and KPIs."
        ),
        agent=agents["strategy_agent"],
        expected_output="A practical GTM plan with positioning, channels, and KPIs.",
    )

    planner_task = Task(
        description=(
            f"Coordinate all agent outputs and assemble the final GTM strategy memo for {domain}. "
            "Keep the document executive-ready, structured, and suitable for export to Google Docs or a brief."
        ),
        agent=agents["head_planner"],
        expected_output="A polished executive GTM strategy document ready for export.",
    )

    return [research_task, analyst_task, strategy_task, planner_task]
