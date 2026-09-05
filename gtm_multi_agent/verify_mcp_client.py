import anyio
from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client


async def main():
    params = StdioServerParameters(
        command="C:/Users/downi/crewai-venv/Scripts/python.exe",
        args=["gtm_multi_agent/mcp_server/gtm_mcp_server.py"],
        cwd="C:/Users/downi/OneDrive/Documents/08metricsdemos_1786575674023/08_metrics_demos/artifacts",
    )
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            tools = await session.list_tools()
            print(tools)


if __name__ == "__main__":
    anyio.run(main)
