import argparse
import asyncio
import json
from pathlib import Path
import sys

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.client.streamable_http import streamable_http_client


async def verify(read, write, *, after_hardware=None) -> None:
    async with ClientSession(read, write) as session:
        handshake = await session.initialize()
        tools = (await session.list_tools()).tools
        if {tool.name for tool in tools if tool.name in {"probe_bridge", "get_windows_hardware"}} != {
            "probe_bridge", "get_windows_hardware",
        } or (after_hardware is None and len(tools) != 2):
            raise RuntimeError("The bridge exposed an unexpected tool set.")
        if any(
            not tool.annotations or not tool.annotations.read_only_hint
            for tool in tools if tool.name in {"probe_bridge", "get_windows_hardware"}
        ):
            raise RuntimeError("Missing read-only tool annotation.")

        probe = await session.call_tool("probe_bridge", {})
        result = await session.call_tool("get_windows_hardware", {})
        if probe.is_error or result.is_error:
            raise RuntimeError(f"Bridge call failed. Probe={probe.content}; hardware={result.content}")

        hardware = result.structured_content
        if not hardware or not hardware["processors"] or not hardware["installed_ram_gib"]:
            raise RuntimeError("The bridge did not report live hardware.")
        if not probe.structured_content or probe.structured_content["request_id"] == hardware["request_id"]:
            raise RuntimeError("The bridge did not return distinct request IDs.")
        print(json.dumps({
            "protocol_version": handshake.protocol_version,
            "server_name": handshake.server_info.name,
            "hardware": hardware,
        }, ensure_ascii=True, indent=2))
        if after_hardware is not None:
            await after_hardware(session, tools)


async def main(url: str | None) -> None:
    if url:
        async with streamable_http_client(url) as (read, write):
            await verify(read, write)
        return

    parameters = StdioServerParameters(
        command=sys.executable,
        args=[str(Path(__file__).with_name("server.py")), "--stdio"],
    )
    async with stdio_client(parameters) as (read, write):
        await verify(read, write)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Verify discovery and hardware reads using the official MCP client.")
    parser.add_argument("--url", help="Streamable HTTP URL. Omit to test stdio.")
    asyncio.run(main(parser.parse_args().url))
