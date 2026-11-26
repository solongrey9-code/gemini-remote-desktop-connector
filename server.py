import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import subprocess
from uuid import uuid4

from mcp.server.mcpserver import MCPServer
from mcp.types import ToolAnnotations
from pydantic import BaseModel


PROJECT_NAME = "Gemini Remote Desktop Connector"
READ_ONLY = ToolAnnotations(
    read_only_hint=True,
    destructive_hint=False,
    idempotent_hint=True,
    open_world_hint=False,
)


class BridgeReceipt(BaseModel):
    source: str
    request_id: str
    observed_at_utc: str


class Processor(BaseModel):
    name: str
    cores: int
    logical_processors: int


class NvidiaGpu(BaseModel):
    name: str
    vram_mib: int
    driver: str


class WindowsHardware(BridgeReceipt):
    manufacturer: str
    model: str
    windows: str
    windows_build: str
    installed_ram_gib: float | None
    usable_ram_gib: float
    processors: list[Processor]
    nvidia_gpus: list[NvidiaGpu]


def receipt() -> dict[str, str]:
    return {
        "source": "windows-pc-bridge",
        "request_id": uuid4().hex,
        "observed_at_utc": datetime.now(timezone.utc).isoformat(),
    }


def probe_bridge() -> BridgeReceipt:
    """Verify the link by returning a freshly generated request ID and Windows-side UTC timestamp."""
    return BridgeReceipt(**receipt())


def get_windows_hardware() -> WindowsHardware:
    """Read the linked Windows PC's CPU, installed RAM, GPU and Windows build."""
    windows = Path(os.environ.get("SystemRoot", r"C:\Windows"))
    powershell = windows / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
    script = Path(__file__).with_name("hardware.ps1")

    try:
        process = subprocess.run(
            [str(powershell), "-NoProfile", "-NonInteractive", "-File", str(script)],
            capture_output=True,
            check=True,
            timeout=25,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        hardware = json.loads(process.stdout.decode("utf-8"))
        return WindowsHardware(**receipt(), **hardware)
    except (OSError, subprocess.SubprocessError, ValueError) as error:
        raise RuntimeError("Windows hardware query failed. Check the local bridge and its PowerShell execution policy.") from error


def create_server(
    name: str = PROJECT_NAME,
    instructions: str = "Reports live diagnostics for the linked Windows PC.",
    **options,
) -> MCPServer:
    server = MCPServer(
        name,
        instructions=instructions,
        **options,
    )
    server.tool(annotations=READ_ONLY)(probe_bridge)
    server.tool(annotations=READ_ONLY)(get_windows_hardware)
    return server


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run the read-only Windows PC MCP server.")
    parser.add_argument("--stdio", action="store_true", help="Use standard input/output instead of HTTP.")
    parser.add_argument("--port", type=int, default=18769, help="Loopback HTTP port.")
    options = parser.parse_args()
    mcp = create_server()

    if options.stdio:
        mcp.run(transport="stdio")
    else:
        mcp.run(
            transport="streamable-http",
            host="127.0.0.1",
            port=options.port,
            stateless_http=True,
            json_response=True,
        )
