"""Register workspace tools and serve approvals from a loopback-only page."""

import asyncio
import base64
from dataclasses import dataclass, field
from html import escape
import json
from pathlib import Path
from secrets import compare_digest, token_urlsafe
from time import time
from typing import Literal
from uuid import uuid4

from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import CallToolResult, ImageContent, TextContent, ToolAnnotations
from pydantic import BaseModel
from starlette.requests import Request
from starlette.responses import HTMLResponse, RedirectResponse

from pc_actions import capture_screen, list_processes
from pc_actions import run_powershell as execute_powershell
from server import PROJECT_NAME, READ_ONLY
from workspace_tools import Workspace, WorkspaceError


REVIEW_REQUIRED = ToolAnnotations(
    read_only_hint=False, destructive_hint=True, idempotent_hint=False, open_world_hint=True,
)
JOB_LIMIT = 50
JOB_TTL = 20 * 60


def result_json(payload: dict, *, error: bool = False) -> CallToolResult:
    return CallToolResult(
        is_error=error,
        content=[TextContent(type="text", text=json.dumps(payload, ensure_ascii=False))],
        structured_content=payload,
    )


def run_query(operation, *args) -> CallToolResult:
    try:
        return result_json(operation(*args))
    except WorkspaceError as error:
        return result_json(error.as_dict(), error=True)


@dataclass
class Action:
    id: str
    client_id: str
    kind: str
    details: dict
    created: float = field(default_factory=time)
    state: str = "pending"
    result: dict | None = None
    image: bytes | None = None


class ActionRequest(BaseModel):
    action_id: str
    state: str
    review_url: str
    message: str


class OperatorQueue:
    def __init__(self, workspace: Workspace, root: Path, port: int):
        self.workspace = workspace
        self.root = root
        self.host = f"127.0.0.1:{port}"
        self.review_url = f"http://{self.host}/review"
        self.csrf = token_urlsafe()
        self.actions: dict[str, Action] = {}
        self.tasks: set[asyncio.Task] = set()
        self.serial = asyncio.Semaphore(1)

    def prune(self):
        cutoff = time() - JOB_TTL
        self.actions = {
            key: job for key, job in self.actions.items()
            if job.created >= cutoff or job.state == "running"
        }

    def enqueue(self, kind: str, details: dict) -> ActionRequest:
        self.prune()
        if len(self.actions) >= JOB_LIMIT:
            raise ToolError("The local review queue has reached its capacity.")
        token = get_access_token()
        if token is None:
            raise ToolError("This operation requires an authenticated connection.")
        job = Action(uuid4().hex, token.client_id, kind, details)
        self.actions[job.id] = job
        return ActionRequest(
            action_id=job.id,
            state=job.state,
            review_url=f"{self.review_url}#{job.id}",
            message="Ask the user to review this exact request on the Windows PC.",
        )

    def result(self, action_id: str) -> CallToolResult:
        self.prune()
        token = get_access_token()
        job = self.actions.get(action_id)
        if job is None or token is None or job.client_id != token.client_id:
            return CallToolResult(
                is_error=True,
                content=[TextContent(type="text", text="The action ID is unknown or expired.")],
            )
        payload = {"action_id": job.id, "state": job.state, "result": job.result}
        content = [TextContent(type="text", text=json.dumps(payload, ensure_ascii=False))]
        if job.image is not None:
            content.append(ImageContent(
                type="image", data=base64.b64encode(job.image).decode("ascii"), mime_type="image/jpeg",
            ))
        return CallToolResult(content=content, structured_content=payload)

    def execute(self, job: Action):
        fields = job.details
        if job.kind == "write":
            result = self.workspace.write_text(fields["path"], fields["text"], fields["overwrite"])
        elif job.kind == "mkdir":
            result = self.workspace.create_directory(fields["path"])
        elif job.kind == "move":
            result = self.workspace.move_path(fields["path"], fields["destination"])
        elif job.kind == "powershell":
            result = execute_powershell(fields["command"], self.root, fields["timeout_seconds"])
        elif job.kind == "screenshot":
            job.image, width, height = capture_screen()
            result = {"width": width, "height": height, "mime_type": "image/jpeg"}
        else:
            raise ValueError("Unknown action.")
        return result

    async def finish(self, job: Action):
        async with self.serial:
            try:
                job.result = await asyncio.to_thread(self.execute, job)
            except (OSError, ValueError, RuntimeError, WorkspaceError) as error:
                job.result = {"message": str(error)}
                job.state = "failed"
            else:
                job.state = "completed"

    async def review(self, scope, receive, send):
        request = Request(scope, receive, send)
        headers = {
            "Cache-Control": "no-store",
            "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'",
            "Referrer-Policy": "same-origin",
            "X-Content-Type-Options": "nosniff",
        }
        if request.headers.get("host") != self.host or not request.client or request.client.host != "127.0.0.1":
            await HTMLResponse("Not found.", 404, headers=headers)(scope, receive, send)
            return
        self.prune()
        if request.method == "GET":
            await HTMLResponse(self.render(), headers=headers)(scope, receive, send)
            return
        origin = request.headers.get("origin")
        same_origin = origin == f"http://{self.host}" or (
            origin in (None, "null") and request.headers.get("sec-fetch-site") == "same-origin"
        )
        if (
            request.method != "POST"
            or not same_origin
            or not request.headers.get("content-type", "").startswith("application/x-www-form-urlencoded")
        ):
            await HTMLResponse("Invalid approval request.", 403, headers=headers)(scope, receive, send)
            return
        async with request.form(max_fields=3) as form:
            csrf = form.get("csrf")
            job = self.actions.get(form.get("id"))
            decision = form.get("decision")
        if not isinstance(csrf, str) or not compare_digest(csrf, self.csrf):
            await HTMLResponse("Invalid approval request.", 403, headers=headers)(scope, receive, send)
            return
        if job is None or job.state != "pending" or decision not in {"approve", "deny"}:
            await HTMLResponse("The request has expired or has already been reviewed.", 409, headers=headers)(scope, receive, send)
            return
        job.state = "denied"
        if decision == "approve":
            job.state = "running"
            task = asyncio.create_task(self.finish(job))
            self.tasks.add(task)
            task.add_done_callback(self.tasks.discard)
        await RedirectResponse(f"/review#{job.id}", 303, headers=headers)(scope, receive, send)

    def render(self) -> str:
        status = {"pending": "Pending", "denied": "Denied", "running": "Running", "completed": "Completed", "failed": "Failed"}
        entries = []
        for job in reversed(list(self.actions.values())):
            details = escape(json.dumps(job.details, ensure_ascii=False, indent=2))
            review = ""
            result = ""
            if job.state == "pending":
                review = f"""
                <form method="post" action="/review">
                    <input type="hidden" name="csrf" value="{self.csrf}">
                    <input type="hidden" name="id" value="{job.id}">
                    <button name="decision" value="approve">Approve and run</button>
                    <button name="decision" value="deny" class="secondary">Deny</button>
                </form>"""
            if job.result is not None:
                output = escape(json.dumps(job.result, ensure_ascii=False, indent=2))
                result = f"<details><summary>Output</summary><pre>{output}</pre></details>"
            entries.append(f"""
            <article id="{job.id}">
                <h2>{escape(job.kind)} <span>{status[job.state]}</span></h2>
                <p class="id">{job.id}</p><pre>{details}</pre>{review}{result}
            </article>""")
        jobs = "".join(entries) or "<p>No requests to review.</p>"
        return f"""<!doctype html>
        <html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
        <title>{PROJECT_NAME} · Local approval</title>
        <style>
          * {{box-sizing:border-box}}
          body {{background:#f3f5f7;color:#182736;font:16px/1.55 system-ui,sans-serif;margin:0}}
          main {{max-width:780px;margin:auto;padding:clamp(20px,6vw,64px) 20px}}
          h1 {{font-size:clamp(26px,6vw,39px);line-height:1.15;margin:0 0 12px}}
          h2 {{font-size:19px;margin:0}}
          h2 span {{color:#2d5064;font-size:14px;font-weight:600;margin-left:8px}}
          article {{background:white;border:1px solid #d7e0e7;border-radius:14px;padding:20px;margin:15px 0}}
          article:target {{border-color:#1c6175;outline:2px solid #1c6175}}
          .id {{font:13px ui-monospace,monospace;color:#4b6170;overflow-wrap:anywhere}}
          pre {{background:#edf2f5;padding:12px;max-height:20em;overflow:auto;white-space:pre-wrap;overflow-wrap:anywhere}}
          button,a {{font:inherit;font-weight:600}}
          button {{background:#154e60;color:white;border:1px solid #154e60;border-radius:8px;padding:8px 12px;cursor:pointer;margin-right:8px}}
          .secondary {{background:white;color:#154e60}}
          a {{color:#154e60}}
          :focus-visible {{outline:3px solid #a33f00;outline-offset:3px}}
        </style>
        <main><h1>Local approvals</h1>
        <p>{PROJECT_NAME} · <a href="/review">Refresh</a></p>{jobs}</main></html>"""


def register_workspace(server, root: Path, port: int):
    root = root.resolve(strict=True)
    workspace = Workspace(root)
    queue = OperatorQueue(workspace, root, port)

    @server.tool(annotations=READ_ONLY)
    def list_directory(path: str = ".", limit: int = 100) -> CallToolResult:
        """List the files and subdirectories inside a relative workspace path."""
        return run_query(workspace.list_directory, path, limit)

    @server.tool(annotations=READ_ONLY)
    def get_file_info(path: str) -> CallToolResult:
        """Read metadata for one workspace file or directory."""
        return run_query(workspace.get_file_info, path)

    @server.tool(annotations=READ_ONLY)
    def read_file(path: str, start_line: int = 1, max_lines: int = 200) -> CallToolResult:
        """Read the requested range of lines from a UTF-8 workspace file."""
        return run_query(workspace.read_text, path, start_line, max_lines)

    @server.tool(annotations=READ_ONLY)
    def search_text(query: str, path: str = ".", limit: int = 50) -> CallToolResult:
        """Find a literal string within workspace text files."""
        return run_query(workspace.search_text, query, path, limit)

    @server.tool(name="list_processes", annotations=READ_ONLY)
    def list_running_processes(query: str = "", limit: int = 100) -> CallToolResult:
        """List Windows executable names and PIDs, optionally filtered by name."""
        return run_query(list_processes, query, limit)

    @server.tool(annotations=REVIEW_REQUIRED)
    async def request_file_change(
        operation: Literal["write", "mkdir", "move"], path: str, text: str | None = None,
        destination: str | None = None, overwrite: bool = False,
    ) -> ActionRequest:
        """Request a workspace file write, directory creation or move for local approval."""
        if not path or len(path) > 1024:
            raise ToolError("Provide a relative workspace path.")
        if operation == "write":
            if text is None or len(text.encode("utf-8")) > 1024 * 1024:
                raise ToolError("A write requires UTF-8 text of at most 1 MiB.")
            details = {"path": path, "text": text, "overwrite": overwrite}
        elif operation == "move":
            if not destination or len(destination) > 1024:
                raise ToolError("A move requires a relative workspace destination.")
            details = {"path": path, "destination": destination}
        else:
            details = {"path": path}
        return queue.enqueue(operation, details)

    @server.tool(annotations=REVIEW_REQUIRED)
    async def request_powershell(command: str, timeout_seconds: int = 30) -> ActionRequest:
        """Propose an exact PowerShell command, run only if locally approved, from the workspace."""
        if not command.strip() or len(command) > 4096 or not 1 <= timeout_seconds <= 120:
            raise ToolError("Use a command of 1–4096 characters and a timeout of 1–120 seconds.")
        return queue.enqueue("powershell", {"command": command, "timeout_seconds": timeout_seconds})

    @server.tool(annotations=REVIEW_REQUIRED)
    async def request_screenshot() -> ActionRequest:
        """Request permission to capture the current Windows primary display and return the image."""
        return queue.enqueue("screenshot", {"display": "primary"})

    @server.tool(annotations=READ_ONLY)
    async def get_action_result(action_id: str) -> CallToolResult:
        """Check a locally reviewed request and retrieve its command output or approved screenshot."""
        return queue.result(action_id)

    return queue.review
