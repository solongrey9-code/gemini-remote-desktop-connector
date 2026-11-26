"""Log MCP request outcomes without recording arguments, results or credentials."""

from datetime import datetime, timezone
import json
import logging
from logging.handlers import RotatingFileHandler
import re


class MCPTrace:
    def __init__(self, path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.log = logging.getLogger("workspace.mcp")
        self.log.propagate = False
        self.log.setLevel(logging.INFO)
        self.log.addHandler(RotatingFileHandler(path, maxBytes=262144, backupCount=1, encoding="utf-8"))

    async def handle(self, app, scope, receive, send):
        request = bytearray()
        captured = True
        status = None

        async def observe_receive():
            nonlocal captured
            message = await receive()
            if message["type"] == "http.request" and captured:
                body = message.get("body", b"")
                if len(request) + len(body) > 32768:
                    captured = False
                    request.clear()
                else:
                    request.extend(body)
            return message

        async def observe_send(message):
            nonlocal status
            if message["type"] == "http.response.start":
                status = message["status"]
            await send(message)

        try:
            await app(scope, observe_receive, observe_send)
        finally:
            self.write(scope, status, request)

    def write(self, scope, status, request):
        headers = dict(scope["headers"])
        event = {
            "at": datetime.now(timezone.utc).isoformat(),
            "method": scope["method"],
            "status": status,
            "authorization_present": b"authorization" in headers,
            "origin_present": b"origin" in headers,
        }
        try:
            payload = json.loads(request)
        except (UnicodeDecodeError, ValueError):
            payload = {}
        if isinstance(payload, dict):
            method = payload.get("method")
            if isinstance(method, str) and re.fullmatch(r"[a-zA-Z/]{1,40}", method):
                event["rpc"] = method
            arguments = payload.get("params")
            if method == "tools/call" and isinstance(arguments, dict):
                tool = arguments.get("name")
                if isinstance(tool, str) and re.fullmatch(r"[a-z_]{1,50}", tool):
                    event["tool"] = tool
        self.log.info(json.dumps(event))
