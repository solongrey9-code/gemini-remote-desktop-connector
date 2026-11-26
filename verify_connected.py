"""Verify Gemini-style OAuth discovery and authorized MCP calls without contacting Google."""

import argparse
import asyncio
import base64
from hashlib import sha256
from pathlib import Path
import re
from secrets import token_urlsafe
from urllib.parse import parse_qs, urlsplit

from httpx2 import AsyncClient
from mcp.client.streamable_http import streamable_http_client

from connected import APPROVALS, PREFIX
from verify import verify


async def verify_workspace(session, tools, review_origin, local_workspace):
    assert {tool.name for tool in tools} == {
        "probe_bridge", "get_windows_hardware", "get_file_info", "list_directory", "read_file",
        "search_text", "list_processes", "request_file_change", "request_powershell",
        "request_screenshot", "get_action_result",
    }
    assert (await session.call_tool("list_directory", {"path": ".."})).is_error
    assert not (await session.call_tool("list_processes", {"limit": 2})).is_error

    async def request(tool, arguments):
        result = await session.call_tool(tool, arguments)
        assert not result.is_error, result.content
        return result.structured_content

    async def status(action_id):
        return await request("get_action_result", {"action_id": action_id})

    async def review(action_id, decision):
        async with AsyncClient(base_url=review_origin, timeout=10, trust_env=False) as local:
            html = (await local.get("/review")).raise_for_status().text
            csrf = re.search(r'name="csrf" value="([^"]+)"', html).group(1)
            data = {"csrf": csrf, "id": action_id, "decision": decision}
            assert (await local.post("/review", data=data)).status_code == 403
            success = await local.post("/review", data=data, headers={"Origin": review_origin})
            assert success.status_code == 303

    async def wait_for(action_id):
        for _ in range(40):
            result = await status(action_id)
            if result["state"] not in {"pending", "running"}:
                return result
            await asyncio.sleep(0.25)
        raise AssertionError("Approved workspace action timed out")

    path = f"bridge-smoke-{token_urlsafe(5)}.txt"
    marker = "Gemini workspace write and read-back."
    write = await request("request_file_change", {"operation": "write", "path": path, "text": marker})
    assert (await status(write["action_id"]))["state"] == "pending"
    assert (await session.call_tool("read_file", {"path": path})).is_error
    await review(write["action_id"], "approve")
    assert (await wait_for(write["action_id"]))["state"] == "completed"
    assert marker in str(await request("read_file", {"path": path}))
    test_file = local_workspace / path
    assert test_file.read_text(encoding="utf-8") == marker
    test_file.unlink()

    command = await request("request_powershell", {"command": "Write-Output 'gemini_powershell_e2e'"})
    await review(command["action_id"], "approve")
    output = await wait_for(command["action_id"])
    assert output["state"] == "completed" and "gemini_powershell_e2e" in str(output["result"])

    screenshot = await request("request_screenshot", {})
    await review(screenshot["action_id"], "deny")
    assert (await status(screenshot["action_id"]))["state"] == "denied"
    print(f"Workspace read/write, PowerShell and screenshot denial passed. Test file {path}.")


async def main(base, prefix, review_origin, local_workspace):
    async with AsyncClient(base_url=base, timeout=30, trust_env=False) as client:
        endpoint = f"{prefix}/mcp"
        body = {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
        if local_workspace:
            standalone = await client.get(endpoint, headers={"Accept": "text/event-stream"})
            assert standalone.status_code == 405
            assert (await client.get(f"{prefix}/review")).status_code == 404
            if urlsplit(base).hostname == "127.0.0.1":
                review_authority = urlsplit(review_origin).netloc
                assert (await client.get("/review", headers={"Host": review_authority})).status_code == 404
            async with AsyncClient(base_url=review_origin, timeout=5, trust_env=False) as local:
                assert (await local.get(endpoint)).status_code == 404
        denied = await client.post(endpoint, json=body)
        assert denied.status_code == 401
        assert "resource_metadata" in denied.headers["WWW-Authenticate"]
        metadata = (await client.get(f"/.well-known/oauth-protected-resource{endpoint}")).json()
        issuer = metadata["authorization_servers"][0]
        assert metadata["resource"] == f"{issuer}/mcp"
        discovery = (await client.get(f"/.well-known/oauth-authorization-server{prefix}")).json()
        assert discovery["issuer"] == issuer
        assert discovery["code_challenge_methods_supported"] == ["S256"]

        redirect_uri = "https://oauth-redirect-test.googleusercontent.com/r/pc-bridge-smoke"
        registration = {
            "redirect_uris": [redirect_uri],
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "client_secret_post",
        }
        register = f"{prefix}/register"
        untrusted = {**registration, "redirect_uris": ["https://example.invalid/callback"]}
        assert (await client.post(register, json=untrusted)).status_code == 400
        registered = await client.post(register, json=registration)
        if registered.status_code == 400 and "pairing window" in registered.text:
            raise RuntimeError("Open a local pairing window with pair-workspace.ps1 -Open before this test.")
        info = registered.raise_for_status().json()
        credentials = {"client_id": info["client_id"], "client_secret": info["client_secret"]}

        verifier = token_urlsafe(48)
        challenge = base64.urlsafe_b64encode(sha256(verifier.encode()).digest()).decode().rstrip("=")
        consent = await client.get(f"{prefix}/authorize", params={
            "client_id": info["client_id"],
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "state": "smoke-test",
            "scope": "pc.read",
            "resource": metadata["resource"],
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        })
        assert consent.status_code == 302
        consent_url = urlsplit(consent.headers["location"])
        path = f"{consent_url.path}?{consent_url.query}"
        assert (await client.post(path)).status_code == 200
        request_id = parse_qs(consent_url.query)["id"][0]
        approval = APPROVALS / request_id
        approval.touch(exist_ok=False)
        try:
            callback = await client.post(path)
        finally:
            approval.unlink(missing_ok=True)
        assert callback.status_code == 303
        result = parse_qs(urlsplit(callback.headers["location"]).query)
        assert result["state"] == ["smoke-test"]
        grant = {
            **credentials, "grant_type": "authorization_code", "code": result["code"][0],
            "redirect_uri": redirect_uri, "code_verifier": verifier, "resource": metadata["resource"],
        }
        token_path = f"{prefix}/token"
        tokens = (await client.post(token_path, data=grant)).raise_for_status().json()
        assert (await client.post(token_path, data=grant)).status_code == 400

        client.headers["Authorization"] = f"Bearer {tokens['access_token']}"
        async with streamable_http_client(base + endpoint, http_client=client) as (read, write):
            async def check_workspace(session, tools):
                await verify_workspace(session, tools, review_origin, local_workspace)

            await verify(read, write, after_hardware=check_workspace if local_workspace else None)

        refresh = {**credentials, "grant_type": "refresh_token", "refresh_token": tokens["refresh_token"]}
        fresh = (await client.post(token_path, data=refresh)).raise_for_status().json()
        assert fresh["refresh_token"] != tokens["refresh_token"]
        assert (await client.post(token_path, data=refresh)).status_code == 400
        revoke = f"{prefix}/revoke"
        (await client.post(revoke, data={**credentials, "token": fresh["refresh_token"]})).raise_for_status()
        for token in (tokens["access_token"], fresh["access_token"]):
            assert (await client.post(endpoint, json=body, headers={"Authorization": f"Bearer {token}"})).status_code == 401
        print("OAuth discovery, consent, authorization code, refresh rotation and revocation passed.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("base", nargs="?", default="http://127.0.0.1:18772")
    parser.add_argument("--prefix", default=PREFIX)
    parser.add_argument("--review-origin", default="http://127.0.0.1:18773")
    parser.add_argument("--local-workspace", type=Path)
    options = parser.parse_args()
    asyncio.run(main(options.base, options.prefix, options.review_origin, options.local_workspace))
