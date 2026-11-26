"""Run an OAuth-protected Gemini Connected App behind a dedicated HTTPS proxy."""

import argparse
from contextlib import ExitStack
from html import escape
from pathlib import Path
import re
from secrets import token_urlsafe
import socket
from time import time
from urllib.parse import urlencode, urlsplit

from mcp.server.auth.provider import (
    AccessToken, AuthorizationCode, AuthorizeError, RefreshToken, RegistrationError,
    TokenError, construct_redirect_uri,
)
from mcp.server.auth.settings import AuthSettings, ClientRegistrationOptions, RevocationOptions
from mcp.server.transport_security import TransportSecuritySettings
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken
from starlette.responses import HTMLResponse, RedirectResponse, Response
import uvicorn

from server import create_server
from oauth_state import OAuthState


SCOPE = "pc.read"
PREFIX = "/gemini-pc"
RUNTIME = Path(__file__).with_name(".bridge")
APPROVALS = RUNTIME / "approvals"
ENROLLMENT = RUNTIME / "enrollment"
GOOGLE_CALLBACKS = {
    "oauth-redirect.googleusercontent.com",
    "oauth-redirect-sandbox.googleusercontent.com",
    "oauth-redirect-test.googleusercontent.com",
}
PAIR_ID = re.compile(r"[\w-]{32}", re.ASCII)
ACCESS_SECONDS = 3600
REFRESH_SECONDS = 30 * 24 * 3600
PAIRING_SECONDS = 15 * 60


def enrollment_open() -> bool:
    try:
        with ENROLLMENT.open(encoding="ascii") as marker:
            deadline = int(marker.read(32).strip())
    except (OSError, ValueError):
        return False
    return 0 < deadline - time() <= PAIRING_SECONDS


class Provider:
    def __init__(self, issuer, state_file=None):
        self.issuer = issuer
        self.resource = issuer + "/mcp"
        self.state = OAuthState(state_file, self.resource) if state_file else None
        stored = self.state.read() if self.state else {}
        self.clients = {
            key: OAuthClientInformationFull.model_validate(item)
            for key, item in stored.get("clients", {}).items()
        }
        self.pending = {}
        self.codes = {}
        self.access = {key: AccessToken.model_validate(item) for key, item in stored.get("access", {}).items()}
        self.refresh = {key: RefreshToken.model_validate(item) for key, item in stored.get("refresh", {}).items()}

    def save(self):
        if self.state:
            self.state.write(clients=self.clients, access=self.access, refresh=self.refresh)

    async def get_client(self, client_id):
        return self.clients.get(client_id)

    async def register_client(self, client_info):
        if not enrollment_open():
            raise RegistrationError("unapproved_software_statement", "Open a pairing window on the Windows PC.")
        for uri in client_info.redirect_uris or ():
            url = urlsplit(str(uri))
            if url.scheme != "https" or url.netloc not in GOOGLE_CALLBACKS or not url.path.startswith(("/r/", "/a/")):
                raise RegistrationError("invalid_redirect_uri", "Only Gemini OAuth callbacks are accepted.")
        now = time()
        active = {
            token.client_id for token in (*self.access.values(), *self.refresh.values())
            if token.expires_at > now
        }
        self.clients = {
            key: client for key, client in self.clients.items()
            if key in active or (client.client_id_issued_at or 0) + PAIRING_SECONDS > now
        }
        if not client_info.redirect_uris or len(self.clients) >= 64:
            raise RegistrationError("invalid_client_metadata", "Missing callback or registration capacity reached.")
        self.clients[client_info.client_id] = client_info
        self.save()

    async def authorize(self, client, params):
        if not enrollment_open():
            raise AuthorizeError("access_denied", "Open a pairing window on the Windows PC.")
        if params.resource not in (None, self.resource):
            raise AuthorizeError("invalid_request", "Unexpected MCP resource.")
        self.pending = {key: value for key, value in self.pending.items() if value[0].expires_at > time()}
        if len(self.pending) >= 32:
            raise AuthorizeError("server_error", "Too many pending pairing requests.")
        pairing_id = token_urlsafe(24)
        code = AuthorizationCode(
            code=token_urlsafe(32),
            scopes=params.scopes or [SCOPE],
            expires_at=time() + PAIRING_SECONDS,
            client_id=client.client_id,
            code_challenge=params.code_challenge,
            redirect_uri=params.redirect_uri,
            redirect_uri_provided_explicitly=params.redirect_uri_provided_explicitly,
            resource=params.resource,
        )
        self.pending[pairing_id] = (code, params.state)
        return f"{self.issuer}/pair?{urlencode({'id': pairing_id})}"

    async def load_authorization_code(self, client, authorization_code):
        code = self.codes.get(authorization_code)
        if code and code.client_id == client.client_id and code.expires_at > time():
            return code
        return None

    async def exchange_authorization_code(self, client, authorization_code):
        if self.codes.pop(authorization_code.code, None) is None:
            raise TokenError("invalid_grant", "Authorization code already used.")
        return self.issue(client.client_id, authorization_code.scopes, int(time()) + REFRESH_SECONDS)

    async def load_refresh_token(self, client, refresh_token):
        token = self.refresh.get(refresh_token)
        if token and token.client_id == client.client_id and token.expires_at > time():
            return token
        return None

    async def exchange_refresh_token(self, client, refresh_token, scopes):
        if self.refresh.pop(refresh_token.token, None) is None:
            raise TokenError("invalid_grant", "Refresh token already used.")
        return self.issue(client.client_id, scopes or refresh_token.scopes, int(time()) + REFRESH_SECONDS)

    async def load_access_token(self, token):
        access = self.access.get(token)
        return access if access and access.expires_at > time() else None

    async def revoke_token(self, token):
        self.access.pop(token.token, None)
        if self.refresh.pop(token.token, None) is not None:
            self.access = {key: item for key, item in self.access.items() if item.client_id != token.client_id}
            self.refresh = {key: item for key, item in self.refresh.items() if item.client_id != token.client_id}
        self.save()

    def issue(self, client_id, scopes, refresh_expiry):
        now = int(time())
        self.access = {key: value for key, value in self.access.items() if value.expires_at > now}
        self.refresh = {key: value for key, value in self.refresh.items() if value.expires_at > now}
        access = AccessToken(
            token=token_urlsafe(32), client_id=client_id, scopes=scopes,
            expires_at=now + ACCESS_SECONDS, resource=self.resource,
        )
        refresh = RefreshToken(
            token=token_urlsafe(32), client_id=client_id, scopes=scopes,
            expires_at=refresh_expiry, resource=self.resource,
        )
        self.access[access.token] = access
        self.refresh[refresh.token] = refresh
        self.save()
        return OAuthToken(
            access_token=access.token, expires_in=ACCESS_SECONDS,
            refresh_token=refresh.token, scope=" ".join(scopes),
        )


def connected_app(
    origin, *, prefix=PREFIX, state_file=None, workspace=None, port=18772, review_port=18773, trace=None,
):
    issuer = origin + prefix
    provider = Provider(issuer, state_file)
    server = create_server(
        name="Gemini PC Bridge",
        instructions=(
            "Accesses the linked Windows PC for hardware, workspace files and process diagnostics. "
            "File changes, shell commands and screen captures wait for an exact local approval."
        ) if workspace else "Reports live diagnostics for the linked Windows PC.",
        auth_server_provider=provider,
        auth=AuthSettings(
            issuer_url=issuer,
            resource_server_url=provider.resource,
            validate_token_resource=True,
            required_scopes=[SCOPE],
            client_registration_options=ClientRegistrationOptions(
                enabled=True, default_scopes=[SCOPE], valid_scopes=[SCOPE],
            ),
            revocation_options=RevocationOptions(enabled=True),
        ),
    )
    review = None
    permissions = "Gemini can check the connection and read the CPU, RAM, GPU and Windows build."
    if workspace:
        from operator_tools import register_workspace

        review = register_workspace(server, workspace, review_port)
        permissions = (
            "Gemini can read hardware details, process names and files in the dedicated workspace. "
            "File changes, PowerShell commands and screenshots require approval on Windows."
        )

    @server.custom_route("/pair", methods=["GET", "POST"])
    async def pair(request):
        pairing_id = request.query_params.get("id", "")
        callbacks = " ".join(f"https://{host}" for host in sorted(GOOGLE_CALLBACKS))
        headers = {
            "Cache-Control": "no-store",
            "Content-Security-Policy": f"default-src 'none'; form-action 'self' {callbacks} "
            "https://gemini.google.com https://accounts.google.com; frame-ancestors 'none'",
            "Referrer-Policy": "no-referrer",
        }
        pending = provider.pending.get(pairing_id) if PAIR_ID.fullmatch(pairing_id) else None
        if not enrollment_open() or pending is None or pending[0].expires_at <= time():
            return HTMLResponse("Pairing request expired.", status_code=404, headers=headers)
        code, state = pending
        marker = APPROVALS / pairing_id
        if request.method == "POST" and marker.is_file():
            marker.unlink()
            provider.pending.pop(pairing_id)
            provider.codes = {key: value for key, value in provider.codes.items() if value.expires_at > time()}
            code.expires_at = time() + 90
            provider.codes[code.code] = code
            return RedirectResponse(
                construct_redirect_uri(str(code.redirect_uri), code=code.code, state=state),
                status_code=303,
                headers=headers,
            )

        return HTMLResponse(
            '<!doctype html><html lang="en"><meta charset="utf-8"><title>Gemini PC Bridge</title>'
            '<main><h1>Connect Gemini PC Bridge</h1>'
            f'<p>{escape(permissions)}</p>'
            f'<p>Approve this pairing on your Windows PC. Request ID <code>{escape(pairing_id)}</code>.</p>'
            f'<form method="post" action="{prefix}/pair?id={escape(pairing_id)}">'
            '<button type="submit">Finish linking</button></form></main></html>',
            headers=headers,
        )

    host = urlsplit(origin).netloc
    app = server.streamable_http_app(
        stateless_http=True, json_response=True,
        transport_security=TransportSecuritySettings(
            allowed_hosts=[host, "127.0.0.1:*"],
            allowed_origins=["https://gemini.google.com", origin],
        ),
    )
    aliases = {
        prefix + path: path for path in ("/mcp", "/authorize", "/register", "/token", "/revoke", "/pair")
    }
    aliases["/.well-known/oauth-authorization-server" + prefix] = "/.well-known/oauth-authorization-server"
    aliases[prefix + "/.well-known/oauth-authorization-server"] = "/.well-known/oauth-authorization-server"
    protected = "/.well-known/oauth-protected-resource" + prefix + "/mcp"

    async def transport(scope, receive, send):
        if scope["path"] == "/mcp" and scope["method"] == "GET":
            # This stateless endpoint has no standalone server-to-client stream.
            await Response(status_code=405, headers={"Allow": "POST"})(scope, receive, send)
            return
        await app(scope, receive, send)

    async def routed(scope, receive, send):
        if scope["type"] == "http":
            path = scope["path"]
            local_port = scope["server"][1] if scope["server"] else None
            if local_port != port:
                if review and local_port == review_port and path == "/review":
                    await review(scope, receive, send)
                else:
                    await HTMLResponse("Not found.", status_code=404)(scope, receive, send)
                return
            if path not in aliases and path != protected:
                await HTMLResponse("Not found.", status_code=404)(scope, receive, send)
                return
            scope = {**scope, "path": aliases.get(path, path)}
            if trace and scope["path"] == "/mcp":
                await trace.handle(transport, scope, receive, send)
                return
            if scope["path"] == "/mcp":
                await transport(scope, receive, send)
                return
        await app(scope, receive, send)

    return routed


def serve(app, ports: tuple[int, ...]) -> None:
    with ExitStack() as stack:
        listeners = []
        for port in ports:
            listener = stack.enter_context(socket.socket())
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
            listener.bind(("127.0.0.1", port))
            listener.listen()
            listeners.append(listener)
        server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=ports[0], access_log=False))
        server.run(sockets=listeners)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--origin", required=True, help="Public HTTPS origin of the proxy.")
    parser.add_argument("--port", type=int, default=18772)
    parser.add_argument("--review-port", type=int, default=18773)
    parser.add_argument("--prefix", default=PREFIX)
    parser.add_argument("--state-file", type=Path, default=RUNTIME / "oauth.dpapi")
    parser.add_argument("--trace-file", type=Path)
    parser.add_argument("--workspace", type=Path, help="Enable file, process and locally reviewed desktop tools.")
    args = parser.parse_args()
    parsed = urlsplit(args.origin)
    if parsed.scheme != "https" or not parsed.hostname or parsed.path or parsed.query or parsed.fragment or parsed.username:
        parser.error("--origin must be a bare HTTPS origin, without a path or credentials.")
    if not re.fullmatch(r"/[a-z0-9-]+", args.prefix):
        parser.error("--prefix must consist of / followed by lowercase letters, digits or hyphens.")
    if not (1 <= args.port <= 65535 and 1 <= args.review_port <= 65535) or args.port == args.review_port:
        parser.error("Use distinct TCP ports for MCP traffic and local approvals.")
    APPROVALS.mkdir(parents=True, exist_ok=True)
    trace = None
    if args.trace_file:
        from mcp_trace import MCPTrace

        trace = MCPTrace(args.trace_file)
    app = connected_app(
        args.origin, prefix=args.prefix, state_file=args.state_file, workspace=args.workspace,
        port=args.port, review_port=args.review_port, trace=trace,
    )
    ports = (args.port, args.review_port) if args.workspace else (args.port,)
    serve(app, ports)
