"""aiohttp application factory for the ph-reqKO REST API (FR-15..FR-17)."""

from __future__ import annotations

import asyncio
import json
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

from aiohttp import web

from reqko.api.auth import AuthFailureLimiter, TokenStore
from reqko.config import Config
from reqko.dns.pipeline import QueryEvent
from reqko.filtering.engine import FilterEngine
from reqko.filtering.rules import RuleManager

# Seconds a /health upstream-probe result stays fresh
PROBE_CACHE_TTL = 10.0

PUBLIC_PATHS = frozenset({"/health", "/ready"})
# Everything under /panel is public static content: the files contain no
# data and fetch it client-side with the user's Bearer token.
PUBLIC_PREFIXES = ("/panel",)

SECURITY_HEADERS: dict[str, str] = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Cache-Control": "no-store",
    "Referrer-Policy": "no-referrer",
    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
}

# The panel needs to load its own script/style and call the API on this origin
PANEL_CSP = (
    "default-src 'none'; script-src 'self'; style-src 'self'; "
    "connect-src 'self'; frame-ancestors 'none'"
)

# Signature of the next middleware/handler in the aiohttp chain
Handler = Callable[[web.Request], Awaitable[web.StreamResponse]]


def problem(
    status: int,
    title: str,
    detail: str | None = None,
    problem_type: str = "about:blank",
) -> web.Response:
    """Builds an RFC 7807 problem-details response."""
    body: dict[str, Any] = {"type": problem_type, "title": title, "status": status}
    if detail:
        body["detail"] = detail
    return web.json_response(body, status=status, content_type="application/problem+json")


class ApiProblem(web.HTTPException):
    """Raiseable RFC 7807 problem-details exception for handlers."""

    def __init__(self, status: int, title: str, detail: str | None = None) -> None:
        self.status_code = status
        self.title = title
        self.detail = detail
        body: dict[str, Any] = {"type": "about:blank", "title": title, "status": status}
        if detail:
            body["detail"] = detail
        super().__init__(text=json.dumps(body), content_type="application/problem+json")


@dataclass
class ApiState:
    """Everything the API handlers need, wired once at startup."""

    cfg: Config
    engine: FilterEngine
    rule_manager: RuleManager
    read_conn: Any  # sqlite3.Connection (used from the executor)
    queue: asyncio.Queue[QueryEvent]
    drop_counter: list[int]
    tokens: TokenStore
    auth_limiter: AuthFailureLimiter
    started_at: float = field(default_factory=time.monotonic)
    probe_timeout: float = 1.0
    # Local directories a blocklist file source may live in (path traversal guard)
    allowed_local_dirs: tuple[str, ...] = ()
    probe_cache: dict[str, Any] = field(
        default_factory=lambda: {"ok": False, "checked_at": float("-inf")}
    )
    update_lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    update_task: asyncio.Task[None] | None = None


# Typed application/request keys (aiohttp best practice, silences warnings).
# Defined after ApiState so the AppKey can reference the concrete type.
STATE_KEY: web.AppKey[ApiState] = web.AppKey("state", ApiState)
SCOPE_KEY: web.RequestKey[str] = web.RequestKey("scope", str)


@web.middleware
async def security_headers_middleware(request: web.Request, handler: Handler) -> web.StreamResponse:
    """Adds hardening headers to every response, errors included."""
    response = await handler(request)
    for name, value in SECURITY_HEADERS.items():
        response.headers.setdefault(name, value)
    return response


@web.middleware
async def problem_error_middleware(request: web.Request, handler: Handler) -> web.StreamResponse:
    """Converts unhandled exceptions and HTTPExceptions to RFC 7807 bodies."""
    try:
        return await handler(request)
    except web.HTTPException as exc:
        if isinstance(exc, ApiProblem):
            # Rebuild as a plain Response (returning the exception object
            # itself is deprecated in aiohttp).
            return problem(exc.status_code, exc.title, exc.detail)
        return problem(exc.status_code, exc.reason or "Error")


@web.middleware
async def auth_middleware(request: web.Request, handler: Handler) -> web.StreamResponse:
    """Bearer-token authentication and scope enforcement (FR-17).

    - /health is public.
    - GET requires the "read" or "admin" scope.
    - POST/DELETE require the "admin" scope.
    - Failed attempts are rate limited per client IP (429).
    """
    state: ApiState = request.app[STATE_KEY]
    if request.path in PUBLIC_PATHS or request.path.startswith(PUBLIC_PREFIXES):
        return await handler(request)

    peer = request.remote or "unknown"
    if state.auth_limiter.is_blocked(peer):
        return problem(
            429,
            "Too Many Requests",
            detail="Too many failed authentication attempts; retry later.",
        )

    header = request.headers.get("Authorization", "")
    if not header.startswith("Bearer "):
        state.auth_limiter.record_failure(peer)
        return problem(
            401,
            "Unauthorized",
            detail="Provide the API token as 'Authorization: Bearer <token>'.",
        )
    token = header[len("Bearer ") :].strip()
    scope = state.tokens.scope_for(token)
    if scope is None:
        state.auth_limiter.record_failure(peer)
        return problem(401, "Unauthorized", detail="Unknown or invalid token.")

    needs_admin = request.method in ("POST", "DELETE", "PUT", "PATCH")
    if needs_admin and scope != "admin":
        return problem(
            403,
            "Forbidden",
            detail="This endpoint requires a token with the admin scope.",
        )
    request[SCOPE_KEY] = scope
    return await handler(request)


def create_app(state: ApiState) -> web.Application:
    """Builds the aiohttp application with middlewares and all routes."""
    from reqko.api.routes import register_routes

    app = web.Application(
        middlewares=[
            security_headers_middleware,
            problem_error_middleware,
            auth_middleware,
        ],
        client_max_size=1024 * 1024,
    )
    app[STATE_KEY] = state
    register_routes(app)
    return app


def utcnow_iso() -> str:
    import datetime

    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
