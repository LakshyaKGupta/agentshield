"""Vercel FastAPI entrypoint.

Vercel routes `/api/*` requests to this function. The local AgentShield backend
expects `/v1/*`, `/ready`, and `/health`, so this adapter strips the `/api`
prefix before passing the request to the real ASGI app.
"""

from __future__ import annotations

from backend.app.main import app as agentshield_app


class StripApiPrefix:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope.get("type") in {"http", "websocket"}:
            path = scope.get("path", "")
            if path == "/api":
                scope = {**scope, "path": "/"}
            elif path.startswith("/api/"):
                scope = {**scope, "path": path[4:]}
        await self.app(scope, receive, send)


app = StripApiPrefix(agentshield_app)
