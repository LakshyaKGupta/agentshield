"""
backend/app/security/session.py
────────────────────────────────
httpOnly session cookie + CSRF double-submit cookie protection.

Session flow
------------
1. On login/signup the backend calls ``create_session(response, api_key)`` which:
   - Generates a cryptographically-random ``session_id``.
   - Stores ``{session_id: api_key}`` in the in-process session store
     (or Redis when REDIS_URL is configured).
   - Sets two cookies on the response:
       • ``session``   — httpOnly, Secure (prod), SameSite=Lax.
       • ``csrf_token`` — readable by JS (no httpOnly), SameSite=Strict.
2. Protected mutating endpoints call ``require_session_or_key(request)`` which
   accepts either the X-AgentShield-API-Key header OR a valid session cookie.
   When the session cookie is present, it additionally validates the
   X-CSRF-Token header matches the csrf_token cookie.
3. ``rotate_session(request, response)`` issues a new session_id and
   invalidates the old one — call this after any privilege change.
4. ``delete_session(request, response)`` clears both cookies on logout.

CSRF protection
---------------
The double-submit cookie pattern:
- Backend sets ``csrf_token`` cookie (not httpOnly → JS can read it).
- Frontend reads the cookie value and echoes it in X-CSRF-Token header.
- Backend compares cookie value == header value using ``secrets.compare_digest``.
- An attacker's cross-origin form submit cannot read the cookie (SameSite=Strict)
  so the header will be missing, blocking the request.
"""
from __future__ import annotations

import secrets
import time
from datetime import datetime, timezone
from typing import Any

from fastapi import Cookie, Header, Request, Response
from fastapi.exceptions import HTTPException
from fastapi.params import Cookie as CookieParam
from fastapi.params import Header as HeaderParam

# ── Session store ──────────────────────────────────────────────────
# In-process dict maps session_id → (api_key_raw, created_at_unix)
# When Redis is configured the session is also written there for
# multi-instance consistency (fail-open: local store is fallback).

_SESSION_STORE: dict[str, tuple[str | None, float, str | None]] = {}
_SESSION_TTL_SECONDS = 60 * 60 * 24 * 7  # 7 days
_CSRF_COOKIE = "csrf_token"
_SESSION_COOKIE = "session"

try:
    import redis as _redis_lib  # type: ignore
    _REDIS_AVAILABLE = True
except ImportError:
    _REDIS_AVAILABLE = False

_redis_client: Any = None
_database_url: str | None = None


def configure_redis(redis_url: str | None) -> None:  # called from main startup
    global _redis_client
    if redis_url and _REDIS_AVAILABLE:
        try:
            import redis  # type: ignore
            pool = redis.ConnectionPool.from_url(
                redis_url, max_connections=20, socket_timeout=2.0
            )
            _redis_client = redis.Redis(connection_pool=pool)
            _redis_client.ping()
        except Exception as exc:
            print(f"[session] Redis unavailable ({exc}); using in-process session store")
            _redis_client = None


_pool: Any = None


def configure_postgres(database_url: str | None) -> None:
    global _database_url, _pool
    _database_url = database_url
    if database_url:
        try:
            from psycopg_pool import ConnectionPool
            _pool = ConnectionPool(conninfo=database_url, min_size=1, max_size=5)
        except Exception as exc:
            print(f"[session] Failed to initialize Postgres ConnectionPool: {exc}")
            _pool = None


# ── Cookie helpers ─────────────────────────────────────────────────

def _is_secure(request: Request) -> bool:
    """Return True only when running behind HTTPS."""
    proto = request.headers.get("x-forwarded-proto", "http")
    return proto == "https"


def _set_session_cookies(
    response: Response,
    session_id: str,
    csrf_token: str,
    secure: bool,
) -> None:
    response.set_cookie(
        key=_SESSION_COOKIE,
        value=session_id,
        httponly=True,
        samesite="lax",
        secure=secure,
        max_age=_SESSION_TTL_SECONDS,
        path="/",
    )
    response.set_cookie(
        key=_CSRF_COOKIE,
        value=csrf_token,
        httponly=False,        # must be JS-readable for the double-submit pattern
        samesite="strict",
        secure=secure,
        max_age=_SESSION_TTL_SECONDS,
        path="/",
    )


def _clear_session_cookies(response: Response) -> None:
    response.delete_cookie(_SESSION_COOKIE, path="/")
    response.delete_cookie(_CSRF_COOKIE, path="/")


# ── Session CRUD ───────────────────────────────────────────────────

def create_session(response: Response, request: Request, api_key_raw: str | None, api_key_hash: str | None = None) -> str:
    """
    Persist a new session and write both cookies onto *response*.
    Returns the session_id (for testing convenience).
    """
    session_id = secrets.token_urlsafe(32)
    csrf_token = secrets.token_urlsafe(24)
    now = time.time()

    # Local store
    _SESSION_STORE[session_id] = (api_key_raw, now, api_key_hash)

    # Redis (best-effort)
    if _redis_client is not None:
        try:
            import json
            _redis_client.setex(
                f"session:{session_id}",
                _SESSION_TTL_SECONDS,
                json.dumps({"api_key": api_key_raw, "api_key_hash": api_key_hash, "csrf_token": csrf_token, "created_at": now}),
            )
        except Exception:
            pass  # local store is canonical fallback

    if _database_url and api_key_hash:
        try:
            expires_at = datetime.fromtimestamp(now + _SESSION_TTL_SECONDS, tz=timezone.utc)
            if _pool is not None:
                ctx = _pool.connection()
            else:
                import psycopg
                ctx = psycopg.connect(_database_url)
            with ctx as conn:
                conn.execute(
                    """
                    INSERT INTO browser_sessions (session_id, api_key_hash, csrf_token, created_at, expires_at)
                    VALUES (%s, %s, %s, %s, %s)
                    ON CONFLICT (session_id) DO UPDATE SET
                        api_key_hash = EXCLUDED.api_key_hash,
                        csrf_token = EXCLUDED.csrf_token,
                        expires_at = EXCLUDED.expires_at
                    """,
                    (session_id, api_key_hash, csrf_token, datetime.fromtimestamp(now, tz=timezone.utc), expires_at),
                )
                conn.commit()
        except Exception:
            pass

    _set_session_cookies(response, session_id, csrf_token, _is_secure(request))
    return session_id


def rotate_session(request: Request, response: Response) -> str | None:
    """
    Invalidate the current session cookie and issue a fresh one.
    Returns the raw API key if the old session was valid, else None.
    """
    old_sid = request.cookies.get(_SESSION_COOKIE)
    if not old_sid:
        return None

    api_key_raw, _created = _resolve_session_id(old_sid)
    api_key_hash = _resolve_session_hash(old_sid)
    if api_key_raw is None:
        if api_key_hash is None:
            return None

    # Invalidate old
    _invalidate(old_sid)

    # Create new
    create_session(response, request, api_key_raw, api_key_hash=api_key_hash)
    return api_key_raw or api_key_hash


def delete_session(request: Request, response: Response) -> None:
    """Clear session from store and delete cookies."""
    sid = request.cookies.get(_SESSION_COOKIE)
    if sid:
        _invalidate(sid)
    _clear_session_cookies(response)


def _resolve_session_id(session_id: str) -> tuple[str | None, float | None]:
    """Return (api_key_raw, created_at) or (None, None)."""
    # Try Redis first
    if _redis_client is not None:
        try:
            import json
            raw = _redis_client.get(f"session:{session_id}")
            if raw:
                data = json.loads(raw)
                return data.get("api_key"), data.get("created_at")
        except Exception:
            pass

    # Fallback to local store
    entry = _SESSION_STORE.get(session_id)
    if entry is not None:
        api_key_raw, created_at, _api_key_hash = entry
        if time.time() - created_at > _SESSION_TTL_SECONDS:
            del _SESSION_STORE[session_id]
            return None, None

        return api_key_raw, created_at

    return None, None


def _resolve_session_hash(session_id: str) -> str | None:
    if _redis_client is not None:
        try:
            import json
            raw = _redis_client.get(f"session:{session_id}")
            if raw:
                data = json.loads(raw)
                return data.get("api_key_hash")
        except Exception:
            pass

    entry = _SESSION_STORE.get(session_id)
    if entry is not None:
        _api_key_raw, created_at, api_key_hash = entry
        if time.time() - created_at > _SESSION_TTL_SECONDS:
            del _SESSION_STORE[session_id]
            return None
        return api_key_hash

    if _database_url:
        try:
            if _pool is not None:
                ctx = _pool.connection()
            else:
                import psycopg
                ctx = psycopg.connect(_database_url)
            with ctx as conn:
                row = conn.execute(
                    "SELECT api_key_hash FROM browser_sessions WHERE session_id = %s AND expires_at > now()",
                    (session_id,),
                ).fetchone()
                if row:
                    return row[0]
        except Exception:
            pass

    return None


def get_api_key_hash_from_session(request: Request) -> str | None:
    session = request.cookies.get(_SESSION_COOKIE)
    if not session:
        return None
    return _resolve_session_hash(session)


def _invalidate(session_id: str) -> None:
    _SESSION_STORE.pop(session_id, None)
    if _redis_client is not None:
        try:
            _redis_client.delete(f"session:{session_id}")
        except Exception:
            pass
    if _database_url:
        try:
            if _pool is not None:
                ctx = _pool.connection()
            else:
                import psycopg
                ctx = psycopg.connect(_database_url)
            with ctx as conn:
                conn.execute("DELETE FROM browser_sessions WHERE session_id = %s", (session_id,))
                conn.commit()
        except Exception:
            pass


# ── FastAPI dependency ─────────────────────────────────────────────

def get_api_key_from_session(
    request: Request,
    session: str | None = Cookie(default=None),
    csrf_token_cookie: str | None = Cookie(default=None, alias=_CSRF_COOKIE),
    x_csrf_token: str | None = Header(default=None, alias="X-CSRF-Token"),
) -> str | None:
    """
    Extract the raw API key from the session cookie.
    Also validates CSRF for non-GET requests.
    Returns the raw API key string, or None if no valid session.
    """
    # This helper is called manually from require_api_key(), not only as a
    # FastAPI dependency. In that path the default Cookie/Header marker objects
    # are passed through unchanged, so resolve real values from the request.
    if isinstance(session, CookieParam):
        session = request.cookies.get(_SESSION_COOKIE)
    if isinstance(csrf_token_cookie, CookieParam):
        csrf_token_cookie = request.cookies.get(_CSRF_COOKIE)
    if isinstance(x_csrf_token, HeaderParam):
        x_csrf_token = request.headers.get("X-CSRF-Token")

    if not session:
        return None

    # CSRF validation on mutating methods
    method = request.method.upper()
    if method not in {"GET", "HEAD", "OPTIONS"}:
        if not csrf_token_cookie or not x_csrf_token:
            raise HTTPException(
                status_code=403,
                detail={"code": "CSRF_TOKEN_MISSING", "message": "CSRF token missing."},
            )
        if not secrets.compare_digest(csrf_token_cookie, x_csrf_token):
            raise HTTPException(
                status_code=403,
                detail={"code": "CSRF_TOKEN_INVALID", "message": "CSRF token mismatch."},
            )

    api_key_raw, _ = _resolve_session_id(session)
    return api_key_raw  # may be None if session expired
