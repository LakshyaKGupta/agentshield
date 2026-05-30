from __future__ import annotations

import time
import uuid as _uuid_mod
from collections import defaultdict, deque
from datetime import datetime, timezone
from uuid import UUID

from fastapi import Depends, FastAPI, Header, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from pydantic import BaseModel
from .contracts import AgentCreateRequest, AnalyzeRequest, AttackSimulationRequest, HealthResponse, ReadinessResponse, ThreatPage, ToolCallRequest, WorkspaceLoginRequest, WorkspaceSignupRequest
from .ledger.service import verify_ledger
from .security.api_keys import authenticate_api_key, create_api_key
from .security.jwt_identity import generate_dev_keypair
from .services import analyze_message, check_tool_call, firebase_verify_and_login, list_agents, login_workspace, revoke_agent, run_attack_simulation, signup_workspace, spawn_agent
from .settings import get_settings
from .store import create_store

settings = get_settings()
store = create_store(settings.database_url)

app = FastAPI(title="AgentShield API", version=settings.app_version)
app.add_middleware(
    CORSMiddleware,
    allow_origins=list(settings.allowed_origins),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Sliding-window rate limiter (in-process, per client IP) ───────
_rate_buckets: dict[str, deque] = defaultdict(deque)

MAX_BODY_BYTES   = 1 * 1024 * 1024   # 1 MB
PUBLIC_RPM       = 60                 # unauthenticated endpoints
AUTHED_RPM       = 300               # authenticated endpoints
WINDOW_SECONDS   = 60

# Endpoints that carry an API key are counted separately
_AUTHED_PREFIXES = ("/v1/agents", "/v1/shield", "/v1/ledger", "/v1/threats", "/v1/attack", "/v1/settings")


def _check_rate_limit(client_ip: str, limit: int) -> None:
    now = time.monotonic()
    bucket = _rate_buckets[client_ip]
    while bucket and now - bucket[0] > WINDOW_SECONDS:
        bucket.popleft()
    if len(bucket) >= limit:
        raise HTTPException(
            status_code=429,
            detail={"code": "RATE_LIMIT_EXCEEDED", "message": f"Too many requests. Limit: {limit}/min."},
            headers={"Retry-After": "60"},
        )
    bucket.append(now)


@app.middleware("http")
async def rate_limit_and_size_guard(request: Request, call_next):
    # 1. Request body size guard
    content_length = request.headers.get("content-length")
    if content_length and int(content_length) > MAX_BODY_BYTES:
        return JSONResponse(
            status_code=413,
            content={"error": {"code": "PAYLOAD_TOO_LARGE", "message": "Request body exceeds 1 MB limit."}},
        )

    # 2. Rate limiting per client IP
    client_ip = request.client.host if request.client else "unknown"
    path = request.url.path
    limit = AUTHED_RPM if path.startswith(_AUTHED_PREFIXES) else PUBLIC_RPM
    try:
        _check_rate_limit(client_ip, limit)
    except HTTPException as exc:
        body = exc.detail if isinstance(exc.detail, dict) else {"message": str(exc.detail)}
        return JSONResponse(status_code=429, content={"error": body}, headers={"Retry-After": "60"})

    return await call_next(request)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    """Inject OWASP-recommended security headers on every response."""
    response = await call_next(request)
    # Prevent MIME-type sniffing
    response.headers["X-Content-Type-Options"] = "nosniff"
    # Deny framing (clickjacking protection)
    response.headers["X-Frame-Options"] = "DENY"
    # Strict XSS filter (legacy browsers)
    response.headers["X-XSS-Protection"] = "1; mode=block"
    # HSTS — tell browsers to always use HTTPS
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    # Minimal referrer leakage
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    # Prevent cross-origin isolation issues
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    # Unique request ID for tracing
    response.headers["X-Request-ID"] = request.headers.get(
        "X-Request-ID", str(_uuid_mod.uuid4())
    )
    return response


# ── App-level bootstrap (demo tenant + keypair) ───────────────────
tenant = store.seed_tenant()
private_key, public_key = generate_dev_keypair()
demo_api_key = create_api_key(store, settings, tenant.id)


def error_response(status_code: int, code: str, message: str, details: object | None = None) -> JSONResponse:
    body = {"error": {"code": code, "message": message}}
    if details is not None:
        body["error"]["details"] = details
    return JSONResponse(status_code=status_code, content=body)


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
    detail = exc.detail
    code = "HTTP_ERROR"
    message = "Request failed."
    if isinstance(detail, dict):
        code = str(detail.get("code", code))
        message = str(detail.get("message", code))
    elif isinstance(detail, str):
        message = detail
    return error_response(exc.status_code, code, message)


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    return error_response(422, "VALIDATION_ERROR", "Request validation failed.", exc.errors())


def require_api_key(x_agentshield_api_key: str | None = Header(default=None, alias="X-AgentShield-API-Key")):
    try:
        return authenticate_api_key(store, settings, x_agentshield_api_key, "shield:write")
    except PermissionError as exc:
        raise HTTPException(status_code=401, detail={"code": str(exc)}) from exc


@app.get("/health", response_model=HealthResponse)
def health():
    return {
        "status": "ok",
        "service": "agentshield",
        "version": settings.app_version,
        "demo_mode": settings.demo_mode,
        "demo_api_key": demo_api_key if settings.demo_mode else None,
    }


@app.get("/ready", response_model=ReadinessResponse)
def ready():
    ledger_status = verify_ledger(store)
    return {
        "ready": ledger_status.valid,
        "service": "agentshield",
        "version": settings.app_version,
        "store": store.backend_name,
        "ledger_valid": ledger_status.valid,
        "ledger_entries": ledger_status.entries_checked,
        "tenant_count": len(store.tenants),
        "agent_count": len(store.agents),
        "event_count": len(store.events),
    }


@app.post("/v1/auth/signup")
def signup(request: WorkspaceSignupRequest):
    try:
        return signup_workspace(store, settings, request)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail={"code": str(exc), "message": "A workspace user with this email already exists."}) from exc


@app.post("/v1/auth/login")
def login(request: WorkspaceLoginRequest):
    try:
        return login_workspace(store, settings, request)
    except PermissionError as exc:
        raise HTTPException(status_code=401, detail={"code": str(exc), "message": "Invalid email or password."}) from exc


class FirebaseVerifyRequest(BaseModel):
    firebase_id_token: str
    workspace_name: str | None = None


@app.post("/v1/auth/firebase-verify")
def firebase_verify(request: FirebaseVerifyRequest):
    """Exchange a Firebase ID token for an AgentShield API key.
    Creates a workspace on first login; returns existing workspace key on subsequent logins.
    """
    try:
        return firebase_verify_and_login(
            store, settings,
            firebase_id_token=request.firebase_id_token,
            workspace_name=request.workspace_name,
        )
    except ValueError as exc:
        raise HTTPException(status_code=401, detail={"code": "FIREBASE_TOKEN_INVALID", "message": str(exc)}) from exc


@app.post("/v1/agents")
def create_agent(request: AgentCreateRequest, api_key=Depends(require_api_key)):
    return spawn_agent(store, settings, request, api_key.tenant_id, private_key)


@app.get("/v1/agents")
def get_agents(api_key=Depends(require_api_key)):
    return list_agents(store, settings, api_key.tenant_id, private_key)


@app.post("/v1/agents/{agent_id}/revoke")
def revoke(agent_id: UUID, api_key=Depends(require_api_key)):
    try:
        return revoke_agent(store, settings, api_key.tenant_id, agent_id, private_key)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail={"code": "AGENT_NOT_FOUND"}) from exc


@app.post("/v1/shield/analyze")
def analyze(request: AnalyzeRequest, authorization: str | None = Header(default=None), api_key=Depends(require_api_key)):
    token = authorization.removeprefix("Bearer ").strip() if authorization else None
    try:
        return analyze_message(store, settings, request, token or "", public_key)
    except PermissionError as exc:
        raise HTTPException(status_code=401, detail={"code": str(exc)}) from exc


@app.post("/v1/shield/tool-call")
def tool_call(request: ToolCallRequest, authorization: str | None = Header(default=None), api_key=Depends(require_api_key)):
    token = authorization.removeprefix("Bearer ").strip() if authorization else None
    try:
        return check_tool_call(store, settings, request, token or "", public_key)
    except PermissionError as exc:
        raise HTTPException(status_code=401, detail={"code": str(exc)}) from exc


@app.get("/v1/ledger")
def ledger(
    limit: int = 100,
    offset: int = 0,
    agent_id: UUID | None = None,
    verdict: str | None = None,
    api_key=Depends(require_api_key)
):
    entries = store.ledger
    # Filter by tenant
    entries = [e for e in entries if e.tenant_id == api_key.tenant_id]
    # Filter by agent_id
    if agent_id:
        entries = [e for e in entries if e.agent_id == agent_id]
    # Filter by verdict
    if verdict:
        entries = [e for e in entries if e.verdict.value == verdict.upper()]
    
    paginated = entries[offset:offset+limit]
    return {
        "entries": paginated,
        "total": len(entries),
        "limit": limit,
        "offset": offset
    }


@app.get("/v1/ledger/verify")
def ledger_verify(api_key=Depends(require_api_key)):
    return verify_ledger(store)


@app.get("/v1/threats")
def threats(api_key=Depends(require_api_key)):
    tenant_threats = [threat for threat in store.threat_events if store.agents[threat["agent_id"]].tenant_id == api_key.tenant_id]
    return ThreatPage(threats=tenant_threats)


@app.post("/v1/threats/{threat_id}/resolve")
def resolve_threat(threat_id: UUID, api_key=Depends(require_api_key)):
    threat = None
    for t in store.threat_events:
        if t["id"] == threat_id:
            threat = t
            break
    if not threat:
        raise HTTPException(status_code=404, detail={"code": "THREAT_NOT_FOUND"})
    
    agent = store.agents.get(threat["agent_id"])
    if not agent or agent.tenant_id != api_key.tenant_id:
        raise HTTPException(status_code=403, detail={"code": "FORBIDDEN"})
        
    threat["resolved"] = True
    store.persist_threat_event(threat)
    return {"status": "success", "resolved": True}


@app.post("/v1/agents/{agent_id}/rotate-token")
def rotate_agent_token(agent_id: UUID, api_key=Depends(require_api_key)):
    try:
        agent = store.agents[agent_id]
        if agent.tenant_id != api_key.tenant_id:
            raise PermissionError("FORBIDDEN")
        if agent.status != "active":
            raise HTTPException(status_code=400, detail={"code": "AGENT_NOT_ACTIVE"})
        
        # Revoke old tokens
        from datetime import datetime, timezone
        for token in store.tokens.values():
            if token.agent_id == agent_id:
                token.revoked_at = datetime.now(timezone.utc)
                store.persist_token(token)
                
        # Issue new token
        from .services import _agent_response
        return _agent_response(store, settings, agent, private_key)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail={"code": "AGENT_NOT_FOUND"}) from exc
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail={"code": str(exc)}) from exc


@app.post("/v1/attack-sim/run")
def attack_sim(request: AttackSimulationRequest, api_key=Depends(require_api_key)):
    return run_attack_simulation(store, settings, request, api_key.tenant_id, private_key, public_key)


@app.post("/v1/chat")
def chat(body: dict):
    """
    Intelligent rule-based chat for the AgentShield assistant.
    Covers identity, permissions, ledger, threats, deployment, pricing, and SDK.
    """
    if not isinstance(body, dict):
        raise HTTPException(status_code=422, detail={"code": "INVALID_BODY", "message": "Body must be a JSON object."})
    raw_msg = body.get("message") or ""
    if not isinstance(raw_msg, str):
        raise HTTPException(status_code=422, detail={"code": "INVALID_MESSAGE", "message": "message must be a string."})
    # Length guard — prevent abuse
    if len(raw_msg) > 2000:
        return {"reply": "Please keep your question under 2000 characters.", "latency_ms": 1}
    msg = raw_msg.strip().lower()

    ANSWERS: list[tuple[tuple[str, ...], str]] = [
        (("what is agentshield", "what does agentshield do", "agentshield do", "about agentshield", "explain agentshield"),
         "AgentShield is a runtime security middleware for AI agents. It sits between your LLM agent and the outside world, checking every message and tool call against three guards: RS256 cryptographic identity, deny-by-default permission manifests, and a SHA-256 hash-chained tamper-evident audit ledger."),

        (("identity", "jwt", "rs256", "token", "verify agent", "how does identity", "agent token"),
         "Every agent registered via POST /v1/agents receives a short-lived RS256 JWT. Before any message analysis or tool check, the token is cryptographically verified using the public key. Expired, revoked, or forged tokens are rejected immediately. Rotate tokens via POST /v1/agents/{id}/rotate-token."),

        (("permission", "permissions", "deny", "allow", "manifest", "tool call", "policy"),
         "AgentShield uses a deny-by-default permission manifest. When you create an agent you declare exactly which tools and actions it may use — e.g. web_search:read. Any call to an unlisted tool is blocked before it executes and written to the ledger as BLOCKED. This stops privilege escalation even if the LLM is manipulated."),

        (("ledger", "audit", "hash chain", "tamper", "immutable", "verify chain", "audit log"),
         "Every decision — ALLOWED, BLOCKED, or FLAGGED — is appended to a SHA-256 hash-chained ledger. Each entry stores the hash of the previous entry, so any tampering is immediately detectable. Call GET /v1/ledger/verify to check the entire chain in one API call."),

        (("injection", "prompt injection", "jailbreak", "attack", "block", "detect", "threat"),
         "Injection detection runs deterministically in <200ms using 50+ regex patterns across 10 attack classes: instruction override, prompt exfiltration, system token injection, jailbreaks, role hijack, data exfiltration, SQL injection, SSRF, privilege escalation, and shell injection. Shannon entropy scoring and repetition heuristics catch obfuscated variants. No LLM on the synchronous guard path."),

        (("attack sim", "simulation", "red team", "test attack", "run simulation"),
         "POST /v1/attack-sim/run fires adversarial payloads at a fresh agent and returns the verdict + evidence. Supported types: instruction_override, role_hijack, data_exfiltration, developer_mode, benign. Add a custom payload field to test your own strings."),

        (("integrate", "how to use", "sdk", "setup", "start", "begin", "langchain", "deploy agent"),
         "Integration is 3 API calls: (1) POST /v1/agents to register your agent and get a JWT. (2) POST /v1/shield/analyze on every inbound and outbound message. (3) POST /v1/shield/tool-call before every tool execution. The Python SDK in sdk/python/ wraps all three. For LangChain, add a @tool decorator that calls /v1/shield/tool-call before executing."),

        (("price", "cost", "pricing", "plan", "free", "tier"),
         "Prototype: Free forever — local in-memory store, up to 5 agents. Team: $149/month — PostgreSQL persistence, team SSO, real-time WebSocket feed, priority support. Enterprise: custom pricing — dedicated infrastructure, SLA guarantees, SIEM integration, custom retention."),

        (("dashboard", "console", "monitor", "ui"),
         "The security console (running on the frontend) shows: active agents with trust scores, real-time ledger entries, threat events with resolution, and an attack simulation panel. Connect it to the backend by setting VITE_API_URL in frontend/.env."),

        (("firebase", "auth", "login", "sign in", "signup", "authentication"),
         "Authentication uses Firebase (Email/Password + Google OAuth). After Firebase sign-in, the frontend exchanges the Firebase ID token at POST /v1/auth/firebase-verify to receive an AgentShield API key. Add your deployed domain to Firebase Console → Authentication → Settings → Authorized domains."),

        (("websocket", "real-time", "events", "live"),
         "Connect to WS /ws/events?api_key=as_live_... to receive a real-time stream of security events as they happen. The WebSocket sends the last 50 events on connect, then streams new verdicts, threat detections, and agent state changes live."),
    ]

    reply = (
        "I'm the AgentShield assistant. Ask me about: identity tokens, permission manifests, "
        "the audit ledger, prompt injection detection, SDK integration, pricing, or how to deploy your first protected agent."
    )
    for keys, answer in ANSWERS:
        if any(k in msg for k in keys):
            reply = answer
            break

    start = time.monotonic()
    latency = max(1, int((time.monotonic() - start) * 1000)) or 8
    return {"reply": reply, "latency_ms": latency}


class UserPreferences(BaseModel):
    theme: str = "light"
    notifications_enabled: bool = True
    default_agent_ttl: int = 3600
    audit_retention_days: int = 30
    language: str = "en"

# In-memory preferences store (per-tenant)
_preferences: dict = {}

@app.get("/v1/settings")
def get_settings_endpoint(api_key=Depends(require_api_key)):
    key = str(api_key.tenant_id)
    return _preferences.get(key, UserPreferences().model_dump())

@app.put("/v1/settings")
def update_settings_endpoint(prefs: UserPreferences, api_key=Depends(require_api_key)):
    key = str(api_key.tenant_id)
    _preferences[key] = prefs.model_dump()
    return {"status": "saved", "settings": _preferences[key]}


@app.get("/v1/metrics")
def metrics(api_key=Depends(require_api_key)):
    """Summary metrics for the tenant dashboard."""
    tid = api_key.tenant_id
    tenant_agents  = [a for a in store.agents.values()  if a.tenant_id == tid]
    tenant_ledger  = [e for e in store.ledger            if e.tenant_id == tid]
    tenant_threats = [
        t for t in store.threat_events
        if store.agents.get(t["agent_id"]) and store.agents[t["agent_id"]].tenant_id == tid
    ]

    blocked  = sum(1 for e in tenant_ledger if e.verdict.value == "BLOCKED")
    flagged  = sum(1 for e in tenant_ledger if e.verdict.value == "FLAGGED")
    allowed  = sum(1 for e in tenant_ledger if e.verdict.value == "ALLOWED")
    active_a = sum(1 for a in tenant_agents  if a.status == "active")
    avg_trust = (
        round(sum(a.trust_score for a in tenant_agents) / len(tenant_agents), 3)
        if tenant_agents else 1.0
    )
    unresolved_threats = sum(1 for t in tenant_threats if not t.get("resolved"))
    ledger_status = verify_ledger(store)

    return {
        "tenant_id":          str(tid),
        "agents_total":       len(tenant_agents),
        "agents_active":      active_a,
        "avg_trust_score":    avg_trust,
        "ledger_entries":     len(tenant_ledger),
        "ledger_valid":       ledger_status.valid,
        "decisions_allowed":  allowed,
        "decisions_blocked":  blocked,
        "decisions_flagged":  flagged,
        "threats_total":      len(tenant_threats),
        "threats_unresolved": unresolved_threats,
        "generated_at":       datetime.now(timezone.utc).isoformat(),
    }


@app.websocket("/ws/events")
async def ws_events(websocket: WebSocket):
    raw_key = websocket.query_params.get("api_key")
    try:
        authenticate_api_key(store, settings, raw_key, "shield:write")
    except PermissionError:
        await websocket.close(code=1008)
        return
    await websocket.accept()
    try:
        await websocket.send_json({"event": "system.health.changed", "component": "api", "status": "ok"})
        for event in store.events[-50:]:
            await websocket.send_json(event)
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        return
