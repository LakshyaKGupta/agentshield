from __future__ import annotations

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
