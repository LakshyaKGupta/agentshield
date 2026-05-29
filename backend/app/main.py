from __future__ import annotations

from uuid import UUID

from fastapi import Depends, FastAPI, Header, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

from .contracts import AgentCreateRequest, AnalyzeRequest, AttackSimulationRequest, ThreatPage, ToolCallRequest
from .ledger.service import verify_ledger
from .security.api_keys import authenticate_api_key, create_api_key
from .security.jwt_identity import generate_dev_keypair
from .services import analyze_message, check_tool_call, list_agents, revoke_agent, run_attack_simulation, spawn_agent
from .settings import get_settings
from .store import store

app = FastAPI(title="AgentShield API", version="0.1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:5174", "http://127.0.0.1:5173", "http://127.0.0.1:5174"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
settings = get_settings()
tenant = store.seed_tenant()
private_key, public_key = generate_dev_keypair()
demo_api_key = create_api_key(store, settings, tenant.id)


def require_api_key(x_agentshield_api_key: str | None = Header(default=None, alias="X-AgentShield-API-Key")):
    try:
        return authenticate_api_key(store, settings, x_agentshield_api_key, "shield:write")
    except PermissionError as exc:
        raise HTTPException(status_code=401, detail={"code": str(exc)}) from exc


@app.get("/health")
def health():
    return {"status": "ok", "service": "agentshield", "demo_api_key": demo_api_key}


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
def ledger(api_key=Depends(require_api_key)):
    return {"entries": store.ledger}


@app.get("/v1/ledger/verify")
def ledger_verify(api_key=Depends(require_api_key)):
    return verify_ledger(store)


@app.get("/v1/threats")
def threats(api_key=Depends(require_api_key)):
    tenant_threats = [threat for threat in store.threat_events if store.agents[threat["agent_id"]].tenant_id == api_key.tenant_id]
    return ThreatPage(threats=tenant_threats)


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
