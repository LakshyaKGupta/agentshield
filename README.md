# AgentShield

AgentShield is an AI agent security middleware prototype with deterministic runtime protection, cryptographic agent identity, permission enforcement, hash-chained audit logging, attack simulation, and a production-style operator interface.

## Current Implementation

- `backend/app`: FastAPI service with workspace signup/login, API-key auth, optional PostgreSQL persistence, RS256 agent JWTs, prompt-injection detection, tool permission checks, ledger verification, threats, attack simulation, and WebSocket event replay.
- `frontend`: Vite React website with a Handhold-inspired light palette, animated Three.js hero, login/signup flows, dashboard, ledger, attack simulation, and agent registry screens.
- `sdk/python/agentshield`: Python SDK skeleton for agent spawning, message analysis, tool-call checks, ledger verification, threats, and attack simulation.
- `AgentShield_Production_Documentation_Pack`: production planning documents and Markdown sources.

## Local Verification

```bash
python3 -m unittest discover -s tests -v
python3 scripts/export_openapi.py
cd frontend && npm install && npm run build
```

## Run Locally

Backend:

```bash
uvicorn backend.app.main:app --reload
```

Health and readiness:

```bash
curl http://127.0.0.1:8000/health
curl http://127.0.0.1:8000/ready
```

Create a workspace, then add an AI agent:

```bash
API_KEY=$(curl -s http://127.0.0.1:8000/v1/auth/signup \
  -H 'Content-Type: application/json' \
  -d '{"email":"ops@example.com","password":"correct-horse","workspace_name":"Ops"}' | python3 -c 'import json,sys; print(json.load(sys.stdin)["api_key"])')

curl -s http://127.0.0.1:8000/v1/agents \
  -H "X-AgentShield-API-Key: $API_KEY" \
  -H 'Content-Type: application/json' \
  -d '{"name":"ResearchAgent","type":"research_agent","permissions":{"tools":{"web_search":["read"]},"default_action":"deny"}}'
```

Frontend:

```bash
cd frontend
npm run dev
```

The backend uses an in-memory store by default. Set `DATABASE_URL=postgresql://...` to enable the PostgreSQL store and initialize `backend/migrations/001_initial_schema.sql`, including append-only ledger triggers.
`DEMO_MODE=true` exposes a local demo API key from `/health`; set `DEMO_MODE=false` before any shared deployment. The frontend now uses workspace signup/login for normal access.
