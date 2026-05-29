# AgentShield

AgentShield is an AI agent security middleware prototype with deterministic runtime protection, cryptographic agent identity, permission enforcement, hash-chained audit logging, attack simulation, and a production-style operator interface.

## Current Implementation

- `backend/app`: FastAPI service with API-key auth, RS256 agent JWTs, prompt-injection detection, tool permission checks, ledger verification, threats, attack simulation, and WebSocket event replay.
- `frontend`: Vite React website with minimal animated Three.js hero, login/signup flows, dashboard, ledger, attack simulation, and agent registry screens.
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

Frontend:

```bash
cd frontend
npm run dev
```

The backend currently uses an in-memory store for the first implementation slice. The SQL migration in `backend/migrations/001_initial_schema.sql` documents the planned PostgreSQL schema and append-only ledger triggers.
