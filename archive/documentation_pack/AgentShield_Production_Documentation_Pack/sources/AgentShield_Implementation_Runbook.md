# AgentShield Implementation Runbook

Step-by-step production build order for backend, frontend, SDK, security engine, deployment, and observability.

Version 1.0 | 2026-05-29

# 1. Repository Layout

| Path | Purpose |
| --- | --- |
| backend/app | FastAPI application, routers, services, middleware. |
| backend/app/security | API key auth, JWT identity, permission engine, injection detector. |
| backend/app/ledger | Ledger append, canonical hash, verification, DB triggers. |
| backend/app/events | Outbox, WebSocket manager, event serializers. |
| backend/migrations | Alembic migrations for PostgreSQL. |
| frontend/app | Next.js App Router pages. |
| frontend/components | Dashboard, ledger, attack sim, shared UI, Three.js scene. |
| sdk/python/agentshield | Python SDK package. |
| tests | Backend, SDK, contract, and e2e tests. |

# 2. Phase 0 - Foundation

1. Create backend FastAPI project with health endpoint, settings loader, structured logging, and test harness.
2. Create PostgreSQL migrations for tenants, api_keys, agents, agent_tokens, permission_manifests, audit_ledger, threat_events, trust_history, and event_outbox.
3. Create frontend Next.js app with Tailwind, base layout, dashboard route shell, and API client placeholder.
4. Create SDK package skeleton with typed client, exceptions, and local example script.
5. Add CI commands for backend tests, frontend lint/build, SDK tests, and contract schema checks.

| Acceptance | Verification Command |
| --- | --- |
| Backend boots and /health returns ok. | uvicorn app.main:app --reload; curl /health |
| Migrations apply from empty database. | alembic upgrade head |
| Frontend builds empty shells. | npm run build |
| SDK imports. | python -c 'import agentshield' |

# 3. Phase 1 - Security Core

1. Implement API key generation, hashing, lookup, scopes, and auth middleware.
2. Implement RS256 key loading, JWT issuance, validation, kid support, jti registry, expiry, and revocation.
3. Implement permission manifests with deny-by-default semantics and action-level checks.
4. Implement deterministic injection detector using curated regexes, normalized text, confidence scoring, and evidence spans.
5. Implement /v1/agents, /v1/shield/analyze, and /v1/shield/tool-call using documented schemas.

| Acceptance | Verification Command |
| --- | --- |
| Invalid credentials are rejected. | pytest tests/security/test_auth.py |
| Unauthorized tool calls are blocked. | pytest tests/security/test_permissions.py |
| Known injection payloads are blocked or flagged. | pytest tests/security/test_injection_detector.py |

# 4. Phase 2 - Ledger, Trust, And Events

1. Implement canonical JSON hash function and genesis hash constant.
2. Implement ledger append service with transaction lock and immutable database trigger migration.
3. Implement trust score delta rules and trust_history writes.
4. Implement event_outbox and WebSocket broadcast for security events, trust updates, and ledger verification.
5. Implement /v1/ledger, /v1/ledger/verify, /v1/threats, and trust history endpoints.

| Acceptance | Verification Command |
| --- | --- |
| Ledger writes are hash chained. | pytest tests/ledger/test_append.py |
| Concurrent writes preserve chain. | pytest tests/ledger/test_concurrency.py |
| Tamper simulation breaks verification. | pytest tests/ledger/test_verify.py |
| WebSocket receives committed events. | pytest tests/events/test_websocket.py |

# 5. Phase 3 - SDK And Demo Agent

1. Implement Python SDK client with retries, timeout, typed responses, and SecurityBlocked exception.
2. Create demo research agent flow that analyzes user messages before processing and checks tool calls before execution.
3. Create 10 curated attack fixtures covering instruction override, role hijack, data exfiltration, tool misuse, and spoofing.
4. Implement /v1/attack-sim/run using the real analyze and tool-call paths; do not mock verdicts.

# 6. Phase 4 - Frontend Dashboard

1. Build dashboard route with live metrics, WebSocket connection state, event feed, and agent trust panel.
2. Build ledger route with paginated table, full hash expansion, verify-chain button, and client-side tamper demo clearly labeled as local simulation.
3. Build attack simulator route with attack selector, custom payload editor, run button, verdict panel, evidence, and latency.
4. Build agent registry route with permissions, status, trust history, revoke action, and empty/loading/error states.
5. Add Three.js network only after REST/WebSocket payloads are stable; use list fallback for mobile.

| Acceptance | Verification Command |
| --- | --- |
| Dashboard connects to backend and updates from WebSocket. | Playwright dashboard smoke test. |
| Ledger page verifies real chain. | Playwright ledger smoke test. |
| Attack sim blocks curated payload. | Playwright attack simulation smoke test. |
| Mobile fallback is usable. | Playwright mobile viewport smoke test. |

# 7. Phase 5 - Deployment And Operations

1. Provision Railway backend and PostgreSQL with separate app and migration credentials.
2. Provision Vercel frontend with NEXT_PUBLIC_API_URL and NEXT_PUBLIC_WS_URL.
3. Configure secrets: DATABASE_URL, JWT_PRIVATE_KEY, JWT_PUBLIC_KEYS_JSON, API_KEY_PEPPER, OPENAI_API_KEY for optional enrichment, CORS origins.
4. Run migrations, seed tenant and demo API key, spawn demo agents, and record non-secret identifiers.
5. Run production smoke: health, agent spawn, analyze allowed message, analyze blocked injection, tool-call denial, ledger verify, dashboard route, WebSocket event.

# 8. Observability Requirements

- Log request_id, tenant_id, agent_id, endpoint, verdict, latency_ms, and ledger_id; never log raw API keys, private keys, or full sensitive messages by default.
- Expose metrics for request count, blocked count, latency, ledger append failures, WebSocket clients, queue depth, and enrichment failures.
- Alert on ledger append failure, ledger verification failure, auth spike, critical threat spike, and queue backlog.
- Provide an incident runbook for key compromise, ledger integrity failure, and backend outage.

# 9. Definition Of Done For Each Phase

| Phase | Done Means |
| --- | --- |
| 0 | A new developer or AI agent can clone the repo, configure env from example files, run migrations, run tests, and boot both apps locally. |
| 1 | The server rejects invalid auth and blocks deterministic policy violations without any frontend or LLM dependency. |
| 2 | Every protected decision has a ledger entry, trust changes are explainable, and event streaming works from committed outbox rows. |
| 3 | The SDK examples protect a real demo flow and failures are ergonomic enough for application developers to handle. |
| 4 | The dashboard is useful with real backend data, with no hidden mock state outside an explicitly labeled demo mode. |
| 5 | A production operator can deploy, verify, monitor, rotate keys, recover from common incidents, and roll back safely. |

# 10. AI Agent Build Rules

- Do not implement dashboard animations before backend contracts and fixture payloads are stable.
- Do not put LLM calls in the default synchronous enforcement path.
- Do not store raw API keys, JWT private keys, or full sensitive payloads in logs or frontend state.
- Do not allow a successful protected action unless the ledger write succeeded.
- Do not treat the Three.js graph as required for mobile acceptance; the mobile list fallback is a first-class interface.
- When uncertain, choose the stricter security behavior and document it in the handoff.
