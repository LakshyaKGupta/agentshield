# 🛡️ AgentShield

AgentShield is a production-ready, high-performance runtime security middleware and monitoring console for autonomous AI agents. It provides deterministic prompt-injection screening, cryptographic agent identity validation via RS256 JWTs, deny-by-default permission manifests, an append-only tamper-evident ledger, secure webhook alert dispatching, multi-tenant RBAC team directories, and interactive behavioral risk profiling.

---

### 🌐 Live Production Application
**Deploy & Monitor Live:** [https://agentshield-sigma.vercel.app](https://agentshield-sigma.vercel.app)

---

## 🚀 Key Features

*   **🔒 Deterministic Prompt Injection Protection**: Screen agent prompts in real-time with regex heuristics, entropy checks, and sandbox evaluations.
*   **🔑 Cryptographic Identities**: Validate agent identities using secure RS256 JWT tokens.
*   **📜 Tamper-Evident Security Ledger**: Verify the integrity of the transaction ledger with audit hashes.
*   **📊 Behavioral Risk Profiling**: Live scoring, trust metrics, and anomaly detection.
*   **🔔 Active Webhooks**: Fire HMAC-SHA256 signed webhook alerts to your systems instantly on security triggers.

---

## 🛠️ Repository Layout

The codebase has been refactored and organized to separate key services, clients, and assets cleanly:

*   [**`backend/`**](file:///Users/lol/Documents/Agent%20Eval/backend) — FastAPI REST and WebSocket server.
*   [**`frontend/`**](file:///Users/lol/Documents/Agent%20Eval/frontend) — Vite React dashboard console.
*   [**`sdk/`**](file:///Users/lol/Documents/Agent%20Eval/sdk) — Packaged SDKs for Python (`sdk/python`) and Node.js (`sdk/nodejs`).
*   [**`scripts/`**](file:///Users/lol/Documents/Agent%20Eval/scripts) — Developer utilities, verification scripts, and OpenAPI exporters.
*   [**`tests/`**](file:///Users/lol/Documents/Agent%20Eval/tests) — Backend unit tests and E2E Playwright test suites.
*   [**`archive/`**](file:///Users/lol/Documents/Agent%20Eval/archive) — Legacy audit files, reports, and UI/UX design snapshots.
    *   [`archive/audits/`](file:///Users/lol/Documents/Agent%20Eval/archive/audits) — Historical audit reports and snapshots.
    *   [`archive/screenshots/`](file:///Users/lol/Documents/Agent%20Eval/archive/screenshots) — Design alignment, visual audits, and dashboard screenshots.
    *   [`archive/documentation_pack/`](file:///Users/lol/Documents/Agent%20Eval/archive/documentation_pack) — Runbooks, threat models, and master production plans.

---

## 💻 Local Development Setup

To run AgentShield on your local machine and make it accessible to other devices on your Wi-Fi network:

### 1. Launch the Backend Server
Bind the FastAPI backend to port `8000`:
```bash
cd backend
python3 -m uvicorn app.main:app --host 0.0.0.0 --port 8000
```

### 2. Launch the Frontend Console
Bind the Vite dev server to port `5173`:
```bash
cd frontend
npm run dev -- --host
```
Point your web browser (or any mobile device/tablet on the same network) to the local network IP provided by Vite (e.g., `http://10.239.68.201:5173`).

---

## 🧪 Testing & Verification

Run the comprehensive Python unit test suite:
```bash
python3 -m unittest discover -s tests -v
```

Compile static frontend assets:
```bash
cd frontend
npm run build
```

---

## 🌐 Production Deployment Checklist

1.  **Durable Database**: Configure `DATABASE_URL=postgresql://user:pass@host:5432/dbname` to auto-run migrations and persist cryptographic keys, invitations, and threat events.
2.  **Harden Security**: Set `DEMO_MODE=false` in your production environment variables to enforce strict signature verification and disable development fallback credentials.
3.  **Publish the SDK**: Package and distribute the client package:
    ```bash
    cd sdk/python
    python3 -m build
    python3 -m twine upload dist/*
    ```
