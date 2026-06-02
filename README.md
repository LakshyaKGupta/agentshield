# AgentShield

AgentShield is a production-ready, full-stack runtime security middleware for autonomous AI agents. It provides deterministic prompt-injection screening, cryptographic agent identity validation via RS256 JWTs, deny-by-default permission manifests, an append-only tamper-evident ledger, secure webhook alert dispatching, multi-tenant RBAC team directories, and interactive behavioral risk profiling.

---

## Technical Architecture

*   **FastAPI Backend (`backend/app`)**: Secure REST and WebSocket API. Implements sliding-window IP rate-limiting, 1MB payload ceilings, 50+ threat regex patterns, Shannon character entropy analyzers, dynamic sandbox stress-testing fallbacks, and HMAC-SHA256 signed async webhooks.
*   **Vite React Console (`frontend`)**: Sleek, high-fidelity security operator console with customizable themes, active navigation scrollspy, canvas-drawn ambient Hero orbs, settings vault navigation, and an interactive sliding behavioral profiling modal drawing custom SVG trust sparklines.
*   **Packaged Python SDK (`sdk/python`)**: Complete packaging ready for PyPI publishing (`pyproject.toml`, `setup.py`, `README.md`), exposing the fully typed `AgentShield` client for LangChain or native integrations.
*   **Durable Database Schema (`backend/migrations`)**: Robust schema supporting both in-memory and PostgreSQL engines, incorporating database-level triggers to guarantee the append-only ledger chain is immutable.

---

## Multi-Device Local Network Hosting

To make AgentShield accessible to **any phone, tablet, or separate device** connected to the same Wi-Fi network:

### 1. Launch the Backend Server
Bind the FastAPI backend to all interfaces (`0.0.0.0`) on port `8000`:
```bash
cd backend
python3 -m uvicorn app.main:app --host 0.0.0.0 --port 8000
```

### 2. Launch the Frontend Console
Bind the Vite dev server to all interfaces (`0.0.0.0`) on port `5173`:
```bash
cd frontend
npm run dev
```
Vite will output the local network IP (e.g. `http://10.239.68.201:5173/`). Point any other device's browser to this IP. The frontend dynamically resolves the active host and channels all cryptographic operations back to your server with zero configuration!

---

## Local Verification & Quality Gates

Run the comprehensive integration test suite (11/11 tests pass cleanly):
```bash
python3 -m unittest discover -s tests -v
```

Compile optimized production static assets:
```bash
cd frontend
npm run build
```

---

## Production Deployment Checklist

1.  **Durable Database**: Set `DATABASE_URL=postgresql://user:pass@host:5432/dbname` on your server to auto-run migrations and persist cryptographic keys, invitations, and threat events.
2.  **Harden Security**: Set `DEMO_MODE=false` in environment variables before hosting to enforce strict, uncompromised signature verification and disable fallback credentials.
3.  **Publish the SDK**: Push the package to PyPI so developers can immediately run `pip install agentshield` globally:
    ```bash
    cd sdk/python
    python3 -m build
    python3 -m twine upload dist/*
    ```

