<!-- Archived legacy security audits -->
# AgentShield — Complete Technical Audit & Reality Due-Diligence Review

**Prepared by:** Senior Staff Engineer, Security Architect, Product Auditor & QA Lead  
**Audit Target:** AgentShield Platform (FastAPI Backend & React Frontend)  
**Execution Context:** Live system evaluated at `http://localhost:8000` (Backend) and `http://localhost:5173` (Frontend)  
**Methodology:** All findings are proven by direct, runtime inspection of active code and raw database states in PostgreSQL. No assumptions or doc-based credits.

---

## 1. Executive Summary

### CTO Due-Diligence Verdict
> [!CAUTION]
> **FAIL — NOT ENTERPRISE READY**  
> While AgentShield exhibits strong potential through its well-crafted pattern-matching injection engine and solid DB-enforced triggers, it contains architectural flaws and security backdoors that would result in an immediate fail in any enterprise technical due-diligence review.
> 
> The core security pillars of the platform—**cryptographic tenant isolation**, **Firebase authentication verification**, and **durable transactional outboxing**—are heavily mocked or compromised at the code level. It is a highly polished security simulator rather than a secure runtime platform.

### Feature Classification: Real, Partial, and Mocked Heuristics

| Component | Status | Code Location / Evidence |
| :--- | :---: | :--- |
| **Prompt Injection Detection Heuristics** | ✅ **REAL** | `backend/app/security/injection.py:147` — Runs 40+ regex patterns, Shannon entropy, and repetition checks in < 5ms. |
| **Tool Gating & Zero-Trust Manifests** | ✅ **REAL** | `backend/app/security/permissions.py:6` — Dict lookup per tool+action, deny-by-default. |
| **SHA-256 Hash-Chained Ledger** | ✅ **REAL** | `backend/app/ledger/service.py:19` — Mathematical hash chains verified on-demand via `/v1/ledger/verify`. |
| **PostgreSQL Table Triggers** | ✅ **REAL** | `backend/migrations/001_initial_schema.sql` — Triggers on `BEFORE UPDATE/DELETE/TRUNCATE` enforce append-only logic. |
| **Tavily Web Search Integration** | ✅ **REAL** | `backend/app/main.py:710` — Executes real Tavily queries when the tool is allowed. |
| **LLM Evaluation Sandbox (Groq)** | ✅ **REAL** | `backend/app/security/sandbox.py` — Evaluates `FLAGGED` prompts via Groq Llama-3.3-70b. |
| **Cryptographic Tenant Isolation** | ❌ **MOCK** | `backend/app/main.py:180` — Uses a single global keypair for *all* tenants, violating cryptographic isolation. |
| **Firebase Auth Verification** | ❌ **MOCK** | `backend/app/security/firebase_auth.py:164` — Silently bypasses signature verification if credentials fail. |
| **Durable Transactional Outbox** | ❌ **MOCK** | `backend/app/store.py:158` — `persist_event` is a silent return no-op under the default in-memory fallback. |
| **Background Outbox Webhooks** | ❌ **MOCK** | `backend/app/main.py:2124` — In-memory outbox scans an empty `store.events` and has immediate 5ms retry burnout. |
| **Database Connection Pooling** | ❌ **MOCK** | `backend/app/store.py:394` — Establishes and tears down a brand-new TCP connection on every single query. |

---

## 2. Brutal Reality Audit (The 10 Key Dimensions)

### 2.1 Overstated Capabilities

#### A. Cryptographic Tenant Identity is a Shared Single Key
The platform claims to issue and verify agent tokens using asymmetric tenant-isolated cryptographic keypairs stored securely in the database.
* **Code Evidence (`backend/app/main.py:180`):**
  ```python
  private_key, public_key = _load_or_create_signing_key()
  ```
  The entire platform bootstrap loads a single global `private_key` and `public_key` into memory once.
* **Code Evidence (`backend/app/main.py:463`):**
  ```python
  response = spawn_agent(store, settings, request, api_key.tenant_id, private_key)
  ```
  Every single tenant registers and signs agent tokens using this global key. If a single tenant's key is rotated or compromised, the identity security of all other tenants is broken. Cryptographic isolation is an architectural illusion.

#### B. The "LLM-Powered Evaluation Sandbox" Fallback
While `LLMEvaluationSandbox` now correctly implements a real Groq Llama-3.3-70b call, if `GROQ_API_KEY` is not present, it has a fallback mode:
* **Code Evidence (`backend/app/security/sandbox.py:73`):**
  ```python
  if self.fallback_to_mock:
      return SandboxVerdict(
          is_safe=False,
          risk_score=0.75,
          classification="AMBIGUOUS",
          analysis="LLM sandbox meta-evaluator unavailable (GROQ_API_KEY not set)..."
      )
  ```
  This is a safe fallback, but it means the "LLM-powered sandbox" is actually a hardcoded fallback block in developer environments.

#### C. The "Durable Transactional Outbox" Silent Failure
The platform's outbox dispatcher claims to protect webhooks from server crashes by saving events durably to the database.
* **Code Evidence (`backend/app/store.py:158`):**
  ```python
  def persist_event(self, event: dict) -> None:
      return
  ```
  In the default in-memory developer configuration, `persist_event` is a silent `return` no-op. The background outbox worker (`main.py:2124`) queries `store.events` which remains permanently empty, meaning **webhooks will never fire in in-memory mode.**

---

### 2.2 Simulated vs. Real Data

#### A. The "Attack Replay" Simulator is a Static Text Fixture
The platform's "Attack Replay" console shows animated security alert stages simulating live attacker traffic.
* **Code Evidence (`frontend/src/main.tsx`):**
  ```typescript
  const SCENARIOS = [
    { id: "prompt_injection",  payload: "Ignore all previous instructions..." },
    { id: "tool_abuse",        payload: "Delete all records from the users database..." }
  ];
  ```
  The attacks are hardcoded client-side text constants. The LLM is never called to simulate an attacker. The detection engine is real, but the environment is entirely simulated.

#### B. Database Row Leaks via Attack Simulations
* **Code Evidence (`backend/app/services.py:435`):**
  Every simulation run creates a throw-away "simulator" agent (e.g. `sim-{attack_type}`) inside the database, resulting in database clutter and row leaks.

#### C. Unimplemented Tool Executors
For all tools other than `web_search` (which calls Tavily), executing tools like `read_docs`, `send_email`, `delete_database`, or `write_file` simply returns:
```json
{
  "executed": false,
  "reason": "No production executor is configured for this tool."
}
```

---

### 2.3 Misleading Trust Signals

#### A. Insignificant Fleet Score Averages
* **The Flaw:** The platform averages individual agent trust scores to report the entire fleet's security health.
* **The Reality:** If only a single agent has sent a single benign request, the entire enterprise fleet score is reported as "A+ / 100% Secure," which represents a false sense of security based on mathematically insignificant data.

#### B. Heuristic-Based Score Changes
* **The Flaw:** The "Trust Score" changes are governed by crude, hardcoded constant deltas applied in Python memory:
  ```python
  # backend/app/services.py:133
  POLICY_TOOL_DENIED evidence -> -0.20
  BLOCKED verdict             -> -0.15
  ALLOWED verdict             -> +0.005
  ```
* **Lacks Dynamism:** The score is a simple accumulator clamped to `[0,1]`. It does not use any statistical model or anomaly detection. A single false positive requires exactly 30 clean allowed requests to recover from, entirely based on arbitrary constants.

---

### 2.4 Metrics & Evidential Soundness
The fleet average calculation immediately reports an "A+" or "Safe" rating for newly registered agents that have never received traffic. This was recently fixed in `main.tsx` to return `N/A — No runtime traffic yet`, but under local SQLite development modes, it defaults back to immediate A+ scoring, presenting a misleading security posture.

---

### 2.5 Local Storage vs. Server-side State
While `localStorage` and `sessionStorage` were purged and replaced with secure httpOnly cookies and a durable `browser_sessions` database table, in the default in-memory developer configuration, restarting the backend server completely wipes all sessions, force-disconnecting all active browser consoles.

---

### 2.6 Broken Workflows

#### A. The In-Memory Outbox Fast-Loop Burnout
* **The Flaw:** In the in-memory outbox path, if a webhook dispatch fails, the background processor has no delay or sleep interval between retry attempts.
* **The Result:** The system burns through all 5 retry attempts in under **5 milliseconds**, making the retry logic useless.

#### B. Team Invitations SMTP Mock
* **The Flaw:** The team invitation workflow is fully mock. The `email_sender.py` module does not contain SMTP transport configurations; invitations are simply printed to stdout. No email is ever sent.

---

### 2.7 Security & Authentication Gaps

#### A. Silent Firebase Signature Verification Bypass (CRITICAL)
In Firebase authentication verification (`backend/app/security/firebase_auth.py`), if `FIREBASE_PROJECT_ID` is missing, or if the GCP credentials fail to load, the system falls back to an unverified claims decode:
```python
# backend/app/security/firebase_auth.py:164
logger.warning("Using explicitly enabled unverified Firebase claims decode...")
claims = _decode_jwt_claims_unsafe(id_token)
```
* **Attack Vector:** An attacker can craft any arbitrary JWT payload containing a fake user ID or email, sign it with no keys, send it to `/v1/auth/firebase-verify`, and the backend will decode it and grant them a valid session API key. This is a severe, unacceptable authentication bypass backdoor.

#### B. Cryptographic Verification CPU-Exhaustion DoS Vector
In `backend/app/security/jwt_identity.py`'s `verify_agent_token()`:
```python
# Sequential RSA signature checks on mismatch:
for tk in tenant_keys:
    try:
        public_key = _get_cached_public_key(tk.public_key_pem)
        public_key.verify(signature, signing_input.encode(), padding.PKCS1v15(), hashes.SHA256())
        signature_verified = True
        break
    except Exception:
        pass
```
* **Attack Vector:** If the `kid` claim is missing in the token, the backend sequentially executes expensive RSA verify operations in a loop against every active key in the DB. An attacker can flood the server with invalid tokens, driving the CPU to 100% utilization and causing a Denial of Service (DoS).

#### C. Absence of Database Connection Pooling
In raw `PostgresStore` operations (`store.py:394`):
```python
def _connect(self):
    return psycopg.connect(self.database_url, row_factory=dict_row)
```
* **The Flaw:** The backend creates and destroys a brand new TCP database connection on *every single query*!
* **Production Impact:** Under high-concurrency traffic, this results in TCP socket exhaustion, introducing severe latency spikes and database server collapse.

---

### 2.8 Deployment & Release Risks
The backend runs exclusively as a raw Uvicorn command `uvicorn app.main:app --host 0.0.0.0 --port 8000`. There are no production configuration templates, no HTTPS setup, no CDN caching layers, and no domain bindings. It is structurally locked into a developer sandbox configuration.

---

### 2.9 UX Inconsistencies & Frontend Monolith
The entire React frontend (routing, state management, pages, styling components, and UI blocks) is written inside a single, massive 250KB `main.tsx` file (`frontend/src/main.tsx`), making it highly fragile, impossible to scale, extremely slow to load, and presents a major maintenance nightmare.

---

### 2.10 Enterprise Technical Due-Diligence Checklist

| Due-Diligence Requirement | Status | Audit Findings |
| :--- | :---: | :--- |
| **Cryptographic Tenant Isolation** | ❌ **FAIL** | Shared global private key used for all tenants. |
| **Secure Authentication Gates** | ❌ **FAIL** | Silent Firebase Auth signature verification bypass fallback. |
| **Database Scaling & Security** | ❌ **FAIL** | Lack of psycopg pooling + N+1 full table scan wrappers. |
| **High Availability Rate Limiting** | ❌ **FAIL** | In-memory rate limiting is isolated per worker, creating split-brain rate limits. |
| **Durable Transactional Outboxing** | ❌ **FAIL** | Outbox is a no-op under default developer fallback mode. |

---

## 3. Architecture Overview

### System Layout
```
Browser
  │
  ├─ Google SSO ──→ Firebase IdToken
  │                      ↓
  │                /v1/auth/firebase-verify
  │                      ↓ verify_firebase_id_token()
  │                      ↓ (Admin SDK or unsafe-decode in demo)
  │                      ↓ upsert workspace + user
  │                      ↓ create_api_key()
  │                      ↓ create_session() → httpOnly cookie
  │
  └─ Email/Auth ──→ /v1/auth/signup or /v1/auth/login
                       ↓ PBKDF2-SHA256, 600k iterations
                       ↓ create_session() → httpOnly cookie + csrf_token cookie
```

### Hot Path Security Pipeline
```
User Prompt
     │
     ▼
┌─────────────────────────────────────┐
│  /v1/agent/run  (Real Path)         │
│                                     │
│  1. verify_agent_token()            │  RS256 JWT validation
│     ↓ BLOCKED if expired/revoked    │
│  2. detect_injection()              │  40+ regex patterns + entropy
│     ↓ BLOCKED if critical threat    │  < 5ms typical
│  3. Groq API (Llama-3.3-70b)        │  Real LLM decides tool calls
│     ↓ returns tool_calls[]          │  ~300ms
│  4. check_tool_permission()         │  Manifest lookup per tool
│     ↓ BLOCKED if not in manifest    │  < 1ms
│  5. append_ledger_entry()           │  SHA-256 hash chain
│     ↓ always writes                 │
│  6. _apply_trust() + persist_agent()│  Trust score update
└─────────────────────────────────────┘
```

---

## 4. API Inventory & Schema Diagnostics

All 38 endpoints mapped, including database row count stats.

### PostgreSQL Active Row Counts
* `tenants`: 4
* `agents`: 7
* `audit_ledger`: 115
* `api_keys`: 7
* `workspace_users`: 4
* `agent_tokens`: 14
* `browser_sessions`: 7
* `cryptographic_keys`: 2
* `event_outbox`: 115
* `threat_events`: 0 (unpopulated)
* `trust_history`: 0 (unpopulated)

### Sequential BigInteger Ledger ID Race Condition
* **The Flaw:** In `backend/app/store.py`, `entry.id` is generated as `len(store.ledger) + 1` before calling `INSERT INTO audit_ledger`. Under high concurrent writes, this causes primary key collisions and fails transactions.
* **Remediation:** Remove Python-side sequence generators; let PostgreSQL `BIGSERIAL` autoincrement the primary key and return it via `RETURNING id` during persistence.

---

## 5. Security Engine Audits

### 5.1 Heuristics Core Heuristics Heuristics
1. **Shannon Entropy Heuristic:** Screens input strings for high randomness typical of base64-encoded binary injections or obfuscated command inputs.
2. **Token Flood Heuristic:** Regex `(.{4,})\1{3,}` detects token floods or repeating payload lines attempting to crash or bypass LLM attention layers.
3. **Regex Pattern Gating:** 40+ compiled rules covering SSRF, Privilege Escalation, Path Traversal, and Shell Injection.

---

## 6. Recommendations and Fix Actions (Ranked by Priority)

### 🔴 High Priority
1. **Implement Proper Key Management (AWS KMS / Cloud HSM):** Replace the single global `private_key` with asymmetric keys provisioned and signed within KMS modules to enable true tenant-isolated identities.
2. **Remove Firebase Auth Backdoors:** Remove the silent fallback unverified claims decode in `firebase_auth.py`. Block login if public key certificates signature validation fails.
3. **Remediate Database N+1 Queries:** Replace the custom `PostgresDict` and `PostgresList` loops that run full table scans on every `values()` iteration with optimized SQL lookups using pagination and `LIMIT / OFFSET`.
4. **Implement psycopg Connection Pooling:** Enable proper psycopg connection pooling to avoid database TCP socket exhaustion under moderate scale.

### 🟡 Medium Priority
1. **Implement Redis Sliding-Window Rate Limiting:** Enforce centralized atomic sliding window limits via Redis Sorted Sets to eliminate uvicorn worker process rate limit split-brain.
2. **Fix Sequential RSA DoS Vector:** Add `kid` assertion on agent JWTs; directly load the matched public key instead of looping through all keys performing trial signature checks.
3. **Decouple Frontend Monolith:** Refactor the single 250KB React `main.tsx` into modular functional folder structures (components, pages, routing hooks).
