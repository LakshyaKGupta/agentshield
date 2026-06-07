# AgentShield Test And Acceptance Plan

Unit, integration, security, latency, ledger-integrity, browser, and production smoke tests.

Version 1.0 | 2026-05-29

# 1. Test Strategy

AgentShield must be tested as a security control, not only as a web app. The core acceptance standard is that protected actions are either allowed or blocked for explicit, auditable reasons, and every decision can be verified later.

# 2. Unit Test Matrix

| Area | Scenarios |
| --- | --- |
| API key auth | missing, malformed, inactive, wrong scope, expired, rate limited, valid. |
| JWT identity | valid, expired, wrong issuer, wrong audience, wrong agent_id, revoked jti, rotated kid. |
| Permission engine | allowed action, missing tool, missing action, wildcard disallowed, denied default. |
| Injection detector | known injection, benign request, mixed benign/malicious, casing/spacing obfuscation, data exfil phrase. |
| Trust scoring | delta bounds, repeated clean cap, blocked threat penalty, manual resolve recovery. |
| Ledger hashing | canonical ordering, genesis row, changed event_data, changed prev_hash, changed timestamp. |

# 3. Integration Test Matrix

| Flow | Expected Result |
| --- | --- |
| Spawn agent then analyze benign message. | ALLOWED, trust unchanged or small positive, ledger row written. |
| Analyze high-confidence injection. | BLOCKED, CRITICAL or HIGH, threat event written, trust reduced, ledger row written. |
| Check unauthorized tool call. | BLOCKED with POLICY_TOOL_DENIED, trust reduced, ledger row written. |
| Use expired token. | 401 AUTH_AGENT_TOKEN_INVALID, auth ledger event if configured. |
| Verify ledger after normal writes. | valid=true and entries count matches. |
| Tamper a copied test database row. | valid=false and broken_at equals changed row. |
| WebSocket client connected during attack sim. | Receives security.event.created and attack_sim.completed. |

# 4. Security Test Cases

| Test | Pass Condition |
| --- | --- |
| No raw secrets in logs | Search logs for API key prefix, JWT private key markers, and OPENAI_API_KEY returns no leaks. |
| Frontend bundle secret scan | No private env vars or raw keys appear in built JS. |
| CORS enforcement | Unauthorized origins fail browser preflight for protected requests. |
| Rate limit | Burst above configured threshold returns RATE_LIMITED. |
| Body size limit | Oversized payload rejected before classifier work. |
| Mutation protection | Application DB role cannot update or delete audit_ledger. |

# 5. Latency And Load Acceptance

| Endpoint | Target | Conditions |
| --- | --- | --- |
| POST /v1/shield/analyze deterministic path | P95 < 200 ms | No LLM enrichment in request path; includes ledger write. |
| POST /v1/shield/tool-call | P95 < 150 ms | Permission check, trust update, ledger write. |
| GET /v1/ledger | P95 < 300 ms | Paginated first page at 10k rows. |
| GET /v1/ledger/verify | Completes for 10k rows under operational threshold | May be async for larger ledgers. |
| WebSocket event delivery | Visible in dashboard under 1 second | After backend commit. |

# 6. Browser Acceptance

| Route | Desktop Acceptance | Mobile Acceptance |
| --- | --- | --- |
| /dashboard | Shows live counters, event feed, 3D graph or initialized scene, agent panel. | Shows list fallback, counters, event feed, no horizontal overflow. |
| /ledger | Rows load, hash expands, verify action returns result. | Rows are readable in compact layout. |
| /attack-sim | Curated attack runs and produces blocked verdict with evidence. | Payload editor and verdict remain usable. |
| /agents | Agent list, trust history, permissions, revoke action states. | Cards or compact rows fit viewport. |

# 7. Production Smoke Checklist

1. GET /health returns ok from deployed backend.
2. Frontend loads deployed dashboard without console errors.
3. Spawn demo agent using production API key.
4. Analyze benign message and confirm ALLOWED verdict plus ledger id.
5. Analyze curated injection and confirm BLOCKED verdict plus threat event.
6. Run unauthorized tool-call check and confirm BLOCKED verdict.
7. GET /v1/ledger/verify returns valid=true.
8. Open dashboard and confirm the new events appear through WebSocket or fallback polling.
9. Run attack simulator from browser and confirm result matches backend ledger.

# 8. Release Gates

| Gate | Required Evidence |
| --- | --- |
| Contracts frozen | API and event contract doc matches OpenAPI/schema files. |
| Core tests pass | Backend unit/integration/security tests green. |
| Frontend checks pass | Lint/build and browser smoke tests green. |
| Ledger proven | Append, tamper, and concurrency tests green. |
| Production smoke pass | Recorded endpoint responses and dashboard evidence. |
| Rollback known | Documented migration rollback or recovery path for failed release. |

# 9. Curated Attack Dataset Requirements

| Category | Minimum Cases | Expected Behavior |
| --- | --- | --- |
| Instruction override | 10 | High-confidence examples BLOCKED; ambiguous examples FLAGGED. |
| Role hijack | 8 | Attempts to redefine the agent role are BLOCKED or FLAGGED with evidence span. |
| Data exfiltration | 8 | Requests to reveal secrets, prompts, keys, or hidden context are BLOCKED. |
| Tool misuse | 8 | Requests for destructive or unauthorized actions are BLOCKED by permission policy. |
| Benign controls | 20 | Normal task requests remain ALLOWED to track false positives. |

# 10. Acceptance Report Format

- Record git commit, deployment URL, backend version, frontend version, database migration head, and test timestamp.
- Include command outputs or links for backend tests, frontend build, browser smoke, and production smoke.
- List skipped checks with a concrete reason and risk, not just 'not run'.
- Attach the final ledger verification result and at least one blocked attack verdict with ledger_id.
- Record any production defects found during smoke testing as follow-up issues before launch approval.
