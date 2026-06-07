# AgentShield API And Event Contracts

Authoritative schemas for REST, WebSocket, SDK, database, errors, and event payloads.

Version 1.0 | 2026-05-29

# 1. Contract Rules

- All production endpoints require X-AgentShield-API-Key unless explicitly marked public.
- Agent-acting endpoints also require an RS256 agent JWT in Authorization: Bearer <token>.
- Every protected decision returns a verdict and writes a ledger entry before returning success.
- All timestamps are ISO 8601 UTC strings. All IDs are UUID strings unless noted.
- All errors use the standard error envelope defined in this document.

# 2. Authentication Headers

| Header | Required For | Format | Validation |
| --- | --- | --- | --- |
| X-AgentShield-API-Key | All non-public REST and WebSocket handshakes | as_live_<token> | Hash lookup, tenant active, scope allowed, rate limit not exceeded. |
| Authorization | Agent message, tool-call, trust, and agent-specific requests | Bearer <RS256 JWT> | Signature, kid, issuer, audience, exp, jti, tenant_id, agent_id, status. |
| X-Request-Id | Recommended all requests | Client UUID | Echoed in response and event metadata. |

# 3. Core REST Endpoints

| Method | Path | Purpose | Auth | Success Response |
| --- | --- | --- | --- | --- |
| POST | /v1/agents | Spawn/register protected agent. | API key | AgentResponse |
| GET | /v1/agents | List agents for tenant. | API key | AgentListResponse |
| POST | /v1/agents/{agent_id}/revoke | Revoke agent and active JWT ids. | API key | AgentResponse |
| POST | /v1/shield/analyze | Evaluate an incoming or outgoing message. | API key + JWT | SecurityVerdict |
| POST | /v1/shield/tool-call | Authorize a tool call before execution. | API key + JWT | SecurityVerdict |
| GET | /v1/ledger | Paginated audit ledger. | API key | LedgerPage |
| GET | /v1/ledger/verify | Verify ledger hash chain. | API key | LedgerVerification |
| GET | /v1/threats | List threat events. | API key | ThreatPage |
| POST | /v1/attack-sim/run | Run curated or custom attack against sandbox agent. | API key | AttackSimulationResult |
| GET | /health | Service health for deploy checks. | Public | HealthResponse |

# 4. Request And Response Schemas

| Schema | Fields |
| --- | --- |
| AgentCreateRequest | name: string; type: user_agent|research_agent|executor_agent|security_agent|custom; permissions: PermissionManifest; metadata?: object |
| AgentResponse | agent_id: uuid; tenant_id: uuid; name: string; status: active|suspended|revoked; trust_score: number; token: string; token_expires_at: datetime; permissions: PermissionManifest |
| PermissionManifest | tools: object where each key is a tool name and value is allowed action array; default_action: deny; max_risk_level?: low|medium|high |
| AnalyzeRequest | agent_id: uuid; direction: inbound|outbound|inter_agent; message: string; context?: object; deep_analysis?: boolean |
| ToolCallRequest | agent_id: uuid; tool_name: string; action: string; arguments_hash?: string; risk_context?: object |
| SecurityVerdict | allowed: boolean; verdict: ALLOWED|BLOCKED|FLAGGED; threat_level: NONE|LOW|MEDIUM|HIGH|CRITICAL; reason: string; evidence: Evidence[]; trust_delta: number; trust_score_after: number; ledger_id: integer; latency_ms: integer; async_enrichment_id?: uuid |
| Evidence | source: pattern|permission|identity|trust|llm|manual; code: string; message: string; confidence?: number; span?: string |
| LedgerEntry | id: integer; tenant_id: uuid; agent_id?: uuid; event_type: message|tool_call|inter_agent|auth|system; severity: INFO|WARN|CRITICAL; verdict: ALLOWED|BLOCKED|FLAGGED; event_data: object; prev_hash: string; curr_hash: string; created_at: datetime |
| ErrorEnvelope | error: {code: string; message: string; request_id?: string; details?: object} |

# 5. Error Codes

| Code | HTTP | Meaning |
| --- | --- | --- |
| AUTH_API_KEY_MISSING | 401 | X-AgentShield-API-Key was not provided. |
| AUTH_API_KEY_INVALID | 401 | API key hash not found or inactive. |
| AUTH_AGENT_TOKEN_INVALID | 401 | JWT signature, issuer, audience, expiry, or jti failed validation. |
| AUTH_AGENT_TOKEN_REVOKED | 401 | JWT jti or agent status is revoked. |
| POLICY_TOOL_DENIED | 403 | Requested tool or action is not in the permission manifest. |
| POLICY_MESSAGE_BLOCKED | 403 | Message was blocked by injection or trust policy. |
| LEDGER_APPEND_FAILED | 500 | Ledger append transaction failed; protected decision must not proceed silently. |
| RATE_LIMITED | 429 | Tenant or API key exceeded configured limit. |

# 6. WebSocket Events

| Event | Payload Fields | Use |
| --- | --- | --- |
| security.event.created | event_id, ledger_id, agent_id, event_type, severity, verdict, threat_level, created_at | Live feed and counters. |
| agent.trust.updated | agent_id, previous_score, delta, score_after, reason, created_at | Node color and trust chart. |
| ledger.verification.completed | valid, entries_checked, broken_at, checked_at | Ledger page verify UI. |
| attack_sim.completed | simulation_id, attack_type, detected, verdict, latency_ms, ledger_id | Attack simulation results. |
| system.health.changed | component, status, message, created_at | Status bar and operational alerts. |

# 7. Database Tables

| Table | Purpose | Important Constraints |
| --- | --- | --- |
| tenants | Customer/workspace boundary. | id primary key; status active/suspended. |
| api_keys | Client credentials. | token_hash only; never store raw key; scopes; last_used_at. |
| agents | Agent registry and current trust. | tenant_id foreign key; status enum; trust_score 0.0 to 1.0. |
| agent_tokens | JWT jti registry and revocation. | jti unique; expires_at; revoked_at nullable. |
| permission_manifests | Versioned permissions. | agent_id; version; manifest jsonb; active flag. |
| audit_ledger | Immutable proof log. | curr_hash unique; no update/delete role; trigger rejects mutation. |
| threat_events | Queryable incidents. | ledger_id foreign key; attack_type; confidence; resolved state. |
| trust_history | Trust score changes. | score_after check 0.0 to 1.0; ledger_id link. |
| event_outbox | Reliable WebSocket/event dispatch. | processed_at nullable; retry_count. |

# 8. SDK Contract

| Method | Input | Output |
| --- | --- | --- |
| spawn_agent | name, permissions, metadata | Agent object with id, token, expires_at. |
| analyze | agent_id, token, message, direction, context, deep_analysis | SecurityVerdict; raises SecurityBlocked when allowed is false if configured. |
| check_tool_call | agent_id, token, tool_name, action, arguments | SecurityVerdict. |
| verify_ledger | optional start/end ids | LedgerVerification. |
| run_attack_sim | attack_type or payload | AttackSimulationResult. |

# 9. Contract Invariants

- A BLOCKED verdict is final for the protected request. Async enrichment may add explanation, but it must not convert a blocked action into an allowed action without a separate audited admin override.
- A FLAGGED verdict means execution may continue only when the caller has explicitly configured allow_on_flagged for that route. The default is to stop and require operator review.
- Every SecurityVerdict must include ledger_id. If the ledger write fails, the protected request must fail closed with LEDGER_APPEND_FAILED.
- Frontend code must treat unknown enum values as unsafe: unknown severity renders as WARN, unknown verdict renders as BLOCKED, and unknown event_type renders as system.
- SDK clients must expose raw response bodies for debugging but must redact API keys and JWTs in exception messages.

# 10. Example Protected Tool-Call Request

| Field | Example | Notes |
| --- | --- | --- |
| agent_id | 6d4f8a7e-2f19-4a4e-8bd2-9d9c7e4f8a10 | Must match JWT agent_id claim. |
| tool_name | web_search | Exact registered tool name, not display label. |
| action | read | Action checked against permission manifest. |
| arguments_hash | sha256:ab12... | Hash avoids logging sensitive arguments while preserving auditability. |
| risk_context | {"destination":"external"} | Optional structured context for policy and audit. |
