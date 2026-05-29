# AgentShield Security Threat Model

Trust boundaries, abuse cases, mitigations, ledger guarantees, auth model, and residual risks.

Version 1.0 | 2026-05-29

# 1. Security Objective

AgentShield protects autonomous agent systems from malicious instructions, identity spoofing, unauthorized tool use, and unverifiable behavior. It is a guardrail and audit layer, not a sandbox or full execution isolation system.

# 2. Trust Boundaries

| Boundary | Trusted Side | Untrusted Side | Controls |
| --- | --- | --- | --- |
| Client to AgentShield API | AgentShield backend | SDK callers, browsers, external services | API key auth, TLS, rate limits, body limits, request logging. |
| Agent identity | JWT issuer and verifier | Agent runtime, copied tokens, forged IDs | RS256 signatures, jti registry, short expiry, revocation. |
| Tool execution | Permission engine | Agent-requested tool name/action/arguments | Deny-by-default manifest, server-side check before execution. |
| Ledger | Append transaction and verifier | Application bugs, operators, compromised clients | DB role separation, mutation trigger, hash chain, backups. |
| LLM enrichment | Deterministic verdict already made | Model output and external retrieved context | Async processing, schema validation, no authority to override blocking decision automatically. |

# 3. Primary Threats

| Threat | Attack Example | Mitigation | Residual Risk |
| --- | --- | --- | --- |
| Prompt injection | User asks agent to ignore prior instructions or reveal secrets. | Pattern classifier, semantic enrichment, block high-confidence signatures, evidence capture. | Novel attacks can evade patterns; dataset must evolve. |
| Identity spoofing | Request claims to be a trusted agent using another agent_id. | JWT subject/agent_id match, tenant match, signature verification, revocation. | Stolen token works until expiry unless detected and revoked. |
| Unauthorized tool use | Research agent requests db_write or external transfer. | Deny-by-default permission manifests and action-level checks. | Badly configured manifests can still allow excessive scope. |
| Ledger tampering | Operator updates event_data after a bad decision. | No update/delete role, mutation trigger, hash verification, offsite backups. | Superuser database compromise can bypass app controls. |
| Replay attack | Old allowed verdict is reused for a new action. | JWT expiry, jti registry, request ids, optional nonce for high-risk tools. | Replay prevention depends on client adoption for nonces. |
| Dashboard deception | Frontend displays mocked security state. | Dashboard must consume real APIs or named fixtures in demo mode. | Demo mode must be visibly labeled. |

# 4. Auth And Key Rotation

- API keys are generated once, shown once, and stored as salted hashes with prefix metadata.
- Each API key has tenant_id, scopes, status, created_at, last_used_at, expires_at, and optional allowed origins.
- Agent JWTs use RS256 with kid. Private keys remain backend-only. Public keys are versioned.
- JWT lifetime defaults to 60 minutes. Revocation stores jti and agent_id state.
- Key rotation keeps old public keys valid until all issued tokens expire, then disables the old kid.
- Emergency rotation invalidates active jti rows and marks affected agents as suspended until respawned.

# 5. Ledger Integrity Design

1. The first row uses a fixed genesis prev_hash value stored in configuration and documented in migration history.
2. Each row hash is SHA-256 over canonical JSON event_data, prev_hash, tenant_id, agent_id, event_type, verdict, severity, and created_at.
3. Ledger append occurs in the same transaction as verdict state changes where possible.
4. Concurrent writes use a PostgreSQL advisory lock or serializable transaction to ensure exactly one previous head.
5. Application DB role can INSERT and SELECT audit_ledger but cannot UPDATE or DELETE.
6. A database trigger rejects any UPDATE or DELETE attempt even if a broader role is accidentally used.
7. Verification scans rows in id order and returns valid, entries_checked, first broken id, expected hash, and actual hash.

# 6. Trust Score Rules

| Event | Trust Delta | Notes |
| --- | --- | --- |
| Clean allowed message | +0.005 | Cap positive movement to once per minute per agent. |
| Low-confidence suspicious content flagged | -0.03 | Verdict FLAGGED unless policy says block. |
| High-confidence injection blocked | -0.15 | Verdict BLOCKED; create threat event. |
| Unauthorized tool call blocked | -0.20 | High severity if tool is sensitive. |
| Invalid or spoofed identity | -0.30 | Critical; may suspend agent depending policy. |
| Manual resolve false positive | +0.05 | Audited admin action; never deletes event. |

Trust scores are bounded between 0.0 and 1.0. The first production version uses trust for visibility and risk escalation, not automatic permission expansion. Adaptive permission escalation is deferred until policy review exists.

# 7. Security Acceptance Gates

| Gate | Pass Condition |
| --- | --- |
| Auth | Missing API key, invalid API key, expired JWT, mismatched agent_id, and revoked jti all fail with expected error codes. |
| Policy | Agent cannot call a tool/action absent from manifest. |
| Ledger | Tampered row causes /ledger/verify to return valid=false at the modified row. |
| Latency | Synchronous deterministic path meets target without invoking LLM. |
| Secrets | No raw API keys, private JWT keys, or prompt payload secrets appear in frontend bundle or logs. |

# 8. Incident Response Runbooks

| Incident | Immediate Action | Follow-Up |
| --- | --- | --- |
| API key compromise | Disable key status, identify last_used_at and request logs, create replacement key. | Review tenant events, rotate any linked demo credentials, document blast radius. |
| JWT private key compromise | Disable current kid, revoke active jti rows, suspend affected agents, rotate private/public key pair. | Audit token issuance logs and require agent respawn. |
| Ledger verification failure | Stop protected write path, snapshot database, identify first broken row, compare backup or export. | Treat as security incident until explained by migration/test data. |
| Critical threat spike | Rate limit affected tenant, surface dashboard alert, collect sample evidence. | Tune detector patterns and update curated attack set. |
| LLM enrichment outage | Keep deterministic protection online, mark enrichment degraded in health status. | Retry queued jobs after provider recovery. |

# 9. Residual Risk Register

| Risk | Why It Remains | Owner Action |
| --- | --- | --- |
| No execution sandbox | Original scope excludes isolation of arbitrary tool execution. | Document integration boundary and require host application sandboxing for dangerous tools. |
| Pattern evasion | Attackers can invent new phrasing that avoids curated regexes. | Maintain labeled dataset and use async enrichment to discover new signatures. |
| Operator misuse | Admins may create overly broad manifests. | Add risky-permission warnings and require review for write/destructive tools. |
| Database superuser tampering | Application-level append-only controls cannot stop a fully compromised DB superuser. | Use backups, external hash anchoring, and restricted production DB access. |
