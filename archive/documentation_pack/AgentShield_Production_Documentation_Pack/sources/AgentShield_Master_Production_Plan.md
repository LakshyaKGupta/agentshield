# AgentShield Master Production Plan

Unified product, architecture, UX, security, implementation, rollout, and acceptance plan.

Version 1.0 | 2026-05-29

# 1. Executive Summary

AgentShield is a production-grade security middleware and observability platform for autonomous and multi-agent LLM systems. It protects the runtime boundary where agents receive messages, exchange handoffs, and invoke tools. The system combines deterministic policy enforcement, cryptographic agent identity, prompt-injection detection, append-only audit logging, trust scoring, and a live operator dashboard.

This plan supersedes the prior PRD, TRD, and design document as the authoritative build source. The original documents remain historical inputs. Their strongest ideas are carried forward: real-time threat detection, identity verification, permission enforcement, hash-chained audit proof, 3D trust visualization, and an attack simulation demo. Their contradictions are resolved here into one production v1 plan.

Production v1 principle: block high-confidence unsafe behavior synchronously, log every protected decision, and run slow AI-assisted enrichment asynchronously unless the caller explicitly requests deep analysis.

# 2. Goals And Success Criteria

| Goal | Production Success Criteria | Verification |
| --- | --- | --- |
| Runtime security control | Protected calls are evaluated before execution and unauthorized calls are blocked by default. | Integration tests for message, tool-call, and inter-agent paths. |
| Provable auditability | Every protected decision writes an immutable ledger entry with a verifiable hash chain. | Tamper test breaks verification at the expected entry. |
| Practical latency | P95 synchronous protection path under 200 ms without LLM calls; deep AI enrichment is async or explicitly requested. | Load test on analyze and tool-call endpoints. |
| Operator visibility | Dashboard shows live events, active agents, trust score changes, blocked events, and ledger status. | Browser smoke test and WebSocket event replay. |
| Agent integration | Python SDK can spawn an agent, analyze messages, check tool calls, and fetch verdicts using documented contracts. | SDK example runs end to end against local and deployed backend. |

# 3. Users And Use Cases

| Persona | Need | AgentShield Outcome |
| --- | --- | --- |
| AI security engineer | Catch prompt injection, spoofing, and unsafe tool use before production damage. | Drop-in middleware and dashboard with policy, audit, and detection evidence. |
| AI infrastructure engineer | Add protection without rebuilding existing LangChain/OpenAI agent flows. | SDK and REST contracts that wrap existing message and tool-call paths. |
| Security reviewer | Verify what an autonomous agent did and why a decision was allowed or blocked. | Immutable ledger, evidence fields, verdict details, and verification endpoint. |
| Product/demo evaluator | See a real working system with visible security behavior. | Attack simulator, live event feed, and 3D network visualization backed by real APIs. |

# 4. Production Scope

| Priority | Included Capabilities | Deferred Capabilities |
| --- | --- | --- |
| P0 Core | API key auth, RS256 agent JWT, deterministic injection checks, permission enforcement, trust score updates, ledger writes, ledger verification, Python SDK basics. | Billing, SSO, tenant admin UI, long-term threat intelligence marketplace. |
| P1 Operator Product | Dashboard, ledger browser, attack simulator, WebSocket stream, agent registry, deployment runbook, demo agent. | Full visual no-code policy builder, advanced analytics, mobile-native app. |
| P2 Advanced Intelligence | Async LLM enrichment, ReAct trace for demos, vector-backed threat context, adaptive risk recommendations. | Autonomous remediation without human approval, production sandbox execution isolation. |

The production v1 build must not depend on an LLM call to block obvious attacks, invalid identity, or unauthorized tools. LLM and ReAct behavior is useful for explanation, enrichment, and demo traces, but not for the critical enforcement path.

# 5. Resolved Architecture

| Layer | Decision | Reason |
| --- | --- | --- |
| Client and SDK | Python SDK and direct REST clients authenticate with X-AgentShield-API-Key. | Separates customer/client authorization from agent identity. |
| Agent identity | Each spawned agent receives a signed RS256 JWT with agent_id, tenant_id, scopes, iat, exp, jti, and key id. | Prevents spoofed inter-agent and tool-call requests. |
| Synchronous guard | Fast policy engine verifies API key, JWT, permission manifest, pattern classifier, trust state, and ledger write. | Meets latency target and blocks deterministic risks. |
| Async enrichment | Queue worker runs optional LLM classification, threat enrichment, vector search, and narrative explanation. | Preserves UX without slowing protected execution. |
| Data | PostgreSQL stores agents, API keys, permission manifests, audit ledger, threats, trust history, revoked tokens, and event outbox. | Keeps the production v1 stack deployable and inspectable. |
| Frontend | Next.js dashboard consumes REST and WebSocket APIs; 3D network reads stable agent/event payloads. | Prevents frontend from relying on mocked visual-only state. |

# 6. Core Runtime Flow

1. Client sends a protected request with X-AgentShield-API-Key and, when acting as an agent, an RS256 agent JWT.
2. Auth middleware validates API key status, tenant scope, rate limit bucket, and request body size.
3. Identity verifier validates JWT signature, exp, issuer, audience, jti revocation, tenant match, and agent status.
4. Policy engine evaluates message or tool-call permissions using deny-by-default manifests.
5. Injection detector runs deterministic pattern checks and optionally flags the event for async LLM enrichment.
6. Trust engine computes the delta and stores current score plus a trust history row in the same transaction.
7. Ledger writer appends a hash-chained audit row using a locked previous-head read and immutable DB role.
8. Event outbox emits a WebSocket event after commit; dashboard updates live counters and feeds.

# 7. Frontend And UX Plan

The production dashboard is the first product surface. The landing page is secondary and may reuse dashboard metrics, but the system should open directly into operational value: active agents, blocked threats, trust changes, and ledger health.

| Route | Purpose | Must Show Real Data |
| --- | --- | --- |
| /dashboard | Primary console with 3D network, live feed, metrics strip, and agent side panel. | Agents, events, trust scores, WebSocket status. |
| /ledger | Audit ledger browser with verify-chain action and tamper-demo explanation. | Ledger rows, hashes, verification result. |
| /attack-sim | Security testing terminal with curated attacks and custom payloads. | Attack result, verdict, evidence, latency, ledger id. |
| /agents | Agent registry, status, permissions, trust history, revoke action. | Agent records, manifests, trust history. |
| / | Production landing page with live counters and path into console. | At minimum threat count and system status. |

Mobile behavior must preserve utility. Under 768 px, replace the full Three.js graph with a sortable agent/event list and compact trust indicators. Do not use a static screenshot as the only mobile fallback.

# 8. Implementation Phases

| Phase | Deliverable | Exit Criteria |
| --- | --- | --- |
| 0 - Foundation | Repo scaffold, env template, database migrations, API health, CI checks. | Local backend and frontend boot; migrations apply cleanly. |
| 1 - Security Core | API key auth, agent JWTs, permission manifests, deterministic injection detector. | Protected message and tool-call tests pass. |
| 2 - Ledger And Trust | Immutable audit ledger, chain verification, trust scoring, event outbox. | Tamper test and concurrent ledger-write test pass. |
| 3 - SDK And Demo Agent | Python SDK, demo protected agent, attack fixtures. | SDK example blocks known attacks and logs ledger entries. |
| 4 - Dashboard | Next.js dashboard, ledger browser, attack simulator, WebSocket feed. | Browser smoke test covers core routes using real backend. |
| 5 - Production Readiness | Deployment, monitoring, rate limits, backups, key rotation, incident runbooks. | Production smoke test and readiness checklist pass. |

# 9. Requirement Disposition

| Original Requirement | Disposition | Production v1 Decision |
| --- | --- | --- |
| Prompt injection detector | Carried forward and revised. | Deterministic fast path required; LLM classifier async or explicit deep mode. |
| Agent identity tokens | Carried forward. | RS256 JWT with jti, kid, tenant_id, scopes, expiry, revocation, and rotation. |
| Permission enforcement | Carried forward and tightened. | Deny by default; server-side enforcement before tool execution. |
| Tamper-proof audit ledger | Carried forward and strengthened. | DB-level append-only controls, hash chain, transaction locking, verify API. |
| Threat dashboard and 3D graph | Carried forward as P1. | Uses stable REST/WebSocket data; mobile gets functional list fallback. |
| Attack simulation sandbox | Carried forward as P1. | Runs curated payloads against the real analyze endpoint and writes ledger entries. |
| Trust score engine | Carried forward and specified. | Bounded score from 0.0 to 1.0 with deterministic event deltas. |
| REST API and SDK | Carried forward. | SDK wraps documented endpoints and never hides verdict errors. |
| Alert system | Carried forward as P1/P2. | Severity events now; resolution workflow later. |
| Multiple specialist agents and vector store | Deferred to P2. | Not required for production core; can enrich threat context later. |

# 10. Risks And Controls

| Risk | Control |
| --- | --- |
| LLM latency breaks protection path. | Keep synchronous protection deterministic; enqueue enrichment. |
| Ledger race conditions break hash chain. | Use serializable transaction or advisory lock for append; test concurrent writes. |
| API key or JWT leakage. | Hash API keys at rest, short-lived agent tokens, revocation, rotation, scoped permissions. |
| Dashboard becomes visual-only demo. | All dashboard components must bind to real API contracts or documented fixtures from the backend. |
| Overbroad agent permissions. | Deny by default; require explicit manifest actions; surface risky manifests in UI. |
