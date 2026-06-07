# AgentShield Product Reality Audit

Date: 2026-06-02  
Auditor stance: skeptical enterprise prospect, zero prior knowledge  
Target: http://127.0.0.1:5173 with backend http://127.0.0.1:8000  
Workspace created: Reality Audit Workspace 151016  
Agent created: ResearchAgent / research_agent

## Executive Summary

AgentShield is no longer a pure simulator. A new user can create a workspace, register an agent, create an SDK key, send real SDK-style protected traffic, see a benign message allowed, see a prompt-injection attack blocked, and verify that kill switch revocation rejects future signed requests with `AUTH_AGENT_TOKEN_REVOKED`.

The core security story is credible, but the product still leaks trust through UX copy and inconsistent counters. The most serious product issue is not backend enforcement. It is that some dashboard labels and post-disable metrics imply the wrong thing at the wrong time.

Final verdict: Ready For Staging, not ready for production.

## Grades

| Area | Grade | Reason |
|---|---:|---|
| Product Grade | B- | Core workflow works, but onboarding has confusing auth and copy leaks. |
| Security Credibility Grade | B+ | Real allow/block/revoke/ledger proof exists. UI still misstates some evidence states. |
| UX Grade | C+ | Good information architecture, but stale refresh behavior and misleading labels hurt trust. |
| Trustworthiness Grade | B- | Simulation/live separation is mostly strong; dashboard post-kill counters are misleading. |
| Workflow Success Rate | 83% | 10 of 12 major phases passed; several passed with caveats. |

## Screenshot Evidence

| Ref | Screenshot |
|---|---|
| S1 | `/Users/lol/Documents/Agent Eval/agentshield-landing.png` |
| S2 | `/Users/lol/Documents/Agent Eval/agentshield-post-signup.png` |
| S3 | `/Users/lol/Documents/Agent Eval/agentshield-agent-created.png` |
| S4 | `/Users/lol/Documents/Agent Eval/agentshield-behavior-preruntime.png` |
| S5 | `/Users/lol/Documents/Agent Eval/agentshield-sdk-created.png` |
| S6 | `/Users/lol/Documents/Agent Eval/agentshield-dashboard-before-runtime.png` |
| S7 | `/Users/lol/Documents/Agent Eval/agentshield-attack-sim-after-all.png` |
| S8 | `/Users/lol/Documents/Agent Eval/agentshield-dashboard-after-sim.png` |
| S9 | `/Users/lol/Documents/Agent Eval/agentshield-dashboard-after-real-runtime.png` |
| S10 | `/Users/lol/Documents/Agent Eval/agentshield-behavior-after-runtime.png` |
| S11 | `/Users/lol/Documents/Agent Eval/agentshield-post-relogin.png` |
| S12 | `/Users/lol/Documents/Agent Eval/agentshield-ledger-final.png` |

## Network Evidence

| Step | Request Evidence | Result |
|---|---|---|
| Signup Firebase attempt | `POST identitytoolkit.googleapis.com/...accounts:signUp` | 400 |
| Signup backend fallback | `POST /api/v1/auth/signup` | 200 |
| Agent creation | `POST /api/v1/agents` | 200; returned `live_connected:false` |
| Runtime evidence pre-runtime | `GET /api/v1/agents/{id}/runtime-evidence` | 200; all false/zero/never |
| SDK key creation | `POST /api/v1/api-keys` | 200; full key shown once, list masks key |
| Simulations | five `POST /api/v1/attack-sim/run` calls | all 200 |
| Real benign runtime | `POST /v1/shield/analyze` | 200; `allowed:true`, `verdict:ALLOWED`, `trust_score_after:1.0` |
| Real prompt injection | `POST /v1/shield/analyze` | 200; `allowed:false`, `verdict:BLOCKED`, `trust_score_after:0.85` |
| Kill switch | `POST /api/v1/agents/{id}/disable` | 200 |
| Post-kill retry | `POST /v1/shield/analyze` | 401; `AUTH_AGENT_TOKEN_REVOKED` |
| Relogin | `POST /api/v1/auth/login` | 200 |
| Ledger verify | `GET /api/v1/ledger/verify` and ledger UI | verified, 15 entries |

## Pass / Fail Matrix

| Phase | Expected | Actual | Pass/Fail | Severity |
|---|---|---|---|---|
| Landing page | First-time visitor understands product in 30 seconds | Clear value prop: identity, permissions, ledger, runtime security | Pass | - |
| Landing proof claims | Marketing examples should not look like customer data | Shows sample `trust_score 0.72->0.57` and hash-chain verified visual | Partial | P2 |
| Signup | Create workspace without hidden errors | Backend signup succeeds, but Firebase request fails 400 in console first | Partial | P2 |
| Session refresh | Session persists after refresh | Authenticated console remains after direct refresh | Pass | - |
| Agent creation | Registered agent appears, no fake score | Registry shows N/A and not connected | Pass | - |
| Agent success copy | Should say registered, not protected | Success panel says `ResearchAgent is now protected` before runtime | Fail | P1 |
| Behavior pre-runtime | SDK false, runtime false, requests 0, threats 0 | Exact expected values shown | Pass | - |
| SDK key workflow | Generate key without refresh; no runtime activity implied | Key generated and masked later; drawer button only navigates to Settings, not SDK tab | Partial | P2 |
| Dashboard before runtime | Protected events 0, threats 0, connected agents 0 | Counts are zero; but chart says `100% blocked` and `Active shielding` | Partial | P2 |
| Attack simulator | Simulations clearly labeled and isolated from live metrics | Five sim calls succeed; live counters remain zero; ledger rows source `simulation` | Pass | - |
| Real runtime allow | `Hello` allowed; evidence updates | Backend allows; after direct refresh dashboard shows 2 live events total | Pass | - |
| Real attack block | Injection blocked; threat generated | Backend blocks and trust drops; dashboard shows 1 live threat after direct refresh | Pass | - |
| Client auto-refresh | External runtime traffic should become visible without manual hard refresh | Dashboard remained stale until direct navigation | Fail | P2 |
| Kill switch | Disable agent, future signed requests rejected | Backend returns 401 `AUTH_AGENT_TOKEN_REVOKED` | Pass | - |
| Kill switch UI | Disabled agent should not look live | Table shows lifecycle `Disabled` but connection still `Live` green | Fail | P1 |
| Evidence after kill | Historical live evidence remains visible | Ledger keeps live rows; dashboard top counters reset to 0 and says no live threats | Fail | P1 |
| Logout/login persistence | State persists after relogin | Agent, ledger, and rows persist; dashboard still has post-kill counter issue | Partial | P1 |

## Issues

### P1 - Disabled Agent Still Shows Green Live Connection

Expected: Disabled agent should show revoked/disabled, not live.  
Actual: After kill switch, row says `Connection: Live` and `Lifecycle: Disabled`.

Impact: A buyer sees contradictory state for the most important emergency control.

### P1 - Dashboard Hides Historical Live Evidence After Kill Switch

Expected: Historical protected requests and blocked threats remain visible, with agent state disabled.  
Actual: After refresh/relogin, dashboard shows `Live protected events: 0`, `Live threats: 0`, `Live connected agents: 0`, while event feed and ledger still show live runtime rows #18 and #19.

Impact: Makes evidence look lost even though ledger proves it exists.

### P1 - Post-Registration Copy Overclaims Protection

Expected: `Agent registered. Connect SDK traffic to activate protection.`  
Actual: Success panel says `ResearchAgent is now protected. Your code is ready to run.`

Impact: Reinforces the exact simulator illusion the product is trying to avoid.

### P2 - Firebase Auth Attempts Fail Before Backend Fallback

Expected: If local/backend auth is primary, no failed Firebase call should occur.  
Actual: Signup and login both attempt Firebase first and produce 400 console errors, then backend auth succeeds.

Impact: Enterprise evaluators see broken auth integration in devtools.

### P2 - Dashboard Shows 100% Blocked / Active Shielding With Zero Runtime Traffic

Expected: Before runtime traffic, chart status should say `No runtime traffic yet`.  
Actual: Dashboard says `Threats Intercepted: 0 / 100% blocked` and `Shield Integrity: 100% Active shielding`.

Impact: Empty-state percentage math creates false confidence.

### P2 - SDK / REST Guidance Is Incomplete

Expected: A new user can reproduce the runtime call from visible docs.  
Actual: The UI snippet is helpful for SDK users but does not reveal exact REST headers/body. Manual testing found the working layout: `X-AgentShield-Api-Key`, `Authorization: Bearer <agent token>`, and body including `direction`.

Impact: Raw REST users will fail with `AUTH_API_KEY_MISSING` or validation errors.

### P2 - External Runtime Updates Require Manual Reload

Expected: Dashboard should refresh or stream updates after SDK traffic.  
Actual: Real runtime calls did not update the active dashboard until direct navigation.

Impact: Demo can look broken immediately after a successful SDK call.

### P3 - Drawer Button Does Not Open SDK API Keys Tab

Expected: `Generate SDK API Key` opens Settings directly on SDK API Keys.  
Actual: It opens Settings on General; user must click SDK API Keys manually.

Impact: Small onboarding friction.

### P3 - Login Form Prefills Unrelated Credentials

Expected: Empty login form or browser-managed autofill only.  
Actual: Login screen initially showed unrelated `ui-score-...` credentials.

Impact: Looks like test data leakage.

## What Felt Trustworthy

- Runtime Evidence panel is excellent before traffic: false/false/never/0.
- Registry score gating works: no A+/100% before runtime.
- Simulator is clearly labeled internal and source-labeled in ledger.
- Real SDK-style traffic actually changes backend state.
- Prompt injection block is real and lowers trust score.
- Kill switch backend enforcement is real: revoked token returns 401.
- Ledger shows setup, simulation, live runtime, and kill-switch rows with chain verification.

## What Felt Fake Or Misleading

- Marketing sample trust-score and hash-chain visuals look like proof before a workspace exists.
- `Active shielding` and `100% blocked` appear with zero runtime traffic.
- `ResearchAgent is now protected` appears immediately after registration.
- Disabled agent still appears green/live.
- Dashboard counters after kill switch imply no live runtime history even while event feed/ledger show it.

## Recommended Fix Order

1. Fix disabled-agent connection status: disabled must override live connection display.
2. Split dashboard counters into `Current live connected agents`, `Historical protected requests`, and `Historical blocked threats`.
3. Replace post-registration copy with `Registered, awaiting SDK traffic`.
4. Remove or gate Firebase attempts when backend auth is active.
5. Replace empty-state `100% blocked` and `Active shielding` with `No runtime traffic yet`.
6. Add an explicit REST/cURL integration panel with exact headers and body.
7. Make dashboard refresh from WebSocket/polling after external SDK traffic.
8. Make `Generate SDK API Key` navigate directly to the SDK API Keys tab.
9. Remove hardcoded/test login prefill.

## Final Verdict

Ready For Staging.

Not ready for production because trust-state UI has contradictions around post-registration, empty dashboard percentages, and kill-switch aftermath. The backend security flow is materially credible; the product layer still needs to stop implying protection or evidence states that are not exactly true.
