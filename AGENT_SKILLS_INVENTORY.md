# Lakshya Engineering Stack - Codex Skills Inventory

**Bundle name:** Lakshya Engineering Stack  
**Updated:** 2026-06-03  
**Skills CLI:** `skills` v1.5.10 at `/Users/lol/.nvm/versions/node/v22.22.3/bin/skills`  
**Global install roots:** `/Users/lol/.codex/skills`, `/Users/lol/.agents/skills`  
**Codex visibility check:** `skills ls -g -a codex --json`  
**Restart Codex required:** Yes, after installing or updating skills

## Executive Decision

Do not install every skill from skills.sh.

The current setup already contains the core engineering stack. I added only three complementary, high-signal skills from skills.sh marketplace and avoided duplicates. The practical working bundle is the 24-skill "Lakshya Engineering Stack" below; additional global skills remain available, but they should not be treated as the default context for every task.

## Newly Installed From skills.sh

| Skill | Source | Purpose | Dependencies | Security / risk | Potential conflicts |
|---|---|---|---|---|---|
| `vercel-react-best-practices` | `vercel-labs/agent-skills` | React and Next.js performance rules from Vercel Engineering: waterfalls, bundle size, rendering, hydration, data fetching. | None beyond Codex skill loading. | Gen Safe, Socket 0 alerts, Snyk Low Risk. | Overlaps with `react-expert`; use this when Vercel/Next.js performance specifics matter. |
| `github-actions-docs` | `xixu-me/skills` | Docs-grounded GitHub Actions guidance for workflow syntax, runners, secrets, OIDC, deployments, reusable workflows, and migrations. | Uses live GitHub docs when answering Actions questions. | Gen Safe, Socket 0 alerts, Snyk Medium Risk. Keep installed because it is docs/reference oriented and useful, but prefer official docs citations. | Overlaps with `devops-cicd` and `gh-fix-ci`; use `gh-fix-ci` for real failing CI logs. |
| `webapp-testing` | `anthropics/skills` | Playwright-based local webapp verification, screenshots, browser logs, and server lifecycle helpers. | Python Playwright runtime when executing browser tests. | Gen Safe, Socket 0 alerts, Snyk Low Risk. | Overlaps with `testing-strategy`, `playwright`, and Browser plugin; use this for local webapp test workflows. |

## Core Lakshya Engineering Stack

These are the highest-value skills for the requested Codex setup. They cover software engineering, full-stack development, React, TypeScript, Python, FastAPI, PostgreSQL, testing, debugging, security, codebase analysis, refactoring, docs, GitHub, and DevOps without turning the environment into a skill dump.

| Skill | Primary use | Source | Dependencies | Conflict guidance |
|---|---|---|---|---|
| `architecture-review` | System design, API boundaries, coupling, scalability, ADR-style review. | Custom `/Users/lol/.codex/skills` | None | Use before large refactors or platform changes. |
| `codebase-refactor` | Safe refactoring, file splitting, deduplication, preserving behavior. | Custom | `testing-strategy` recommended | Do not use before tests or smoke checks exist. |
| `scientific-debugging` | Repro-first debugging, hypothesis testing, root cause isolation. | Custom | None | Use for bugs before broad rewrites. |
| `typescript-expert` | Strict TS/TSX, generics, Zod, tsconfig, typed APIs. | Custom | None | Pair with `react-expert` for React work. |
| `react-expert` | React hooks, components, state, accessibility, Vite/Next patterns. | Custom | None | Pair with `vercel-react-best-practices` for performance-heavy React/Next work. |
| `vercel-react-best-practices` | Next.js/React performance and bundle rules. | `vercel-labs/agent-skills` | None | Supplement, not replacement, for `react-expert`. |
| `python-fastapi` | FastAPI, Pydantic, async services, pytest, API hardening. | Custom | None | Main skill for AgentShield backend work. |
| `postgresql-expert` | PostgreSQL schema, migrations, indexes, EXPLAIN, RLS, pgBouncer. | Custom | None | Use for DB persistence and performance audits. |
| `testing-strategy` | Test architecture across pytest, Vitest, Playwright, CI. | Custom | None | Strategy layer; use tool-specific skills for execution. |
| `webapp-testing` | Browser verification for local web apps using Playwright. | `anthropics/skills` | Playwright runtime | Execution layer; keep reports concise. |
| `playwright` | Browser automation and UI validation. | OpenAI curated/preinstalled | Browser/runtime support | Use when the task explicitly needs browser control. |
| `playwright-interactive` | Step-by-step browser debugging. | OpenAI curated/preinstalled | Browser/runtime support | Use for uncertain UI flows. |
| `security-best-practices` | OWASP-style code security review. | OpenAI curated/preinstalled | None | General app security. |
| `security-threat-model` | STRIDE threat modeling. | OpenAI curated/preinstalled | None | Use for new architecture or risky features. |
| `agent-security-audit` | AI agent security: prompt injection, tool abuse, identity, ledger, kill switch. | Custom | `security-best-practices`, `security-threat-model` helpful | Main skill for AgentShield credibility audits. |
| `security-ownership-map` | Git history ownership and security-critical areas. | OpenAI curated/preinstalled | Git repo history | Useful before production security reviews. |
| `performance-profiler` | Latency, bundle size, DB query, React render profiling. | Custom | `postgresql-expert`, `react-expert` helpful | Use after functional correctness is proven. |
| `docs-generator` | README, ADRs, docstrings, OpenAPI, runbooks. | Custom | None | Use for repo docs, not Notion workflows. |
| `openai-docs` | Current OpenAI API docs and SDK guidance. | OpenAI/system/preinstalled | Web/docs lookup | Use for OpenAI product/API facts. |
| `github-actions-docs` | Official-docs-grounded GitHub Actions authoring and security. | `xixu-me/skills` | Live docs lookup | Use for docs/YAML guidance, not failing log triage. |
| `gh-fix-ci` | Diagnose and fix failing GitHub Actions CI. | OpenAI curated/preinstalled | GitHub access/CLI when needed | Use for real CI failures. |
| `gh-address-comments` | Address GitHub PR review comments. | OpenAI curated/preinstalled | GitHub access/CLI when needed | Use only for PR review loops. |
| `devops-cicd` | CI/CD, Docker, deployment strategy, secrets, release automation. | Custom | None | Broad strategy; pair with platform-specific deploy skills. |
| `saas-startup-review` | YC/startup product audit, onboarding, pricing, SaaS GTM. | Custom | None | Use for product strategy and adoption UX. |

## Additional Global Skills Available

These are installed and Codex-visible but are not part of the default top-stack decision.

| Skill | Purpose |
|---|---|
| `instructions-ai` | User's global instruction system for Codex/OpenCode workflows. |
| `define-goal` | Structured goal definition. |
| `cli-creator` | CLI creation patterns. |
| `cloudflare-deploy` | Cloudflare deployment. |
| `develop-web-game` | Browser game development. |
| `figma`, `figma-implement-design` | Figma and design-to-code workflows. |
| `imagegen`, `sora` | Image/video generation workflows. |
| `jupyter-notebook` | Notebook operations. |
| `linear` | Linear issue management. |
| `migrate-to-codex` | Migration from other AI tool workflows. |
| `netlify-deploy`, `render-deploy`, `vercel-deploy` | Platform-specific deployment helpers. |
| `notion-knowledge-capture`, `notion-research-documentation`, `notion-spec-to-implementation` | Notion workflows. |
| `pdf`, `screenshot` | Document extraction and visual capture helpers. |
| `sentry` | Sentry issue triage. |
| `yeet` | GitHub push workflow helper. |

## Marketplace Search Summary

Searched and reviewed skills.sh marketplace coverage for:

- Software engineering and architecture: `mattpocock/skills@improve-codebase-architecture`, `wshobson/agents@architecture-patterns`.
- React: `vercel-labs/agent-skills@vercel-react-best-practices`.
- FastAPI/Python: `wshobson/agents@fastapi-templates`, `mindrally/skills@fastapi-python`, `fastapi/fastapi@fastapi`.
- PostgreSQL: `wshobson/agents@postgresql-table-design`, `github/awesome-copilot@postgresql-optimization`.
- Testing: `anthropics/skills@webapp-testing`, `wshobson/agents@python-testing-patterns`, `wshobson/agents@e2e-testing-patterns`.
- Security: Firebase rules, OpenClaw skill vetting, Better Auth security, and security review skills.
- Git/GitHub: `xixu-me/skills@github-actions-docs`, Git commit/CLI/documentation skills.
- Agent ecosystems: LangGraph persistence, human-in-the-loop, docs, and CLI skills.
- SaaS billing: Stripe best practices and Stripe integration skills.

Installed only the three skills that added meaningful coverage without duplicating the existing custom stack.

## Deliberately Not Installed

| Candidate | Reason |
|---|---|
| FastAPI marketplace skills | Existing `python-fastapi` already covers this stack and local conventions better. |
| PostgreSQL marketplace skills | Existing `postgresql-expert` is already targeted at Alembic, indexing, performance, and RLS. |
| Architecture marketplace skills | Existing `architecture-review` plus `codebase-refactor` cover the practical workflow. |
| Extra testing pattern skills | Existing `testing-strategy`, `playwright`, and new `webapp-testing` are enough. |
| Firebase-specific security skills | Not globally useful enough for all Codex projects. |
| LangGraph skills | Good future candidate, but too narrow for global install until AgentShield's Connect Agent flow prioritizes LangGraph implementation. |
| Stripe skills | Good future candidate when billing/metering implementation starts; not installed now to avoid premature context load. |
| Novelty or non-stack skills | Excluded by design. |

## Project-Specific Recommendations

### AgentShield

Recommended future installs only when implementation starts:

| Skill area | Why it matters |
|---|---|
| LangGraph/CrewAI/OpenAI Agents/MCP integration skills | Support "Connect Existing Agent" adoption paths without forcing users to read docs. |
| LLM evaluation and red-team corpus skill | Verify prompt-injection/tool-abuse behavior with real attack suites. |
| SOC 2 / compliance evidence skill | Convert ledger, auth, and incident workflows into buyer-facing control evidence. |
| KMS/Vault operations skill | Help replace app-managed private keys with enterprise-grade custody. |
| Stripe metering skill | Usage billing for protected agent requests. |

### Hiring Wallah

| Skill area | Why it matters |
|---|---|
| ATS integrations | Greenhouse, Lever, Workday webhook/import workflows. |
| Resume parsing/NLP | Structured extraction from messy resumes and job descriptions. |
| Fairness and bias evaluation | Hiring workflows need measurable adverse-impact checks. |
| Email/SMS lifecycle automation | Candidate communication and interview scheduling. |

### AI Agents

| Skill area | Why it matters |
|---|---|
| LangGraph persistence / HITL | Durable agent workflows and review gates. |
| MCP server/client development | Tool integration surface for agent products. |
| Evals and observability | Track model, prompt, tool, and safety regressions. |

### Security Platforms

| Skill area | Why it matters |
|---|---|
| OWASP API Security | Hardens public API surfaces. |
| SIEM/SOC integrations | Makes alerts useful to enterprise security teams. |
| Incident response runbooks | Converts detections into operational workflows. |
| Secrets scanning and supply-chain review | Prevents accidental key and dependency exposure. |

### SaaS / YC-Style Startup Development

| Skill area | Why it matters |
|---|---|
| Product onboarding audit | Optimizes time-to-first-value. |
| Usage analytics / funnels | Tracks activation and retention. |
| Pricing and packaging | Converts technical value into buyer language. |
| Stripe billing / metering | Enables real SaaS monetization. |

## Verification

Commands run:

```bash
npm install -g skills
skills --version
skills ls -g -a codex --json
skills find fastapi
skills find security
skills find react
skills find postgresql
skills find testing
skills find github
skills find architecture
skills find langgraph
skills find stripe
```

Verified results:

- `skills` CLI is installed globally.
- Codex can see 45 global skills:
  - 42 under `/Users/lol/.codex/skills`.
  - 3 newly installed marketplace skills under `/Users/lol/.agents/skills`.
- `skills list` without `-g` correctly reports no project-local skills; this setup is intentionally global.

## Usage Rules

1. Use the smallest relevant skill set for the task.
2. Do not load all skills into context.
3. Prefer custom Lakshya skills for local stack conventions.
4. Prefer marketplace skills only when they provide sharper, docs-backed, or vendor-specific guidance.
5. Before adding more global skills, check for overlap and security risk.

