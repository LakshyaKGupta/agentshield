# AgentShield Staging Deployment

AgentShield can be staged on Vercel with Neon Postgres. Do not deploy the
frontend alone; the console depends on the FastAPI API, httpOnly session cookies,
CSRF, SDK key issuance, runtime screening, and the append-only ledger API.

## Current Staging

- App: `https://agentshield-sigma.vercel.app`
- API readiness: `https://agentshield-sigma.vercel.app/api/ready`
- Database: Neon Postgres, database `agentshield`
- Runtime: Vercel Python serverless function at `api/index.py`
- Frontend: Vite build output from `frontend/dist`
- Redis: not configured for this staging deployment. Session durability is
  backed by Postgres; rate limiting falls back to per-instance memory.

## Vercel + Neon Shape

The deployment uses:

- `vercel.json` for build/output/rewrite configuration.
- `api/index.py` as a Vercel ASGI adapter.
- `requirements.txt` for Python runtime dependencies.
- Neon pooled `DATABASE_URL` for serverless-safe Postgres access.

Relevant Vercel rewrites:

```json
[
  { "source": "/api/:path*", "destination": "/api/index.py" },
  { "source": "/v1/:path*", "destination": "/api/index.py" },
  { "source": "/ready", "destination": "/api/index.py" },
  { "source": "/health", "destination": "/api/index.py" }
]
```

## Required Services

- Managed PostgreSQL.
- Managed Redis is recommended for production, but optional for staging because
  browser sessions also persist in Postgres.

## Required Environment

Set these on the web service before first boot:

```bash
DEMO_MODE=false
APP_VERSION=0.1.0
DATABASE_URL=postgresql://...
REDIS_URL=redis://... # optional for staging, recommended for production
API_KEY_PEPPER=<random 32+ byte secret>
KEY_ENCRYPTION_KEY=<random 32 byte base64/url-safe secret>
JWT_ISSUER=https://<staging-host>
JWT_AUDIENCE=agentshield-agents
ALLOWED_ORIGINS=https://<staging-host>
FRONTEND_URL=https://<staging-host>
ALLOW_UNVERIFIED_FIREBASE_AUTH=false
AGENTSHIELD_CHAT_LLM_ENABLED=true
GROQ_API_KEY=<optional, for assistant LLM>
TAVILY_API_KEY=<optional, for real web_search tool execution>
```

Firebase values are only required if Google sign-in is enabled:

```bash
FIREBASE_PROJECT_ID=<firebase-project-id>
```

## Deploy On Vercel

```bash
vercel link --yes --project agentshield
vercel env add DATABASE_URL production
vercel env add API_KEY_PEPPER production
vercel env add KEY_ENCRYPTION_KEY production
vercel env add DEMO_MODE production --value false --yes
vercel --prod --yes
```

Health check:

```bash
curl -fsS https://agentshield-sigma.vercel.app/api/ready
```

## Staging Verification

After deployment:

```bash
curl -fsS https://agentshield-sigma.vercel.app/api/ready
```

Expected readiness:

```json
{
  "ready": true,
  "store": "postgres",
  "database": "connected",
  "ledger_valid": true
}
```

Then verify the live runtime path:

1. Sign up on the staging console.
2. Open Protect Agent.
3. Register an agent.
4. Create an SDK key.
5. Run the copied external demo-agent command from a terminal.
6. Open Live Protection and Evidence.

The staging console must show live runtime requests, at least one blocked
threat, and ledger-valid evidence.
