<!-- Operational documentation for workspace setup -->
# AgentShield API Keys And Free Setup

This project should run locally without paid services. External provider keys are optional unless you enable the related feature.

## Required For Local Development

### AgentShield workspace API key
- Created by AgentShield itself after signup or login.
- Used by the frontend, SDK, and REST examples as `AGENTSHIELD_API_KEY`.
- Do not create this manually in an external console.

### API_KEY_PEPPER
- Required for production because AgentShield hashes workspace API keys.
- Free option: generate locally.

```bash
python3 - <<'PY'
import secrets
print(secrets.token_urlsafe(48))
PY
```

Set:

```bash
API_KEY_PEPPER=<generated value>
```

## Optional Free / Local Services

### PostgreSQL
- Purpose: durable tenants, users, agents, tokens, ledger, outbox, keys, invites.
- Free local option: run Postgres locally or use the included `docker-compose.yml` when Docker is installed.
- Free hosted option: Neon provides a Postgres connection string from the project dashboard.

Set:

```bash
DATABASE_URL=postgresql://user:password@host:5432/dbname?sslmode=require
```

### Redis
- Purpose: distributed rate limiting across multiple backend instances.
- Free local option: local Redis.
- Free hosted option: Upstash Redis. The current backend expects a Redis protocol URL, not Upstash REST variables.

Set:

```bash
REDIS_URL=redis://host:6379/0
```

Production status:
- `/ready` reports `redis.configured`, `redis.connected`, and `redis.mode`.
- If `REDIS_URL` is missing, AgentShield still runs with the in-process fallback, but this is not multi-instance production rate limiting.

## Optional LLM Chat Provider

### Groq
- Purpose: production chat copilot responses.
- Current env vars:

```bash
GROQ_API_KEY=<from Groq console>
GROQ_MODEL=llama-3.3-70b-versatile
```

Notes:
- Groq is wired through its OpenAI-compatible endpoint.
- If Groq returns a provider-side `403`, AgentShield falls back to the local assistant.
- Rotate any key pasted into chat before production use.

### Tavily
- Purpose: execute allowed `web_search` tool calls after AgentShield gates them.
- Used by `/v1/agent/run` only after the tool manifest allows `web_search:read`.

```bash
TAVILY_API_KEY=<from Tavily dashboard>
```

Notes:
- If this is missing, AgentShield still records the allow/block tool decision but returns a `TAVILY_API_KEY is not configured` execution result.
- Blocked tools are never executed, even if Tavily or another executor is configured.

### OpenAI
- Purpose: fallback chat copilot provider.

```bash
OPENAI_API_KEY=<from OpenAI platform>
OPENAI_MODEL=gpt-4o-mini
```

## Optional Firebase Auth

### Frontend Firebase config
- Purpose: Google sign-in and Firebase email/password sign-in.
- Firebase web API keys identify the Firebase app/project; Firebase authorization still depends on Firebase Auth, IAM, rules, and App Check.

Set in frontend env:

```bash
VITE_FIREBASE_API_KEY=
VITE_FIREBASE_AUTH_DOMAIN=
VITE_FIREBASE_PROJECT_ID=
VITE_FIREBASE_STORAGE_BUCKET=
VITE_FIREBASE_MESSAGING_SENDER_ID=
VITE_FIREBASE_APP_ID=
```

### Backend Firebase verification
- Purpose: verify Firebase ID tokens server-side.
- Production requires `firebase-admin` plus a configured Firebase project.

```bash
FIREBASE_PROJECT_ID=<project id>
ALLOW_UNVERIFIED_FIREBASE_AUTH=false
```

Only set `ALLOW_UNVERIFIED_FIREBASE_AUTH=true` for local sandbox testing.

## Optional KMS / HSM Key Custody

### Free local option
- Use app-generated dev keys only for local testing.

### Production option
- Use a real KMS/HSM or self-hosted secret manager.
- AWS KMS customer-managed keys are not a free-only dependency for asymmetric signing workloads.
- Self-hosting Vault/OpenBao is the closest free infrastructure option, but it still requires operational setup.

```bash
KMS_KEY_ARN=<provider key id or arn>
SIGNING_KEY_PROVIDER=kms
```

Production status:
- `/ready` reports `signing_key_provider` and `kms_hsm`.
- `SIGNING_KEY_PROVIDER=kms` requires AWS credentials and `KMS_KEY_ARN`.
- Without this, AgentShield uses encrypted local/serverless key custody when `KEY_ENCRYPTION_KEY` is set, but not external HSM/KMS custody.

## Optional Enterprise Identity

### OIDC SSO
- Purpose: redirect users through a real external identity provider.
- Supported through generic OIDC discovery.

```bash
OIDC_ISSUER_URL=https://your-idp.example.com
OIDC_CLIENT_ID=<client id>
OIDC_CLIENT_SECRET=<client secret>
OIDC_REDIRECT_URI=https://agentshield.example.com/api/v1/sso/oidc/callback
```

Endpoints:
- `GET /v1/sso/oidc/config`
- `GET /v1/sso/oidc/login`
- `GET /v1/sso/oidc/callback`

### SCIM
- Purpose: directory-style user provisioning.
- Workspace API-key protected SCIM endpoints are available for automation:

```bash
GET  /v1/scim/v2/Users
POST /v1/scim/v2/Users
```

Set `SCIM_BEARER_TOKEN` when connecting a dedicated enterprise SCIM gateway/provider.

## Audit Export And SIEM

### Audit export
- Tenant-scoped audit export is available in both JSON and CSV.

```bash
GET /v1/enterprise/audit-export?format=json
GET /v1/enterprise/audit-export?format=csv
```

### SIEM export
- Configure a signed webhook URL under Settings.
- Blocked security events and webhook test events are signed with `X-AgentShield-Signature`.
- `/v1/enterprise/readiness` reports whether SIEM export is configured.

## App URLs

```bash
FRONTEND_URL=http://localhost:5173
ALLOWED_ORIGINS=http://localhost:5173,http://127.0.0.1:5173
```

## Local-Only Dev Login

Disabled by default. Enable only for local sandbox usage:

```bash
VITE_ENABLE_DEV_LOGIN=true
VITE_DEV_EMAIL=local@example.test
VITE_DEV_PASSWORD=<local password>
VITE_DEV_WORKSPACE=Local Workspace
```
