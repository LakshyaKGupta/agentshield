-- AgentShield production v1 schema draft.
-- This migration documents the PostgreSQL shape; the first code slice uses an
-- in-memory store so tests can run without a database service.

CREATE TABLE IF NOT EXISTS tenants (
  id UUID PRIMARY KEY,
  name TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'active',
  preferences JSONB NOT NULL DEFAULT '{}',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE tenants ADD COLUMN IF NOT EXISTS preferences JSONB NOT NULL DEFAULT '{}';


CREATE TABLE IF NOT EXISTS api_keys (
  id UUID PRIMARY KEY,
  tenant_id UUID NOT NULL REFERENCES tenants(id),
  token_hash TEXT NOT NULL UNIQUE,
  scopes JSONB NOT NULL,
  status TEXT NOT NULL DEFAULT 'active',
  name TEXT NOT NULL DEFAULT 'Workspace session',
  key_prefix TEXT NOT NULL DEFAULT 'as_live_',
  key_type TEXT NOT NULL DEFAULT 'session',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_used_at TIMESTAMPTZ
);

ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS name TEXT NOT NULL DEFAULT 'Workspace session';
ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS key_prefix TEXT NOT NULL DEFAULT 'as_live_';
ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS key_type TEXT NOT NULL DEFAULT 'session';

CREATE TABLE IF NOT EXISTS browser_sessions (
  session_id TEXT PRIMARY KEY,
  api_key_hash TEXT NOT NULL REFERENCES api_keys(token_hash) ON DELETE CASCADE,
  csrf_token TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_browser_sessions_expires_at ON browser_sessions(expires_at);

CREATE TABLE IF NOT EXISTS workspace_users (
  id UUID PRIMARY KEY,
  tenant_id UUID NOT NULL REFERENCES tenants(id),
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'owner',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS agents (
  id UUID PRIMARY KEY,
  tenant_id UUID NOT NULL REFERENCES tenants(id),
  name TEXT NOT NULL,
  type TEXT NOT NULL,
  permissions JSONB NOT NULL DEFAULT '{"tools": {}, "default_action": "deny"}',
  trust_score NUMERIC NOT NULL DEFAULT 1.0 CHECK (trust_score >= 0 AND trust_score <= 1),
  status TEXT NOT NULL DEFAULT 'active',
  metadata JSONB NOT NULL DEFAULT '{}',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE agents ADD COLUMN IF NOT EXISTS permissions JSONB NOT NULL DEFAULT '{"tools": {}, "default_action": "deny"}';

CREATE TABLE IF NOT EXISTS agent_tokens (
  jti TEXT PRIMARY KEY,
  tenant_id UUID NOT NULL REFERENCES tenants(id),
  agent_id UUID NOT NULL REFERENCES agents(id),
  expires_at TIMESTAMPTZ NOT NULL,
  revoked_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS audit_ledger (
  id BIGSERIAL PRIMARY KEY,
  tenant_id UUID NOT NULL REFERENCES tenants(id),
  agent_id UUID REFERENCES agents(id),
  event_type TEXT NOT NULL,
  severity TEXT NOT NULL,
  verdict TEXT NOT NULL,
  event_data JSONB NOT NULL,
  prev_hash TEXT NOT NULL,
  curr_hash TEXT NOT NULL UNIQUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE OR REPLACE FUNCTION reject_audit_ledger_mutation()
RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'audit_ledger is append-only; % is not allowed', TG_OP;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS audit_ledger_no_update ON audit_ledger;
CREATE TRIGGER audit_ledger_no_update
BEFORE UPDATE ON audit_ledger
FOR EACH ROW EXECUTE FUNCTION reject_audit_ledger_mutation();

DROP TRIGGER IF EXISTS audit_ledger_no_delete ON audit_ledger;
CREATE TRIGGER audit_ledger_no_delete
BEFORE DELETE ON audit_ledger
FOR EACH ROW EXECUTE FUNCTION reject_audit_ledger_mutation();

CREATE TABLE IF NOT EXISTS threat_events (
  id UUID PRIMARY KEY,
  ledger_id BIGINT NOT NULL REFERENCES audit_ledger(id),
  agent_id UUID NOT NULL REFERENCES agents(id),
  tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
  attack_type TEXT NOT NULL,
  confidence NUMERIC NOT NULL CHECK (confidence >= 0 AND confidence <= 1),
  evidence TEXT NOT NULL,
  resolved BOOLEAN NOT NULL DEFAULT false,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS trust_history (
  id UUID PRIMARY KEY,
  agent_id UUID NOT NULL REFERENCES agents(id),
  ledger_id BIGINT REFERENCES audit_ledger(id),
  delta NUMERIC NOT NULL,
  reason TEXT NOT NULL,
  score_after NUMERIC NOT NULL CHECK (score_after >= 0 AND score_after <= 1),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS event_outbox (
  id BIGSERIAL PRIMARY KEY,
  event_name TEXT NOT NULL,
  payload JSONB NOT NULL,
  processed_at TIMESTAMPTZ,
  last_attempt_at TIMESTAMPTZ,
  retry_count INTEGER NOT NULL DEFAULT 0,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE event_outbox ADD COLUMN IF NOT EXISTS last_attempt_at TIMESTAMPTZ;

CREATE TABLE IF NOT EXISTS cryptographic_keys (
  id UUID PRIMARY KEY,
  tenant_id UUID NOT NULL REFERENCES tenants(id),
  private_key_pem TEXT NOT NULL,
  public_key_pem TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  rotated_at TIMESTAMPTZ,
  status TEXT NOT NULL DEFAULT 'active'
);

CREATE TABLE IF NOT EXISTS invitations (
  id UUID PRIMARY KEY,
  tenant_id UUID NOT NULL REFERENCES tenants(id),
  email TEXT NOT NULL,
  role TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, email)
);

-- 1. Redefine Foreign Keys to Cascade Deletions where appropriate
-- Drop and recreate API keys FK with CASCADE
ALTER TABLE api_keys DROP CONSTRAINT IF EXISTS api_keys_tenant_id_fkey;
ALTER TABLE api_keys ADD CONSTRAINT api_keys_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE;

-- Drop and recreate Workspace users FK with CASCADE
ALTER TABLE workspace_users DROP CONSTRAINT IF EXISTS workspace_users_tenant_id_fkey;
ALTER TABLE workspace_users ADD CONSTRAINT workspace_users_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE;

-- Drop and recreate Agents FK with CASCADE
ALTER TABLE agents DROP CONSTRAINT IF EXISTS agents_tenant_id_fkey;
ALTER TABLE agents ADD CONSTRAINT agents_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE;

-- Drop and recreate Agent tokens FK with CASCADE
ALTER TABLE agent_tokens DROP CONSTRAINT IF EXISTS agent_tokens_tenant_id_fkey;
ALTER TABLE agent_tokens DROP CONSTRAINT IF EXISTS agent_tokens_agent_id_fkey;
ALTER TABLE agent_tokens ADD CONSTRAINT agent_tokens_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE;
ALTER TABLE agent_tokens ADD CONSTRAINT agent_tokens_agent_id_fkey FOREIGN KEY (agent_id) REFERENCES agents(id) ON DELETE CASCADE;

-- Drop and recreate Audit ledger FK (ON DELETE SET NULL for agent so history persists if agent is removed)
ALTER TABLE audit_ledger DROP CONSTRAINT IF EXISTS audit_ledger_tenant_id_fkey;
ALTER TABLE audit_ledger DROP CONSTRAINT IF EXISTS audit_ledger_agent_id_fkey;
ALTER TABLE audit_ledger ADD CONSTRAINT audit_ledger_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE;
ALTER TABLE audit_ledger ADD CONSTRAINT audit_ledger_agent_id_fkey FOREIGN KEY (agent_id) REFERENCES agents(id) ON DELETE SET NULL;

-- Drop and recreate Threat events FK with CASCADE
ALTER TABLE threat_events DROP CONSTRAINT IF EXISTS threat_events_ledger_id_fkey;
ALTER TABLE threat_events DROP CONSTRAINT IF EXISTS threat_events_agent_id_fkey;
ALTER TABLE threat_events ADD CONSTRAINT threat_events_ledger_id_fkey FOREIGN KEY (ledger_id) REFERENCES audit_ledger(id) ON DELETE CASCADE;
ALTER TABLE threat_events ADD CONSTRAINT threat_events_agent_id_fkey FOREIGN KEY (agent_id) REFERENCES agents(id) ON DELETE CASCADE;

-- Drop and recreate Trust history FK with CASCADE
ALTER TABLE trust_history DROP CONSTRAINT IF EXISTS trust_history_agent_id_fkey;
ALTER TABLE trust_history DROP CONSTRAINT IF EXISTS trust_history_ledger_id_fkey;
ALTER TABLE trust_history ADD CONSTRAINT trust_history_agent_id_fkey FOREIGN KEY (agent_id) REFERENCES agents(id) ON DELETE CASCADE;
ALTER TABLE trust_history ADD CONSTRAINT trust_history_ledger_id_fkey FOREIGN KEY (ledger_id) REFERENCES audit_ledger(id) ON DELETE CASCADE;

-- Drop and recreate Cryptographic keys FK with CASCADE
ALTER TABLE cryptographic_keys DROP CONSTRAINT IF EXISTS cryptographic_keys_tenant_id_fkey;
ALTER TABLE cryptographic_keys ADD CONSTRAINT cryptographic_keys_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE;

-- Drop and recreate Invitations FK with CASCADE
ALTER TABLE invitations DROP CONSTRAINT IF EXISTS invitations_tenant_id_fkey;
ALTER TABLE invitations ADD CONSTRAINT invitations_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE;


-- 2. Performance Indexes to accelerate JOIN operations and scans
CREATE INDEX IF NOT EXISTS idx_api_keys_tenant_id ON api_keys(tenant_id);
CREATE INDEX IF NOT EXISTS idx_workspace_users_tenant_id ON workspace_users(tenant_id);
CREATE INDEX IF NOT EXISTS idx_agents_tenant_id ON agents(tenant_id);
CREATE INDEX IF NOT EXISTS idx_agent_tokens_agent_id ON agent_tokens(agent_id);
CREATE INDEX IF NOT EXISTS idx_audit_ledger_tenant_id ON audit_ledger(tenant_id);
CREATE INDEX IF NOT EXISTS idx_audit_ledger_agent_id ON audit_ledger(agent_id);
CREATE INDEX IF NOT EXISTS idx_threat_events_agent_id ON threat_events(agent_id);
CREATE INDEX IF NOT EXISTS idx_threat_events_ledger_id ON threat_events(ledger_id);
CREATE INDEX IF NOT EXISTS idx_threat_events_tenant_id ON threat_events(tenant_id);
CREATE INDEX IF NOT EXISTS idx_trust_history_agent_id ON trust_history(agent_id);
CREATE INDEX IF NOT EXISTS idx_cryptographic_keys_tenant_id ON cryptographic_keys(tenant_id);
CREATE INDEX IF NOT EXISTS idx_invitations_tenant_id ON invitations(tenant_id);

-- 3. Partial index for Outbox Polling optimization
CREATE INDEX IF NOT EXISTS idx_event_outbox_unprocessed ON event_outbox(id) WHERE processed_at IS NULL AND retry_count < 5;

-- 4. Truncate trigger for Append-Only Ledger safety
CREATE OR REPLACE FUNCTION reject_audit_ledger_truncate()
RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'audit_ledger is append-only; TRUNCATE is not allowed';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS audit_ledger_no_truncate ON audit_ledger;
CREATE TRIGGER audit_ledger_no_truncate
BEFORE TRUNCATE ON audit_ledger
EXECUTE FUNCTION reject_audit_ledger_truncate();
