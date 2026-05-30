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
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_used_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS workspace_users (
  id UUID PRIMARY KEY,
  tenant_id UUID NOT NULL REFERENCES tenants(id),
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
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
  retry_count INTEGER NOT NULL DEFAULT 0,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

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

