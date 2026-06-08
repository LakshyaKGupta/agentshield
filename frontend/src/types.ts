// AgentShield — shared TypeScript types
// Extracted from main.tsx for code organization

export type Agent = {
  agent_id: string;
  name: string;
  type: string;
  status: string;
  trust_score: number;
  token: string;
  token_expires_at?: string | null;
  permissions: { tools: Record<string, string[]>; default_action?: string };
  live_connected?: boolean;
  first_live_at?: string | null;
  last_live_at?: string | null;
  last_seen?: string | null;
  runtime_source?: string;
  is_simulation?: boolean;
  requests_screened?: number;
  threats_blocked?: number;
  policy_violations?: number;
  metadata?: Record<string, unknown>;
};

export type LedgerEntry = {
  id: number;
  agent_id: string | null;
  event_type: string;
  verdict: "ALLOWED" | "BLOCKED" | "FLAGGED";
  severity: string;
  curr_hash: string;
  prev_hash: string;
  created_at: string;
  event_data: Record<string, unknown>;
};

export type Threat = {
  id: string;
  ledger_id: number;
  agent_id: string;
  attack_type: string;
  confidence: number;
  evidence: string;
  resolved: boolean;
  created_at: string;
};

export type AppData = {
  apiKey: string;
  agents: Agent[];
  ledger: LedgerEntry[];
  threats: Threat[];
  ledgerValid: boolean | null;
  settings: unknown | null;
  loading: boolean;
  error: string | null;
  apiKeys: unknown[];
  activeSdkKeyExists?: boolean;
};

export type AuthResponse = {
  tenant_id: string;
  workspace_name: string;
  email: string;
  api_key: string;
};

export type SessionStatus = {
  authenticated: boolean;
  csrf_ready?: boolean;
};

export type ReadyStatus = {
  ready: boolean;
  store?: string;
  database?: string;
  ledger_valid?: boolean;
  redis?: { configured?: boolean; connected?: boolean; mode?: string };
  signing_key_provider?: string;
  kms_hsm?: { configured?: boolean; status?: string; provider?: string; key_arn_configured?: boolean };
  sso?: { oidc_configured?: boolean; scim_configured?: boolean; issuer?: string };
};

export type EnterpriseMetrics = {
  agents_total: number;
  agents_active: number;
  agents_live_connected: number;
  avg_trust_score: number;
  ledger_entries: number;
  live_runtime_entries: number;
  ledger_valid: boolean;
  decisions_allowed: number;
  decisions_blocked: number;
  decisions_flagged: number;
  threats_total: number;
  threats_unresolved: number;
  generated_at: string;
};

export type LifecycleStatus = {
  label: string;
  state: "registered" | "connected" | "protected" | "disabled";
};

export type LiveRuntimeStats = {
  entries: LedgerEntry[];
  protectedRequests: number;
  blockedThreats: number;
  flaggedThreats: number;
};
