// AgentShield — shared utility functions
// Extracted from main.tsx for code organization

import type { Agent, LedgerEntry, LiveRuntimeStats } from "./types";

// ─── Formatting helpers ───────────────────────────────────────────────────────

export function fmtHash(h: string): string {
  if (!h) return "-";
  return `${h.slice(0, 8)}…${h.slice(-8)}`;
}

export function agentName(agents: Agent[], id: string | null): string {
  return agents.find(a => a.agent_id === id)?.name || "system";
}

export function scoreGrade(score: number | null): string {
  if (score === null) return "N/A";
  if (score >= 97) return "A+";
  if (score >= 93) return "A";
  if (score >= 90) return "A-";
  if (score >= 87) return "B+";
  if (score >= 83) return "B";
  if (score >= 80) return "B-";
  if (score >= 70) return "C";
  if (score >= 60) return "D";
  return "F";
}

export function scoreTone(score: number | null): string {
  if (score === null) return "var(--ink-40)";
  if (score >= 90) return "var(--green)";
  if (score >= 70) return "var(--amber)";
  return "var(--red)";
}

// ─── Live agent status ────────────────────────────────────────────────────────

/** 5-minute window. Must match LIVE_TIMEOUT_SECONDS = 300 in backend/app/services.py */
export const LIVE_TIMEOUT_MS = 5 * 60 * 1000;

/**
 * Returns true only when the agent has sent a real /v1/shield/analyze request
 * in the last 5 minutes. Relies on last_live_at being set by _mark_agent_live_if_sdk()
 * in the backend, which only fires for SDK-key requests with event_source="live_runtime".
 *
 * Simulation and proof agents are always excluded.
 */
export function isAgentCurrentlyLive(agent: Agent | null | undefined): boolean {
  if (!agent || agent.status !== "active" || !agent.live_connected) return false;
  if (isSimulationAgent(agent)) return false;
  const lastSeenStr = agent.last_live_at || agent.last_seen;
  if (!lastSeenStr) return false;
  const lastSeen = new Date(lastSeenStr).getTime();
  if (!Number.isFinite(lastSeen)) return false;
  return Date.now() - lastSeen < LIVE_TIMEOUT_MS;
}

/**
 * Returns null when the agent has never processed a real runtime request.
 * Showing "100 / A+" for a brand-new agent that has never been seen by the shield
 * is actively misleading — a score needs real traffic to mean anything.
 */
export function agentDisplayScore(agent: Agent): number | null {
  if (!isAgentCurrentlyLive(agent)) return null;
  if (agent.status === "revoked") return Math.min(Math.round(agent.trust_score * 100), 35);
  return Math.round(agent.trust_score * 100);
}

/** Lifecycle: Registered → Connected → Protected (or Disabled) */
export function agentLifecycleStatus(agent: Agent): { label: string; state: "registered" | "connected" | "protected" | "disabled" } {
  if (agent.status === "revoked") return { label: "Disabled", state: "disabled" };
  if (isAgentCurrentlyLive(agent)) return { label: "Protected", state: "protected" };
  if (agent.status === "active") return { label: "Registered", state: "registered" };
  return { label: agent.status, state: "registered" };
}

/**
 * Returns true for simulation and internal proof agents.
 * These agents should never appear in live counts, runtime decisions, or evidence pages.
 */
export function isSimulationAgent(agent: Agent): boolean {
  return (
    Boolean(agent.is_simulation)
    || agent.runtime_source === "simulation"
    || agent.runtime_source === "console_proof"
    || agent.metadata?.is_internal_proof === true
    || agent.name === "AgentShield Proof Agent"
    || agent.name.startsWith("sim-")
  );
}

// ─── Ledger entry helpers ─────────────────────────────────────────────────────

export function ledgerSource(entry: LedgerEntry): string {
  return String(entry.event_data?.source || "setup");
}

/** True only for ledger entries that originated from external SDK/API live traffic. */
export function isLiveRuntimeEntry(entry: LedgerEntry): boolean {
  return ledgerSource(entry) === "live_runtime";
}

/**
 * True for entries that should appear in the RUNTIME DECISIONS timeline.
 * Excludes: console_proof runs, agent registration events, system setup entries.
 */
export function isLiveRuntimeDecisionEntry(entry: LedgerEntry): boolean {
  return (
    isLiveRuntimeEntry(entry)
    && (entry.event_type === "message" || entry.event_type === "tool_call")
    && entry.event_type !== "agent_registered"
    && entry.event_type !== "system"
    && !entry.event_data?.proof_test
  );
}

/**
 * Returns ledger entries from the live_runtime source,
 * optionally filtered to only currently-live agents.
 */
export function liveRuntimeDecisionEntries(ledger: LedgerEntry[], agents?: Agent[]): LedgerEntry[] {
  const liveAgentIds = agents
    ? new Set(agents.filter(isAgentCurrentlyLive).map(agent => agent.agent_id))
    : null;
  return ledger.filter(entry => (
    isLiveRuntimeDecisionEntry(entry)
    && (!liveAgentIds || (entry.agent_id !== null && liveAgentIds.has(entry.agent_id)))
  ));
}

export function liveRuntimeStats(ledger: LedgerEntry[], agents?: Agent[]): LiveRuntimeStats {
  const entries = liveRuntimeDecisionEntries(ledger, agents);
  return {
    entries,
    protectedRequests: entries.length,
    blockedThreats: entries.filter(entry => entry.verdict === "BLOCKED").length,
    flaggedThreats: entries.filter(entry => entry.verdict === "FLAGGED").length,
  };
}

export function agentRuntimeStats(ledger: LedgerEntry[], agentId: string): LiveRuntimeStats {
  const entries = liveRuntimeDecisionEntries(ledger).filter(entry => entry.agent_id === agentId);
  return {
    entries,
    protectedRequests: entries.length,
    blockedThreats: entries.filter(entry => entry.verdict === "BLOCKED").length,
    flaggedThreats: entries.filter(entry => entry.verdict === "FLAGGED").length,
  };
}
