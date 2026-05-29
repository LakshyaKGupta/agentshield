from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, Field


class Verdict(StrEnum):
    ALLOWED = "ALLOWED"
    BLOCKED = "BLOCKED"
    FLAGGED = "FLAGGED"


class ThreatLevel(StrEnum):
    NONE = "NONE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Severity(StrEnum):
    INFO = "INFO"
    WARN = "WARN"
    CRITICAL = "CRITICAL"


class Evidence(BaseModel):
    source: Literal["pattern", "permission", "identity", "trust", "llm", "manual"]
    code: str
    message: str
    confidence: float | None = Field(default=None, ge=0, le=1)
    span: str | None = None


class PermissionManifest(BaseModel):
    tools: dict[str, list[str]] = Field(default_factory=dict)
    default_action: Literal["deny"] = "deny"
    max_risk_level: Literal["low", "medium", "high"] | None = None


class AgentCreateRequest(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    type: Literal["user_agent", "research_agent", "executor_agent", "security_agent", "custom"] = "custom"
    permissions: PermissionManifest
    metadata: dict[str, Any] = Field(default_factory=dict)


class AgentResponse(BaseModel):
    agent_id: UUID
    tenant_id: UUID
    name: str
    type: str
    status: Literal["active", "suspended", "revoked"]
    trust_score: float = Field(ge=0, le=1)
    token: str
    token_expires_at: datetime
    permissions: PermissionManifest


class AgentListResponse(BaseModel):
    agents: list[AgentResponse]


class WorkspaceSignupRequest(BaseModel):
    email: str = Field(min_length=3, max_length=180)
    password: str = Field(min_length=8, max_length=200)
    workspace_name: str = Field(min_length=1, max_length=120)


class WorkspaceLoginRequest(BaseModel):
    email: str = Field(min_length=3, max_length=180)
    password: str = Field(min_length=8, max_length=200)


class WorkspaceAuthResponse(BaseModel):
    tenant_id: UUID
    workspace_name: str
    email: str
    api_key: str


class AnalyzeRequest(BaseModel):
    agent_id: UUID
    direction: Literal["inbound", "outbound", "inter_agent"]
    message: str = Field(min_length=1, max_length=20_000)
    context: dict[str, Any] = Field(default_factory=dict)
    deep_analysis: bool = False


class ToolCallRequest(BaseModel):
    agent_id: UUID
    tool_name: str = Field(min_length=1, max_length=120)
    action: str = Field(min_length=1, max_length=120)
    arguments_hash: str | None = None
    risk_context: dict[str, Any] = Field(default_factory=dict)


class SecurityVerdict(BaseModel):
    allowed: bool
    verdict: Verdict
    threat_level: ThreatLevel
    reason: str
    evidence: list[Evidence]
    trust_delta: float
    trust_score_after: float = Field(ge=0, le=1)
    ledger_id: int
    latency_ms: int
    async_enrichment_id: UUID | None = None


class LedgerEntry(BaseModel):
    id: int
    tenant_id: UUID
    agent_id: UUID | None
    event_type: Literal["message", "tool_call", "inter_agent", "auth", "system"]
    severity: Severity
    verdict: Verdict
    event_data: dict[str, Any]
    prev_hash: str
    curr_hash: str
    created_at: datetime


class LedgerVerification(BaseModel):
    valid: bool
    entries_checked: int
    broken_at: int | None = None
    expected_hash: str | None = None
    actual_hash: str | None = None
    checked_at: datetime


class ThreatEvent(BaseModel):
    id: UUID
    ledger_id: int
    agent_id: UUID
    attack_type: str
    confidence: float = Field(ge=0, le=1)
    evidence: str
    resolved: bool = False
    created_at: datetime


class ThreatPage(BaseModel):
    threats: list[ThreatEvent]


class HealthResponse(BaseModel):
    status: Literal["ok"]
    service: str
    version: str
    demo_mode: bool
    demo_api_key: str | None = None


class ReadinessResponse(BaseModel):
    ready: bool
    service: str
    version: str
    store: Literal["in_memory", "postgres"]
    ledger_valid: bool
    ledger_entries: int
    tenant_count: int
    agent_count: int
    event_count: int


class AttackSimulationRequest(BaseModel):
    attack_type: str = "instruction_override"
    payload: str | None = None


class AttackSimulationResult(BaseModel):
    simulation_id: UUID
    attack_type: str
    detected: bool
    verdict: SecurityVerdict
    latency_ms: int
    ledger_id: int


class ErrorEnvelope(BaseModel):
    error: dict[str, Any]
