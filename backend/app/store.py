from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from uuid import UUID, uuid4

from .contracts import LedgerEntry, PermissionManifest


@dataclass
class Tenant:
    id: UUID
    name: str
    status: str = "active"


@dataclass
class ApiKeyRecord:
    id: UUID
    tenant_id: UUID
    token_hash: str
    scopes: list[str]
    status: str = "active"
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_used_at: datetime | None = None


@dataclass
class AgentRecord:
    id: UUID
    tenant_id: UUID
    name: str
    type: str
    permissions: PermissionManifest
    trust_score: float = 1.0
    status: str = "active"
    metadata: dict = field(default_factory=dict)


@dataclass
class TokenRecord:
    jti: str
    tenant_id: UUID
    agent_id: UUID
    expires_at: datetime
    revoked_at: datetime | None = None


class InMemoryStore:
    def __init__(self) -> None:
        self.tenants: dict[UUID, Tenant] = {}
        self.api_keys: dict[str, ApiKeyRecord] = {}
        self.agents: dict[UUID, AgentRecord] = {}
        self.tokens: dict[str, TokenRecord] = {}
        self.ledger: list[LedgerEntry] = []
        self.threat_events: list[dict] = []
        self.trust_history: list[dict] = []
        self.events: list[dict] = []

    def seed_tenant(self, name: str = "Demo Tenant") -> Tenant:
        tenant = Tenant(id=uuid4(), name=name)
        self.tenants[tenant.id] = tenant
        return tenant


store = InMemoryStore()

