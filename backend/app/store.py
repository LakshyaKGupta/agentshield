from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from uuid import UUID, uuid4

from .contracts import LedgerEntry, PermissionManifest, Severity, Verdict

try:
    import psycopg
    from psycopg.rows import dict_row
    from psycopg.types.json import Json
except ImportError:  # pragma: no cover - exercised only without optional database dependency
    psycopg = None
    dict_row = None
    Json = None


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


@dataclass
class WorkspaceUser:
    id: UUID
    tenant_id: UUID
    email: str
    password_hash: str
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class InMemoryStore:
    def __init__(self) -> None:
        self.backend_name = "in_memory"
        self.tenants: dict[UUID, Tenant] = {}
        self.api_keys: dict[str, ApiKeyRecord] = {}
        self.users: dict[str, WorkspaceUser] = {}
        self.agents: dict[UUID, AgentRecord] = {}
        self.tokens: dict[str, TokenRecord] = {}
        self.ledger: list[LedgerEntry] = []
        self.threat_events: list[dict] = []
        self.trust_history: list[dict] = []
        self.events: list[dict] = []

    def seed_tenant(self, name: str = "Demo Tenant") -> Tenant:
        for tenant in self.tenants.values():
            if tenant.name == name:
                return tenant
        tenant = Tenant(id=uuid4(), name=name)
        self.tenants[tenant.id] = tenant
        self.persist_tenant(tenant)
        return tenant

    def persist_tenant(self, tenant: Tenant) -> None:
        return

    def persist_user(self, user: WorkspaceUser) -> None:
        return

    def persist_api_key(self, api_key: ApiKeyRecord) -> None:
        return

    def persist_agent(self, agent: AgentRecord) -> None:
        return

    def persist_token(self, token: TokenRecord) -> None:
        return

    def persist_ledger_entry(self, entry: LedgerEntry) -> None:
        return

    def persist_threat_event(self, threat: dict) -> None:
        return

    def persist_trust_history(self, trust: dict) -> None:
        return

    def persist_event(self, event: dict) -> None:
        return


class PostgresStore(InMemoryStore):
    def __init__(self, database_url: str) -> None:
        if psycopg is None or dict_row is None:
            raise RuntimeError("PostgreSQL persistence requires psycopg[binary]. Install project dependencies first.")
        super().__init__()
        self.backend_name = "postgres"
        self.database_url = database_url
        self._init_schema()
        self._hydrate()

    def _connect(self):
        return psycopg.connect(self.database_url, row_factory=dict_row)

    def _init_schema(self) -> None:
        migration = Path(__file__).resolve().parents[1] / "migrations" / "001_initial_schema.sql"
        with self._connect() as conn:
            conn.execute(migration.read_text())
            conn.commit()

    def _hydrate(self) -> None:
        with self._connect() as conn:
            for row in conn.execute("SELECT * FROM tenants"):
                self.tenants[row["id"]] = Tenant(id=row["id"], name=row["name"], status=row["status"])
            for row in conn.execute("SELECT * FROM workspace_users"):
                self.users[row["email"]] = WorkspaceUser(
                    id=row["id"],
                    tenant_id=row["tenant_id"],
                    email=row["email"],
                    password_hash=row["password_hash"],
                    created_at=row["created_at"],
                )
            for row in conn.execute("SELECT * FROM api_keys"):
                self.api_keys[row["token_hash"]] = ApiKeyRecord(
                    id=row["id"],
                    tenant_id=row["tenant_id"],
                    token_hash=row["token_hash"],
                    scopes=row["scopes"],
                    status=row["status"],
                    created_at=row["created_at"],
                    last_used_at=row["last_used_at"],
                )
            for row in conn.execute("SELECT * FROM agents"):
                self.agents[row["id"]] = AgentRecord(
                    id=row["id"],
                    tenant_id=row["tenant_id"],
                    name=row["name"],
                    type=row["type"],
                    permissions=PermissionManifest.model_validate(row["permissions"]),
                    trust_score=float(row["trust_score"]),
                    status=row["status"],
                    metadata=row["metadata"],
                )
            for row in conn.execute("SELECT * FROM agent_tokens"):
                self.tokens[row["jti"]] = TokenRecord(
                    jti=row["jti"],
                    tenant_id=row["tenant_id"],
                    agent_id=row["agent_id"],
                    expires_at=row["expires_at"],
                    revoked_at=row["revoked_at"],
                )
            for row in conn.execute("SELECT * FROM audit_ledger ORDER BY id"):
                self.ledger.append(
                    LedgerEntry(
                        id=row["id"],
                        tenant_id=row["tenant_id"],
                        agent_id=row["agent_id"],
                        event_type=row["event_type"],
                        severity=Severity(row["severity"]),
                        verdict=Verdict(row["verdict"]),
                        event_data=row["event_data"],
                        prev_hash=row["prev_hash"],
                        curr_hash=row["curr_hash"],
                        created_at=row["created_at"],
                    )
                )
            self.threat_events = list(conn.execute("SELECT * FROM threat_events ORDER BY created_at"))
            self.trust_history = list(conn.execute("SELECT * FROM trust_history ORDER BY created_at"))
            self.events = [row["payload"] for row in conn.execute("SELECT payload FROM event_outbox ORDER BY id")]

    def persist_tenant(self, tenant: Tenant) -> None:
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO tenants (id, name, status) VALUES (%s, %s, %s) ON CONFLICT (id) DO NOTHING",
                (tenant.id, tenant.name, tenant.status),
            )
            conn.commit()

    def persist_user(self, user: WorkspaceUser) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO workspace_users (id, tenant_id, email, password_hash, created_at)
                VALUES (%s, %s, %s, %s, %s)
                ON CONFLICT (email) DO UPDATE SET password_hash = EXCLUDED.password_hash
                """,
                (user.id, user.tenant_id, user.email, user.password_hash, user.created_at),
            )
            conn.commit()

    def persist_api_key(self, api_key: ApiKeyRecord) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO api_keys (id, tenant_id, token_hash, scopes, status, created_at, last_used_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (token_hash) DO UPDATE SET status = EXCLUDED.status, last_used_at = EXCLUDED.last_used_at
                """,
                (api_key.id, api_key.tenant_id, api_key.token_hash, Json(api_key.scopes), api_key.status, api_key.created_at, api_key.last_used_at),
            )
            conn.commit()

    def persist_agent(self, agent: AgentRecord) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO agents (id, tenant_id, name, type, permissions, trust_score, status, metadata)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (id) DO UPDATE SET permissions = EXCLUDED.permissions, trust_score = EXCLUDED.trust_score, status = EXCLUDED.status, metadata = EXCLUDED.metadata
                """,
                (agent.id, agent.tenant_id, agent.name, agent.type, Json(agent.permissions.model_dump()), agent.trust_score, agent.status, Json(agent.metadata)),
            )
            conn.commit()

    def persist_token(self, token: TokenRecord) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO agent_tokens (jti, tenant_id, agent_id, expires_at, revoked_at)
                VALUES (%s, %s, %s, %s, %s)
                ON CONFLICT (jti) DO UPDATE SET revoked_at = EXCLUDED.revoked_at
                """,
                (token.jti, token.tenant_id, token.agent_id, token.expires_at, token.revoked_at),
            )
            conn.commit()

    def persist_ledger_entry(self, entry: LedgerEntry) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO audit_ledger (id, tenant_id, agent_id, event_type, severity, verdict, event_data, prev_hash, curr_hash, created_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (id) DO NOTHING
                """,
                (entry.id, entry.tenant_id, entry.agent_id, entry.event_type, entry.severity.value, entry.verdict.value, Json(entry.event_data), entry.prev_hash, entry.curr_hash, entry.created_at),
            )
            conn.commit()

    def persist_threat_event(self, threat: dict) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO threat_events (id, ledger_id, agent_id, attack_type, confidence, evidence, resolved, created_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (id) DO NOTHING
                """,
                (threat["id"], threat["ledger_id"], threat["agent_id"], threat["attack_type"], threat["confidence"], threat["evidence"], threat["resolved"], threat["created_at"]),
            )
            conn.commit()

    def persist_trust_history(self, trust: dict) -> None:
        trust.setdefault("id", uuid4())
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO trust_history (id, agent_id, ledger_id, delta, reason, score_after, created_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (id) DO NOTHING
                """,
                (trust["id"], trust["agent_id"], trust.get("ledger_id"), trust["delta"], trust.get("reason", "runtime_trust_update"), trust["score_after"], trust["created_at"]),
            )
            conn.commit()

    def persist_event(self, event: dict) -> None:
        with self._connect() as conn:
            conn.execute("INSERT INTO event_outbox (event_name, payload) VALUES (%s, %s)", (event.get("event", "event"), Json(event)))
            conn.commit()


def create_store(database_url: str | None = None) -> InMemoryStore:
    if database_url:
        return PostgresStore(database_url)
    return InMemoryStore()


store = InMemoryStore()
