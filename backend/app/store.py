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
    risk_score: float = 0.0
    risk_profile: str = "Safe"  # Safe, Guarded, Critical Risk
    threat_counts: dict[str, int] = field(default_factory=lambda: {
        "instruction_override": 0,
        "prompt_exfiltration": 0,
        "system_token_injection": 0,
        "jailbreak": 0,
        "role_hijacking": 0,
        "data_exfiltration": 0,
        "sql_injection": 0,
        "ssrf_open_redirect": 0,
        "privilege_escalation": 0,
        "shell_injection": 0
    })
    trust_score_history: list[dict] = field(default_factory=list)


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
    role: str = "owner"  # owner, editor, auditor, viewer
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class CryptographicKey:
    id: UUID
    tenant_id: UUID
    private_key_pem: str
    public_key_pem: str
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    rotated_at: datetime | None = None
    status: str = "active"  # active, rotated


@dataclass
class Invitation:
    id: UUID
    tenant_id: UUID
    email: str
    role: str
    status: str = "pending"  # pending, accepted
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
        self.keys: dict[UUID, CryptographicKey] = {}
        self.invitations: dict[UUID, Invitation] = {}

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

    def persist_key(self, key: CryptographicKey) -> None:
        return

    def persist_invitation(self, invitation: Invitation) -> None:
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
                meta = row["metadata"] or {}
                self.agents[row["id"]] = AgentRecord(
                    id=row["id"],
                    tenant_id=row["tenant_id"],
                    name=row["name"],
                    type=row["type"],
                    permissions=PermissionManifest.model_validate(row["permissions"]),
                    trust_score=float(row["trust_score"]),
                    status=row["status"],
                    metadata=meta,
                    risk_score=float(meta.get("risk_score", 0.0)),
                    risk_profile=meta.get("risk_profile", "Safe"),
                    threat_counts=meta.get("threat_counts", {
                        "instruction_override": 0,
                        "prompt_exfiltration": 0,
                        "system_token_injection": 0,
                        "jailbreak": 0,
                        "role_hijacking": 0,
                        "data_exfiltration": 0,
                        "sql_injection": 0,
                        "ssrf_open_redirect": 0,
                        "privilege_escalation": 0,
                        "shell_injection": 0
                    }),
                    trust_score_history=meta.get("trust_score_history", [])
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
            for row in conn.execute("SELECT * FROM cryptographic_keys"):
                self.keys[row["id"]] = CryptographicKey(
                    id=row["id"],
                    tenant_id=row["tenant_id"],
                    private_key_pem=row["private_key_pem"],
                    public_key_pem=row["public_key_pem"],
                    created_at=row["created_at"],
                    rotated_at=row["rotated_at"],
                    status=row["status"],
                )
            for row in conn.execute("SELECT * FROM invitations"):
                self.invitations[row["id"]] = Invitation(
                    id=row["id"],
                    tenant_id=row["tenant_id"],
                    email=row["email"],
                    role=row["role"],
                    status=row["status"],
                    created_at=row["created_at"],
                )


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
        meta = dict(agent.metadata or {})
        meta["risk_score"] = agent.risk_score
        meta["risk_profile"] = agent.risk_profile
        meta["threat_counts"] = agent.threat_counts
        meta["trust_score_history"] = agent.trust_score_history

        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO agents (id, tenant_id, name, type, permissions, trust_score, status, metadata)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (id) DO UPDATE SET permissions = EXCLUDED.permissions, trust_score = EXCLUDED.trust_score, status = EXCLUDED.status, metadata = EXCLUDED.metadata
                """,
                (agent.id, agent.tenant_id, agent.name, agent.type, Json(agent.permissions.model_dump()), agent.trust_score, agent.status, Json(meta)),
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

    def persist_key(self, key: CryptographicKey) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO cryptographic_keys (id, tenant_id, private_key_pem, public_key_pem, created_at, rotated_at, status)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (id) DO UPDATE SET rotated_at = EXCLUDED.rotated_at, status = EXCLUDED.status
                """,
                (key.id, key.tenant_id, key.private_key_pem, key.public_key_pem, key.created_at, key.rotated_at, key.status),
            )
            conn.commit()

    def persist_invitation(self, invitation: Invitation) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO invitations (id, tenant_id, email, role, status, created_at)
                VALUES (%s, %s, %s, %s, %s, %s)
                ON CONFLICT (id) DO UPDATE SET status = EXCLUDED.status
                """,
                (invitation.id, invitation.tenant_id, invitation.email, invitation.role, invitation.status, invitation.created_at),
            )
            conn.commit()



def create_store(database_url: str | None = None) -> InMemoryStore:
    if database_url:
        return PostgresStore(database_url)
    return InMemoryStore()


store = InMemoryStore()
