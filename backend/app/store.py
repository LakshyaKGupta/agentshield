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

try:
    from psycopg_pool import ConnectionPool
except ImportError:
    ConnectionPool = None


@dataclass
class Tenant:
    id: UUID
    name: str
    status: str = "active"
    preferences: dict = field(default_factory=dict)



@dataclass
class ApiKeyRecord:
    id: UUID
    tenant_id: UUID
    token_hash: str
    scopes: list[str]
    status: str = "active"
    name: str = "Workspace session"
    key_prefix: str = "as_live_"
    key_type: str = "session"
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

    def seed_tenant(self, name: str = "Local Workspace") -> Tenant:
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

    def delete_user(self, email: str) -> None:
        if email in self.users:
            del self.users[email]

    def delete_invitation(self, id: UUID) -> None:
        if id in self.invitations:
            del self.invitations[id]



class PostgresDict(dict):
    def __init__(self, connect_func, table, key_col, val_col=None, to_obj_func=None):
        self._connect = connect_func
        self.table = table
        self.key_col = key_col
        self.val_col = val_col
        self.to_obj = to_obj_func

    def _query_all(self):
        res = {}
        with self._connect() as conn:
            for row in conn.execute(f"SELECT * FROM {self.table}"):
                obj = self.to_obj(row) if self.to_obj else row
                key = row[self.key_col]
                res[key] = obj
        return res

    def get(self, key, default=None):
        if key is None:
            return default
        try:
            return self[key]
        except KeyError:
            return default

    def __getitem__(self, key):
        if key is None:
            raise KeyError(key)
        query_val = key
        if self.key_col == "id" and isinstance(key, str) and len(key) == 36:
            try:
                query_val = UUID(key)
            except ValueError:
                pass
        with self._connect() as conn:
            row = conn.execute(f"SELECT * FROM {self.table} WHERE {self.key_col} = %s", (query_val,)).fetchone()
            if row is None:
                raise KeyError(key)
            return self.to_obj(row) if self.to_obj else row

    def __contains__(self, key):
        if key is None:
            return False
        query_val = key
        if self.key_col == "id" and isinstance(key, str) and len(key) == 36:
            try:
                query_val = UUID(key)
            except ValueError:
                pass
        with self._connect() as conn:
            row = conn.execute(f"SELECT 1 FROM {self.table} WHERE {self.key_col} = %s", (query_val,)).fetchone()
            return row is not None

    def values(self):
        return self._query_all().values()

    def keys(self):
        return self._query_all().keys()

    def items(self):
        return self._query_all().items()

    def __iter__(self):
        return iter(self.keys())

    def __len__(self):
        with self._connect() as conn:
            row = conn.execute(f"SELECT COUNT(*) as cnt FROM {self.table}").fetchone()
            return row["cnt"] if row else 0

    def __setitem__(self, key, value):
        pass

    def __delitem__(self, key):
        query_val = key
        if self.key_col == "id" and isinstance(key, str) and len(key) == 36:
            try:
                query_val = UUID(key)
            except ValueError:
                pass
        with self._connect() as conn:
            conn.execute(f"DELETE FROM {self.table} WHERE {self.key_col} = %s", (query_val,))
            conn.commit()


class PostgresList(list):
    def __init__(self, connect_func, table, to_obj_func=None, order_by=None):
        self._connect = connect_func
        self.table = table
        self.to_obj = to_obj_func
        self.order_by = order_by

    def _query_all(self):
        res = []
        q = f"SELECT * FROM {self.table}"
        if self.order_by:
            q += f" ORDER BY {self.order_by}"
        with self._connect() as conn:
            for row in conn.execute(q):
                res.append(self.to_obj(row) if self.to_obj else row)
        return res

    def __iter__(self):
        return iter(self._query_all())

    def __len__(self):
        with self._connect() as conn:
            row = conn.execute(f"SELECT COUNT(*) as cnt FROM {self.table}").fetchone()
            return row["cnt"] if row else 0

    def __getitem__(self, index):
        all_items = self._query_all()
        return all_items[index]

    def append(self, item):
        pass

    def __bool__(self):
        return len(self) > 0


class PostgresStore(InMemoryStore):
    def __init__(self, database_url: str) -> None:
        if psycopg is None or dict_row is None:
            raise RuntimeError("PostgreSQL persistence requires psycopg[binary]. Install project dependencies first.")
        super().__init__()
        self.backend_name = "postgres"
        self.database_url = database_url
        
        # Initialize database connection pool for high concurrency performance
        try:
            if ConnectionPool is not None:
                self._pool = ConnectionPool(
                    conninfo=self.database_url,
                    min_size=2,
                    max_size=15,
                    kwargs={"row_factory": dict_row}
                )
            else:
                self._pool = None
        except Exception as exc:
            print(f"[store] Failed to initialize connection pool ({exc}); falling back to raw connections")
            self._pool = None

        self._init_schema()

        self.tenants = PostgresDict(
            self._connect, "tenants", "id",
            to_obj_func=lambda r: Tenant(id=r["id"], name=r["name"], status=r["status"], preferences=r.get("preferences") or {})
        )
        self.users = PostgresDict(
            self._connect, "workspace_users", "email",
            to_obj_func=lambda r: WorkspaceUser(id=r["id"], tenant_id=r["tenant_id"], email=r["email"], password_hash=r["password_hash"], created_at=r["created_at"])
        )
        self.api_keys = PostgresDict(
            self._connect, "api_keys", "token_hash",
            to_obj_func=lambda r: ApiKeyRecord(
                id=r["id"],
                tenant_id=r["tenant_id"],
                token_hash=r["token_hash"],
                scopes=r["scopes"],
                status=r["status"],
                name=r["name"],
                key_prefix=r["key_prefix"],
                key_type=r["key_type"],
                created_at=r["created_at"],
                last_used_at=r["last_used_at"],
            )
        )

        def agent_row_to_obj(row):
            meta = row["metadata"] or {}
            return AgentRecord(
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

        self.agents = PostgresDict(self._connect, "agents", "id", to_obj_func=agent_row_to_obj)

        self.tokens = PostgresDict(
            self._connect, "agent_tokens", "jti",
            to_obj_func=lambda r: TokenRecord(jti=r["jti"], tenant_id=r["tenant_id"], agent_id=r["agent_id"], expires_at=r["expires_at"], revoked_at=r["revoked_at"])
        )

        def ledger_row_to_obj(row):
            return LedgerEntry(
                id=row["id"],
                tenant_id=row["tenant_id"],
                agent_id=row["agent_id"],
                event_type=row["event_type"],
                severity=Severity(row["severity"]),
                verdict=Verdict(row["verdict"]),
                event_data=row["event_data"],
                prev_hash=row["prev_hash"],
                curr_hash=row["curr_hash"],
                created_at=row["created_at"]
            )

        self.ledger = PostgresList(self._connect, "audit_ledger", to_obj_func=ledger_row_to_obj, order_by="id")
        self.threat_events = PostgresList(self._connect, "threat_events", order_by="created_at")
        self.trust_history = PostgresList(self._connect, "trust_history", order_by="created_at")
        self.events = PostgresList(self._connect, "event_outbox", to_obj_func=lambda r: r["payload"], order_by="id")

        self.keys = PostgresDict(
            self._connect, "cryptographic_keys", "id",
            to_obj_func=lambda r: CryptographicKey(id=r["id"], tenant_id=r["tenant_id"], private_key_pem=r["private_key_pem"], public_key_pem=r["public_key_pem"], created_at=r["created_at"], rotated_at=r["rotated_at"], status=r["status"])
        )
        self.invitations = PostgresDict(
            self._connect, "invitations", "id",
            to_obj_func=lambda r: Invitation(id=r["id"], tenant_id=r["tenant_id"], email=r["email"], role=r["role"], status=r["status"], created_at=r["created_at"])
        )

    def _connect(self):
        if getattr(self, "_pool", None) is not None:
            return self._pool.connection()
        return psycopg.connect(self.database_url, row_factory=dict_row)

    def _init_schema(self) -> None:
        import os
        import subprocess
        import sys
        try:
            backend_dir = Path(__file__).resolve().parents[1]
            ini_path = backend_dir / "alembic.ini"
            # Set DATABASE_URL in env for Alembic
            env = os.environ.copy()
            env["DATABASE_URL"] = self.database_url
            
            result = subprocess.run(
                ["alembic", "-c", str(ini_path), "upgrade", "head"],
                cwd=str(backend_dir),
                capture_output=True,
                text=True,
                env=env
            )
            if result.returncode != 0:
                print(f"Alembic migration failed (code {result.returncode}): {result.stderr}", file=sys.stderr)
                # Fallback to direct raw SQL script
                migration = Path(__file__).resolve().parents[1] / "migrations" / "001_initial_schema.sql"
                with self._connect() as conn:
                    conn.execute(migration.read_text())
                    conn.commit()
            else:
                print("Alembic database migrations applied successfully.", file=sys.stdout)
        except Exception as exc:
            print(f"Failed to run alembic on startup: {exc}. Falling back to raw SQL schema script.", file=sys.stderr)
            migration = Path(__file__).resolve().parents[1] / "migrations" / "001_initial_schema.sql"
            with self._connect() as conn:
                conn.execute(migration.read_text())
                conn.commit()


    def persist_tenant(self, tenant: Tenant) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO tenants (id, name, status, preferences)
                VALUES (%s, %s, %s, %s)
                ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name, status = EXCLUDED.status, preferences = EXCLUDED.preferences
                """,
                (tenant.id, tenant.name, tenant.status, Json(tenant.preferences)),
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
                INSERT INTO api_keys (id, tenant_id, token_hash, scopes, status, name, key_prefix, key_type, created_at, last_used_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (token_hash) DO UPDATE SET
                    status = EXCLUDED.status,
                    name = EXCLUDED.name,
                    key_prefix = EXCLUDED.key_prefix,
                    key_type = EXCLUDED.key_type,
                    last_used_at = EXCLUDED.last_used_at
                """,
                (
                    api_key.id,
                    api_key.tenant_id,
                    api_key.token_hash,
                    Json(api_key.scopes),
                    api_key.status,
                    api_key.name,
                    api_key.key_prefix,
                    api_key.key_type,
                    api_key.created_at,
                    api_key.last_used_at,
                ),
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

    def delete_user(self, email: str) -> None:
        super().delete_user(email)
        with self._connect() as conn:
            conn.execute("DELETE FROM workspace_users WHERE email = %s", (email,))
            conn.commit()

    def delete_invitation(self, id: UUID) -> None:
        super().delete_invitation(id)
        with self._connect() as conn:
            conn.execute("DELETE FROM invitations WHERE id = %s", (id,))
            conn.commit()




def create_store(database_url: str | None = None) -> InMemoryStore:
    if database_url:
        return PostgresStore(database_url)
    return InMemoryStore()


store = InMemoryStore()
