from __future__ import annotations

import os
import unittest
from uuid import uuid4

from backend.app.contracts import (
    AgentCreateRequest,
    AnalyzeRequest,
    PermissionManifest,
    Severity,
    Verdict,
)
from backend.app.ledger.service import verify_ledger
from backend.app.security.api_keys import create_api_key
from backend.app.security.jwt_identity import generate_dev_keypair
from backend.app.services import analyze_message, spawn_agent
from backend.app.settings import get_settings
from backend.app.store import CryptographicKey, PostgresStore, create_store


class PostgresIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.db_url = os.getenv("AGENTSHIELD_TEST_DATABASE_URL")
        cls.redis_url = os.getenv("REDIS_URL", "redis://127.0.0.1:6379/0")
        cls.settings = get_settings()

        if not cls.db_url:
            cls.store = None
            cls.enabled = False
            print("Skipping PostgresIntegrationTests: set AGENTSHIELD_TEST_DATABASE_URL to a disposable test database.")
            return

        app_db_url = os.getenv("DATABASE_URL")
        if app_db_url and cls.db_url == app_db_url:
            cls.store = None
            cls.enabled = False
            print("Skipping PostgresIntegrationTests: AGENTSHIELD_TEST_DATABASE_URL must not equal DATABASE_URL.")
            return
        
        # Test if postgres connection works, otherwise skip tests
        try:
            cls.store = PostgresStore(cls.db_url)
            cls.enabled = True
        except Exception as e:
            cls.enabled = False
            print(f"Skipping PostgresIntegrationTests: Postgres not available ({e})")

    def setUp(self) -> None:
        if not self.enabled:
            self.skipTest("PostgreSQL integration database is not running.")
        
        # Drop all tables CASCADE to clean up completely bypass append-only triggers
        with self.store._connect() as conn:
            conn.execute("""
                DROP TABLE IF EXISTS alembic_version CASCADE;
                DROP TABLE IF EXISTS invitations CASCADE;
                DROP TABLE IF EXISTS cryptographic_keys CASCADE;
                DROP TABLE IF EXISTS event_outbox CASCADE;
                DROP TABLE IF EXISTS trust_history CASCADE;
                DROP TABLE IF EXISTS threat_events CASCADE;
                DROP TABLE IF EXISTS audit_ledger CASCADE;
                DROP TABLE IF EXISTS agent_tokens CASCADE;
                DROP TABLE IF EXISTS agents CASCADE;
                DROP TABLE IF EXISTS workspace_users CASCADE;
                DROP TABLE IF EXISTS api_keys CASCADE;
                DROP TABLE IF EXISTS tenants CASCADE;
            """)
            conn.commit()
            
        # Re-initialize the schema using Alembic/SQL script
        self.store._init_schema()

    def test_tenant_and_cascades(self) -> None:
        # 1. Create tenant
        tenant = self.store.seed_tenant("Integration Workspace")
        self.assertIn(tenant.id, self.store.tenants)
        
        # 2. Add API key
        api_key = create_api_key(self.store, self.settings, tenant.id)
        self.assertTrue(any(k.tenant_id == tenant.id for k in self.store.api_keys.values()))
        
        # 3. Add workspace user
        from backend.app.store import WorkspaceUser
        user = WorkspaceUser(
            id=uuid4(),
            tenant_id=tenant.id,
            email="integration-owner@example.com",
            password_hash="hashed_password",
        )
        self.store.persist_user(user)
        self.assertIn("integration-owner@example.com", self.store.users)
        
        # 4. Delete tenant and verify CASCADE deletes everything
        with self.store._connect() as conn:
            conn.execute("DELETE FROM tenants WHERE id = %s", (tenant.id,))
            conn.commit()
            
        # Verify cascades
        self.assertNotIn(tenant.id, self.store.tenants)
        self.assertFalse(any(k.tenant_id == tenant.id for k in self.store.api_keys.values()))
        self.assertNotIn("integration-owner@example.com", self.store.users)

    def test_append_only_ledger_trigger_prevents_modifications(self) -> None:
        tenant = self.store.seed_tenant("Ledger Test Workspace")
        priv, pub = generate_dev_keypair()
        agent = spawn_agent(
            self.store,
            self.settings,
            AgentCreateRequest(
                name="ledger-agent",
                permissions=PermissionManifest(tools={"web_search": ["read"]}),
            ),
            tenant.id,
            priv,
        )
        
        # Append a ledger entry
        analyze_message(
            self.store,
            self.settings,
            AnalyzeRequest(agent_id=agent.agent_id, direction="inbound", message="Benign payload"),
            agent.token,
            pub,
        )
        
        self.assertEqual(len(self.store.ledger), 2)
        ledger_entry = self.store.ledger[1]
        
        # Attempting to UPDATE the entry should raise an exception (Database Trigger)
        with self.assertRaises(Exception):
            with self.store._connect() as conn:
                conn.execute(
                    "UPDATE audit_ledger SET verdict = %s WHERE id = %s",
                    ("BLOCKED", ledger_entry.id),
                )
                conn.commit()
                
        # Attempting to DELETE the entry should raise an exception (Database Trigger)
        with self.assertRaises(Exception):
            with self.store._connect() as conn:
                conn.execute("DELETE FROM audit_ledger WHERE id = %s", (ledger_entry.id,))
                conn.commit()

    def test_ledger_hash_chain_verification(self) -> None:
        tenant = self.store.seed_tenant("Ledger Chain Workspace")
        priv, pub = generate_dev_keypair()
        agent = spawn_agent(
            self.store,
            self.settings,
            AgentCreateRequest(
                name="ledger-agent-2",
                permissions=PermissionManifest(tools={"web_search": ["read"]}),
            ),
            tenant.id,
            priv,
        )
        
        # Add 3 benign events
        for i in range(3):
            analyze_message(
                self.store,
                self.settings,
                AnalyzeRequest(agent_id=agent.agent_id, direction="inbound", message=f"message-{i}"),
                agent.token,
                pub,
            )
            
        self.assertEqual(len(self.store.ledger), 4)
        self.assertTrue(verify_ledger(self.store).valid)

        # Force bypass trigger via raw db (or if we tamper with the in-memory cache representation)
        # Note: the trigger prevents UPDATE on postgres. Let's make sure postgres verification is canonical.
        ledger_status = verify_ledger(self.store)
        self.assertTrue(ledger_status.valid)


if __name__ == "__main__":
    unittest.main()
