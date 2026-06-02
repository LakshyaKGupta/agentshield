from __future__ import annotations

import unittest
from datetime import timedelta, timezone

from backend.app.contracts import AgentCreateRequest, AnalyzeRequest, PermissionManifest
from backend.app.ledger.service import verify_ledger
from backend.app.security.jwt_identity import generate_dev_keypair
from backend.app.services import analyze_message, spawn_agent
from backend.app.settings import get_settings
from backend.app.store import InMemoryStore
from scripts.check_production_env import validate_environment


class ProductionReadinessTests(unittest.TestCase):
    def test_ledger_verification_is_timezone_canonical(self) -> None:
        store = InMemoryStore()
        settings = get_settings()
        tenant = store.seed_tenant()
        private_key, public_key = generate_dev_keypair()
        agent = spawn_agent(
            store,
            settings,
            request=AgentCreateRequest(
                name="timezone-regression-agent",
                permissions=PermissionManifest(tools={"web_search": ["read"]}),
            ),
            tenant_id=tenant.id,
            private_key_pem=private_key,
        )
        analyze_message(
            store,
            settings,
            AnalyzeRequest(agent_id=agent.agent_id, direction="inbound", message="hello from another timezone"),
            agent.token,
            public_key,
        )

        original = store.ledger[0]
        store.ledger[0] = original.model_copy(update={"created_at": original.created_at.astimezone(timezone(timedelta(hours=5, minutes=30)))})

        self.assertTrue(verify_ledger(store).valid)

    def test_production_env_rejects_demo_defaults(self) -> None:
        findings = validate_environment(
            {
                "DEMO_MODE": "false",
                "DATABASE_URL": "postgresql://agentshield:pw@db:5432/agentshield",
                "API_KEY_PEPPER": "dev-pepper-change-me",
                "JWT_ISSUER": "https://api.example.test",
                "JWT_AUDIENCE": "agentshield-agents",
                "ALLOWED_ORIGINS": "*",
            }
        )
        errors = {(finding.key, finding.level) for finding in findings}
        self.assertIn(("API_KEY_PEPPER", "error"), errors)
        self.assertIn(("ALLOWED_ORIGINS", "error"), errors)

    def test_production_env_accepts_minimum_hardened_shape(self) -> None:
        findings = validate_environment(
            {
                "DEMO_MODE": "false",
                "DATABASE_URL": "postgresql://agentshield:pw@db:5432/agentshield",
                "API_KEY_PEPPER": "abcdefghijklmnopqrstuvwxyz123456",
                "JWT_ISSUER": "https://api.example.test",
                "JWT_AUDIENCE": "agentshield-agents",
                "ALLOWED_ORIGINS": "https://app.example.test",
                "REDIS_URL": "redis://redis:6379/0",
                "KMS_KEY_ARN": "arn:aws:kms:us-east-1:123456789012:key/example",
            }
        )
        self.assertFalse([finding for finding in findings if finding.level == "error"])


if __name__ == "__main__":
    unittest.main()
