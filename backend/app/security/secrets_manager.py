"""
backend/app/security/secrets_manager.py
─────────────────────────────────────────
Secure production-grade secrets manager for AgentShield.

Provides a pluggable system to load sensitive credentials (e.g., database passwords,
signing keys, API key peppers) directly from an HSM/KMS-backed Cloud Secret Manager
(such as AWS Secrets Manager or HashiCorp Vault) rather than relying on flat local files.

Env vars:
---------
SECRETS_PROVIDER=local|aws|vault      (default: local)
AWS_SECRET_NAME=agentshield/prod       (required for aws)
AWS_DEFAULT_REGION=us-east-1           (optional)
"""
from __future__ import annotations

import json
import os
import logging
from typing import Any

logger = logging.getLogger(__name__)

_cached_secrets: dict[str, Any] | None = None


def get_secret(key: str, default: Any = None) -> Any:
    """
    Retrieve a secret value from the active pluggable secrets provider.
    Falls back to environment variables/local .env if the provider is 'local'
    or if the specific key is not found in the remote store.
    """
    global _cached_secrets
    provider = os.getenv("SECRETS_PROVIDER", "local").lower()

    if provider == "local":
        return os.getenv(key, default)

    if provider == "aws":
        if _cached_secrets is None:
            _cached_secrets = _load_secrets_from_aws()
        return _cached_secrets.get(key, os.getenv(key, default))

    if provider == "vault":
        # Stub for future HashiCorp Vault / OpenBao transit secrets engine
        logger.warning("VaultSecretsProvider is not yet implemented. Falling back to env.")
        return os.getenv(key, default)

    return os.getenv(key, default)


def _load_secrets_from_aws() -> dict[str, Any]:
    """Retrieve secrets from AWS Secrets Manager using boto3."""
    secret_name = os.getenv("AWS_SECRET_NAME")
    if not secret_name:
        logger.error("AWS_SECRET_NAME is not configured under SECRETS_PROVIDER=aws. Falling back to local env.")
        return {}

    region_name = os.getenv("AWS_DEFAULT_REGION", "us-east-1")
    logger.info(f"🔑 Loading secure credentials from AWS Secrets Manager: {secret_name} [{region_name}]")

    try:
        import boto3
        from botocore.exceptions import ClientError

        session = boto3.session.Session()
        client = session.client(
            service_name="secretsmanager",
            region_name=region_name
        )

        get_secret_value_response = client.get_secret_value(
            SecretId=secret_name
        )

        if "SecretString" in get_secret_value_response:
            secret = get_secret_value_response["SecretString"]
            return json.loads(secret)
        else:
            logger.error("Secret format not supported (binary payload).")
            return {}

    except ImportError:
        logger.error("boto3 is required for AWSSecretsProvider. Run: pip install boto3")
        return {}
    except ClientError as e:
        logger.error(f"Failed to fetch secrets from AWS Secrets Manager: {e}")
        return {}
    except json.JSONDecodeError:
        logger.error("Failed to parse secret string as JSON.")
        return {}
