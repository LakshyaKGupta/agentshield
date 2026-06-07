from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from dotenv import load_dotenv

_BACKEND_ENV = Path(__file__).resolve().parents[1] / ".env"
load_dotenv(_BACKEND_ENV)
load_dotenv()


@dataclass(frozen=True)
class Settings:
    app_name: str = "AgentShield"
    app_version: str = "0.1.0"
    api_key_pepper: str = "dev-pepper-change-me"
    jwt_issuer: str = "agentshield.local"
    jwt_audience: str = "agentshield-agents"
    jwt_private_key_pem: str | None = None
    jwt_public_key_pem: str | None = None
    database_url: str | None = None
    redis_url: str | None = None
    kms_key_arn: str | None = None
    signing_key_provider: str = "local"
    key_encryption_key: str | None = None
    keys_dir: str | None = None
    oidc_issuer_url: str | None = None
    oidc_client_id: str | None = None
    oidc_client_secret: str | None = None
    oidc_redirect_uri: str | None = None
    scim_bearer_token: str | None = None
    allowed_origins: tuple[str, ...] = (
        "http://localhost:5173",
        "http://localhost:5174",
        "http://localhost:5175",
        "http://127.0.0.1:5173",
        "http://127.0.0.1:5174",
        "http://127.0.0.1:5175",
    )
    demo_mode: bool = False


from .security.secrets_manager import get_secret


def get_settings() -> Settings:
    allowed_origins = tuple(
        origin.strip()
        for origin in get_secret(
            "ALLOWED_ORIGINS",
            "http://localhost:5173,http://localhost:5174,http://localhost:5175,http://127.0.0.1:5173,http://127.0.0.1:5174,http://127.0.0.1:5175",
        ).split(",")
        if origin.strip()
    )
    return Settings(
        app_version=get_secret("APP_VERSION", "0.1.0"),
        api_key_pepper=get_secret("API_KEY_PEPPER", "dev-pepper-change-me"),
        jwt_issuer=get_secret("JWT_ISSUER", "agentshield.local"),
        jwt_audience=get_secret("JWT_AUDIENCE", "agentshield-agents"),
        jwt_private_key_pem=get_secret("JWT_PRIVATE_KEY"),
        jwt_public_key_pem=get_secret("JWT_PUBLIC_KEY"),
        database_url=get_secret("DATABASE_URL"),
        redis_url=get_secret("REDIS_URL"),
        kms_key_arn=get_secret("KMS_KEY_ARN"),
        signing_key_provider=get_secret("SIGNING_KEY_PROVIDER", "local"),
        key_encryption_key=get_secret("KEY_ENCRYPTION_KEY"),
        keys_dir=get_secret("KEYS_DIR"),
        oidc_issuer_url=get_secret("OIDC_ISSUER_URL"),
        oidc_client_id=get_secret("OIDC_CLIENT_ID"),
        oidc_client_secret=get_secret("OIDC_CLIENT_SECRET"),
        oidc_redirect_uri=get_secret("OIDC_REDIRECT_URI"),
        scim_bearer_token=get_secret("SCIM_BEARER_TOKEN"),
        allowed_origins=allowed_origins,
        demo_mode=str(get_secret("DEMO_MODE", "false")).lower() in {"1", "true", "yes", "on"},
    )
