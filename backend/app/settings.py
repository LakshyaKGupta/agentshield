from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    app_name: str = "AgentShield"
    api_key_pepper: str = "dev-pepper-change-me"
    jwt_issuer: str = "agentshield.local"
    jwt_audience: str = "agentshield-agents"
    jwt_private_key_pem: str | None = None
    jwt_public_key_pem: str | None = None


def get_settings() -> Settings:
    return Settings(
        api_key_pepper=os.getenv("API_KEY_PEPPER", "dev-pepper-change-me"),
        jwt_issuer=os.getenv("JWT_ISSUER", "agentshield.local"),
        jwt_audience=os.getenv("JWT_AUDIENCE", "agentshield-agents"),
        jwt_private_key_pem=os.getenv("JWT_PRIVATE_KEY"),
        jwt_public_key_pem=os.getenv("JWT_PUBLIC_KEY"),
    )

