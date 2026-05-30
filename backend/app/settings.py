from __future__ import annotations

import os
from dataclasses import dataclass
from dotenv import load_dotenv

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
    allowed_origins: tuple[str, ...] = (
        "http://localhost:5173",
        "http://localhost:5174",
        "http://localhost:5175",
        "http://127.0.0.1:5173",
        "http://127.0.0.1:5174",
        "http://127.0.0.1:5175",
    )
    demo_mode: bool = True


def get_settings() -> Settings:
    allowed_origins = tuple(
        origin.strip()
        for origin in os.getenv(
            "ALLOWED_ORIGINS",
            "http://localhost:5173,http://localhost:5174,http://localhost:5175,http://127.0.0.1:5173,http://127.0.0.1:5174,http://127.0.0.1:5175",
        ).split(",")
        if origin.strip()
    )
    return Settings(
        app_version=os.getenv("APP_VERSION", "0.1.0"),
        api_key_pepper=os.getenv("API_KEY_PEPPER", "dev-pepper-change-me"),
        jwt_issuer=os.getenv("JWT_ISSUER", "agentshield.local"),
        jwt_audience=os.getenv("JWT_AUDIENCE", "agentshield-agents"),
        jwt_private_key_pem=os.getenv("JWT_PRIVATE_KEY"),
        jwt_public_key_pem=os.getenv("JWT_PUBLIC_KEY"),
        database_url=os.getenv("DATABASE_URL"),
        allowed_origins=allowed_origins,
        demo_mode=os.getenv("DEMO_MODE", "true").lower() in {"1", "true", "yes", "on"},
    )
