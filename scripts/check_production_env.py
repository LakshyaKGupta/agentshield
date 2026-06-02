from __future__ import annotations

import os
import re
import sys
from dataclasses import dataclass
from typing import Mapping
from urllib.parse import urlparse


REQUIRED_IN_PRODUCTION = (
    "DATABASE_URL",
    "API_KEY_PEPPER",
    "JWT_ISSUER",
    "JWT_AUDIENCE",
    "ALLOWED_ORIGINS",
)

INSECURE_VALUES = {
    "API_KEY_PEPPER": {"dev-pepper-change-me", "change-me", "changeme", "replace-with-random-32-byte-secret"},
}


@dataclass(frozen=True)
class ReadinessFinding:
    level: str
    key: str
    message: str


def _truthy(value: str | None) -> bool:
    return (value or "").strip().lower() in {"1", "true", "yes", "on"}


def validate_environment(env: Mapping[str, str]) -> list[ReadinessFinding]:
    findings: list[ReadinessFinding] = []
    demo_mode = _truthy(env.get("DEMO_MODE", "true"))

    if demo_mode:
        findings.append(ReadinessFinding("warn", "DEMO_MODE", "DEMO_MODE=true is acceptable only for local demos."))
    else:
        for key in REQUIRED_IN_PRODUCTION:
            if not env.get(key):
                findings.append(ReadinessFinding("error", key, f"{key} is required when DEMO_MODE=false."))

    pepper = env.get("API_KEY_PEPPER", "")
    if pepper in INSECURE_VALUES["API_KEY_PEPPER"] or len(pepper) < 32:
        findings.append(ReadinessFinding("error", "API_KEY_PEPPER", "Use a unique random secret with at least 32 characters."))

    database_url = env.get("DATABASE_URL", "")
    if database_url:
        scheme = urlparse(database_url).scheme
        if scheme not in {"postgresql", "postgres"}:
            findings.append(ReadinessFinding("error", "DATABASE_URL", "Production persistence must use PostgreSQL."))
    elif not demo_mode:
        findings.append(ReadinessFinding("error", "DATABASE_URL", "PostgreSQL is required for production readiness."))

    origins = [origin.strip() for origin in env.get("ALLOWED_ORIGINS", "").split(",") if origin.strip()]
    if "*" in origins and not demo_mode:
        findings.append(ReadinessFinding("error", "ALLOWED_ORIGINS", "Wildcard CORS is not allowed in production."))
    for origin in origins:
        if origin.startswith("http://") and "localhost" not in origin and "127.0.0.1" not in origin:
            findings.append(ReadinessFinding("warn", "ALLOWED_ORIGINS", f"Non-HTTPS origin configured: {origin}"))

    redis_url = env.get("REDIS_URL", "")
    if not redis_url and not demo_mode:
        findings.append(ReadinessFinding("warn", "REDIS_URL", "Redis is recommended for production rate limiting across multiple API instances."))

    kms_key = env.get("KMS_KEY_ARN", "")
    if not kms_key and not demo_mode:
        findings.append(ReadinessFinding("warn", "KMS_KEY_ARN", "KMS/HSM-backed key custody is still required for production-grade signing keys."))

    jwt_private = env.get("JWT_PRIVATE_KEY", "")
    if jwt_private and not re.search(r"BEGIN (RSA )?PRIVATE KEY", jwt_private):
        findings.append(ReadinessFinding("error", "JWT_PRIVATE_KEY", "JWT_PRIVATE_KEY must be PEM encoded."))

    return findings


def main() -> int:
    findings = validate_environment(os.environ)
    for finding in findings:
        print(f"{finding.level.upper()} {finding.key}: {finding.message}")
    return 1 if any(f.level == "error" for f in findings) else 0


if __name__ == "__main__":
    raise SystemExit(main())
