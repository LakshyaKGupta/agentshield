"""Firebase ID token verification for AgentShield.

Works in two modes:
1. Firebase Admin SDK available (firebase-admin installed + FIREBASE_PROJECT_ID set):
   Verifies the token cryptographically against Firebase's public keys.

2. Fallback (no firebase-admin or no project configured):
   Decodes the JWT without full verification for local dev convenience,
   extracts email/uid from claims, and logs a warning.
   ⚠  Do NOT use fallback mode in production.
"""
from __future__ import annotations

import json
import logging
import os
import ssl
import time
import urllib.request
from base64 import urlsafe_b64decode

logger = logging.getLogger(__name__)

_FIREBASE_ADMIN_AVAILABLE = False
_firebase_app = None
_CERT_CACHE: dict[str, object] = {"expires_at": 0.0, "certs": {}}
_FIREBASE_CERTS_URL = "https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com"

try:
    import firebase_admin  # type: ignore
    from firebase_admin import auth as firebase_auth  # type: ignore
    _FIREBASE_ADMIN_AVAILABLE = True
except ImportError:
    logger.warning(
        "firebase-admin not installed. Firebase token verification will use "
        "unverified JWT decoding (LOCAL DEV ONLY). Install firebase-admin for production."
    )


def _b64_decode_padding(s: str) -> bytes:
    s += "=" * (-len(s) % 4)
    return urlsafe_b64decode(s)


def _decode_jwt_claims_unsafe(token: str) -> dict:
    """Decode JWT payload without signature verification (dev fallback only)."""
    try:
        parts = token.split(".")
        if len(parts) != 3:
            raise ValueError("Not a valid JWT")
        payload = _b64_decode_padding(parts[1])
        return json.loads(payload)
    except Exception as e:
        raise ValueError(f"Could not decode Firebase ID token: {e}") from e


def _fetch_firebase_public_certs() -> dict[str, str]:
    now = time.time()
    cached = _CERT_CACHE.get("certs")
    if cached and now < float(_CERT_CACHE.get("expires_at", 0.0)):
        return cached  # type: ignore[return-value]

    cafile = None
    try:
        import certifi
        cafile = certifi.where()
    except Exception:
        cafile = None
    context = ssl.create_default_context(cafile=cafile)

    with urllib.request.urlopen(_FIREBASE_CERTS_URL, timeout=5, context=context) as response:
        payload = response.read().decode("utf-8")
        cache_control = response.headers.get("Cache-Control", "")

    max_age = 3600
    for part in cache_control.split(","):
        part = part.strip()
        if part.startswith("max-age="):
            try:
                max_age = int(part.split("=", 1)[1])
            except ValueError:
                pass

    certs = json.loads(payload)
    _CERT_CACHE["certs"] = certs
    _CERT_CACHE["expires_at"] = now + max_age
    return certs


def _verify_firebase_id_token_with_public_certs(id_token: str, project_id: str) -> dict:
    import jwt
    from cryptography import x509

    try:
        header = jwt.get_unverified_header(id_token)
    except Exception as e:
        raise ValueError(f"Invalid Firebase token header: {e}") from e

    kid = header.get("kid")
    if not kid:
        raise ValueError("Firebase token header is missing key id.")

    cert = _fetch_firebase_public_certs().get(kid)
    if not cert:
        raise ValueError("Firebase token signing key is unknown or expired.")

    try:
        public_key = x509.load_pem_x509_certificate(cert.encode("utf-8")).public_key()
        decoded = jwt.decode(
            id_token,
            public_key,
            algorithms=["RS256"],
            audience=project_id,
            issuer=f"https://securetoken.google.com/{project_id}",
            options={"require": ["aud", "iss", "sub", "iat", "exp"]},
        )
    except Exception as e:
        raise ValueError(f"Firebase token verification failed: {e}") from e

    uid = decoded.get("user_id") or decoded.get("sub") or decoded.get("uid")
    if not uid:
        raise ValueError("Firebase token is missing user id.")
    return {"uid": uid, "email": decoded.get("email") or ""}


def verify_firebase_id_token(id_token: str) -> dict:
    """
    Verify a Firebase ID token and return its claims.

    Returns:
        dict with at least: uid, email (may be None for Google-sign-in w/o email)
    Raises:
        ValueError if the token is invalid or if authentication is bypassed.
    """
    from ..settings import get_settings
    settings = get_settings()

    if settings.demo_mode:
        raise ValueError("Firebase Auth is disabled in Demo/Development Mode. Please use standard Workspace Email/Password authentication.")

    project_id = os.environ.get("FIREBASE_PROJECT_ID", "")
    if not project_id:
        logger.error("Production Error: FIREBASE_PROJECT_ID is missing.")
        raise ValueError("Authentication service misconfigured")

    return _verify_firebase_id_token_with_public_certs(id_token, project_id)
