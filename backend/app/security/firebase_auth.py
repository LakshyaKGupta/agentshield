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
from base64 import urlsafe_b64decode

logger = logging.getLogger(__name__)

_FIREBASE_ADMIN_AVAILABLE = False
_firebase_app = None

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


def verify_firebase_id_token(id_token: str) -> dict:
    """
    Verify a Firebase ID token and return its claims.

    Returns:
        dict with at least: uid, email (may be None for Google-sign-in w/o email)
    Raises:
        ValueError if the token is invalid.
    """
    project_id = os.environ.get("FIREBASE_PROJECT_ID", "")

    if _FIREBASE_ADMIN_AVAILABLE and project_id:
        global _firebase_app
        if _firebase_app is None:
            try:
                if "GOOGLE_CLOUD_PROJECT" not in os.environ:
                    os.environ["GOOGLE_CLOUD_PROJECT"] = project_id
                _firebase_app = firebase_admin.initialize_app(options={"projectId": project_id})
            except ValueError:
                _firebase_app = firebase_admin.get_app()
        try:
            decoded = firebase_auth.verify_id_token(id_token)
            return {"uid": decoded["uid"], "email": decoded.get("email") or decoded.get("email", "")}
        except Exception as e:
            raise ValueError(f"Firebase token verification failed: {e}") from e
    else:
        logger.warning(
            "⚠  Using UNVERIFIED Firebase token decode. "
            "Set FIREBASE_PROJECT_ID and install firebase-admin for production."
        )
        claims = _decode_jwt_claims_unsafe(id_token)
        uid = claims.get("user_id") or claims.get("sub") or claims.get("uid", "")
        email = claims.get("email", "") or f"{uid}@firebase.local"
        return {"uid": uid, "email": email}
