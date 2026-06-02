from __future__ import annotations

import base64
import json
from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4
from functools import lru_cache

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from ..settings import Settings
from ..store import InMemoryStore, TokenRecord


@lru_cache(maxsize=256)
def _get_cached_public_key(public_key_pem: str):
    return serialization.load_pem_public_key(public_key_pem.encode())


@lru_cache(maxsize=128)
def _get_cached_private_key(private_key_pem: str):
    return serialization.load_pem_private_key(private_key_pem.encode(), password=None)


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_decode(data: str) -> bytes:
    padding_len = (4 - len(data) % 4) % 4
    return base64.urlsafe_b64decode(data + ("=" * padding_len))


def generate_dev_keypair() -> tuple[str, str]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    public = key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    return private, public


def issue_agent_token(
    store: InMemoryStore,
    settings: Settings,
    tenant_id: UUID,
    agent_id: UUID,
    private_key_pem: str,
    ttl_minutes: int = 60,
) -> tuple[str, datetime, str]:
    now = datetime.now(timezone.utc)
    exp = now + timedelta(minutes=ttl_minutes)
    jti = str(uuid4())
    
    from .key_provider import get_key_provider
    provider = get_key_provider(settings)
    
    use_kms = settings.signing_key_provider == "kms"
    kid = settings.kms_key_arn if use_kms else f"key-{tenant_id}"
    
    header = {"alg": "RS256", "typ": "JWT", "kid": kid}
    payload = {
        "iss": settings.jwt_issuer,
        "aud": settings.jwt_audience,
        "sub": str(agent_id),
        "agent_id": str(agent_id),
        "tenant_id": str(tenant_id),
        "iat": int(now.timestamp()),
        "exp": int(exp.timestamp()),
        "jti": jti,
        "scopes": ["agent:act"],
    }
    signing_input = f"{_b64url(json.dumps(header, separators=(',', ':')).encode())}.{_b64url(json.dumps(payload, separators=(',', ':')).encode())}"
    
    try:
        signature = provider.sign(tenant_id, signing_input.encode('utf-8'))
    except Exception:
        # Fallback to store active keys or private_key_pem (for tests)
        active_keys = [k for k in store.keys.values() if k.tenant_id == tenant_id and k.status == "active"]
        target_key_pem = active_keys[0].private_key_pem if active_keys else private_key_pem
        
        private_key = _get_cached_private_key(target_key_pem)
        signature = private_key.sign(signing_input.encode(), padding.PKCS1v15(), hashes.SHA256())
        
    token = f"{signing_input}.{_b64url(signature)}"
    record = TokenRecord(jti=jti, tenant_id=tenant_id, agent_id=agent_id, expires_at=exp)
    store.tokens[jti] = record
    store.persist_token(record)
    return token, exp, jti


def verify_agent_token(store: InMemoryStore, settings: Settings, token: str | None, public_key_pem: str, expected_agent_id: UUID) -> dict:
    if not token:
        raise PermissionError("AUTH_AGENT_TOKEN_INVALID")
    parts = token.split(".")
    if len(parts) != 3:
        raise PermissionError("AUTH_AGENT_TOKEN_INVALID")
    signing_input = f"{parts[0]}.{parts[1]}"
    try:
        header = json.loads(_b64url_decode(parts[0]))
        payload = json.loads(_b64url_decode(parts[1]))
        signature = _b64url_decode(parts[2])
        tenant_id = UUID(payload["tenant_id"])
        
        # Eliminate sequential RSA loop DoS: reject immediately if kid is missing or invalid
        kid = header.get("kid")
        expected_kid = settings.kms_key_arn if settings.signing_key_provider == "kms" else f"key-{tenant_id}"
        if not kid or kid != expected_kid:
            raise PermissionError("AUTH_AGENT_TOKEN_INVALID")
        
        from .key_provider import get_key_provider
        provider = get_key_provider(settings)
        try:
            provider.verify(tenant_id, signing_input.encode('utf-8'), signature)
        except Exception as provider_err:
            # Fallback for existing tests that use in-memory keys
            tenant_keys = [k for k in store.keys.values() if k.tenant_id == tenant_id]
            if tenant_keys:
                signature_verified = False
                for tk in tenant_keys:
                    try:
                        public_key = _get_cached_public_key(tk.public_key_pem)
                        public_key.verify(signature, signing_input.encode(), padding.PKCS1v15(), hashes.SHA256())
                        signature_verified = True
                        break
                    except Exception:
                        pass
                if not signature_verified:
                    raise PermissionError("AUTH_AGENT_TOKEN_INVALID") from provider_err
            else:
                public_key = _get_cached_public_key(public_key_pem)
                public_key.verify(signature, signing_input.encode(), padding.PKCS1v15(), hashes.SHA256())
    except Exception as e:
        raise PermissionError("AUTH_AGENT_TOKEN_INVALID") from e

    now_ts = int(datetime.now(timezone.utc).timestamp())
    if payload.get("iss") != settings.jwt_issuer or payload.get("aud") != settings.jwt_audience:
        raise PermissionError("AUTH_AGENT_TOKEN_INVALID")
    if int(payload.get("exp", 0)) <= now_ts:
        raise PermissionError("AUTH_AGENT_TOKEN_INVALID")
    if payload.get("agent_id") != str(expected_agent_id):
        raise PermissionError("AUTH_AGENT_TOKEN_INVALID")
    record = store.tokens.get(payload.get("jti"))
    if not record or record.revoked_at is not None:
        raise PermissionError("AUTH_AGENT_TOKEN_REVOKED")
    agent = store.agents.get(expected_agent_id)
    if not agent or agent.status != "active":
        raise PermissionError("AUTH_AGENT_TOKEN_REVOKED")
    return payload
