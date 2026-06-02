from __future__ import annotations

import hashlib
import hmac
import secrets
from datetime import datetime, timezone
from uuid import UUID, uuid4

from ..settings import Settings
from ..store import ApiKeyRecord, InMemoryStore


def hash_api_key(raw_key: str, pepper: str) -> str:
    return hmac.new(pepper.encode(), raw_key.encode(), hashlib.sha256).hexdigest()


def create_api_key(
    store: InMemoryStore,
    settings: Settings,
    tenant_id: UUID,
    scopes: list[str] | None = None,
    *,
    name: str = "Workspace session",
    key_type: str = "session",
) -> str:
    raw_key = "as_live_" + secrets.token_urlsafe(32)
    token_hash = hash_api_key(raw_key, settings.api_key_pepper)
    record = ApiKeyRecord(
        id=uuid4(),
        tenant_id=tenant_id,
        token_hash=token_hash,
        scopes=scopes or ["agents:write", "shield:write", "ledger:read", "threats:read"],
        name=name,
        key_prefix=raw_key[:16],
        key_type=key_type,
    )
    store.api_keys[token_hash] = record
    store.persist_api_key(record)
    return raw_key


def list_sdk_api_keys(store: InMemoryStore, tenant_id: UUID) -> list[ApiKeyRecord]:
    return sorted(
        [
            record
            for record in store.api_keys.values()
            if record.tenant_id == tenant_id and record.key_type == "sdk"
        ],
        key=lambda record: record.created_at,
        reverse=True,
    )


def revoke_api_key(store: InMemoryStore, tenant_id: UUID, key_id: UUID) -> ApiKeyRecord:
    for record in store.api_keys.values():
        if record.id == key_id and record.tenant_id == tenant_id and record.key_type == "sdk":
            record.status = "revoked"
            store.persist_api_key(record)
            return record
    raise KeyError(str(key_id))


def authenticate_api_key(store: InMemoryStore, settings: Settings, raw_key: str | None, required_scope: str) -> ApiKeyRecord:
    if not raw_key:
        raise PermissionError("AUTH_API_KEY_MISSING")
    token_hash = hash_api_key(raw_key, settings.api_key_pepper)
    record = store.api_keys.get(token_hash)
    if not record or record.status != "active":
        raise PermissionError("AUTH_API_KEY_INVALID")
    if required_scope not in record.scopes:
        raise PermissionError("AUTH_API_KEY_INVALID")
    record.last_used_at = datetime.now(timezone.utc)
    store.persist_api_key(record)
    return record
