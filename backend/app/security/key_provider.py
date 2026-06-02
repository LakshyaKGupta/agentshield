"""
backend/app/security/key_provider.py
──────────────────────────────────────
Pluggable RSA signing-key provider for AgentShield.

Providers
---------
LocalKeyProvider  (default)
    Stores RSA-2048 keypairs as PEM files in ``backend/.keys/<tenant_id>/``.
    In dev mode (KEY_ENCRYPTION_KEY unset) files are stored as plaintext PEM
    (gitignored). In production set KEY_ENCRYPTION_KEY (32 random bytes, hex)
    and every private key is AES-256-GCM encrypted at rest.

KMSKeyProvider
    Delegates signing and verification to AWS KMS via boto3.
    Requires KMS_KEY_ARN and valid AWS credentials.

VaultKeyProvider  (stub)
    Intended for HashiCorp Vault / OpenBao — not yet implemented.

Usage
-----
Call ``get_key_provider(settings)`` once at startup, then:

    provider = get_key_provider(settings)
    private_pem, public_pem = provider.get_or_create_keypair(tenant_id)
    signature = provider.sign(tenant_id, data_bytes)
    provider.verify(tenant_id, data_bytes, signature)      # raises on failure

Env vars
--------
SIGNING_KEY_PROVIDER=local|kms|vault   (default: local)
KEY_ENCRYPTION_KEY=<64 hex chars>      (optional; plaintext PEM if absent)
KEYS_DIR=<path>                        (default: backend/.keys)
KMS_KEY_ARN=<arn>                      (required for kms provider)
"""
from __future__ import annotations

import os
import secrets
from abc import ABC, abstractmethod
from pathlib import Path
from typing import TYPE_CHECKING
from uuid import UUID

if TYPE_CHECKING:
    from ..settings import Settings


# ── helpers ───────────────────────────────────────────────────────

def _generate_rsa_pair() -> tuple[str, str]:
    """Generate a fresh RSA-2048 keypair; return (private_pem, public_pem)."""
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    public_pem = key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    return private_pem, public_pem


def _encrypt_pem(plaintext: str, hex_key: str) -> bytes:
    """AES-256-GCM encrypt a PEM string. Returns nonce(12) + tag(16) + ciphertext."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    key_bytes = bytes.fromhex(hex_key)
    nonce = secrets.token_bytes(12)
    ct = AESGCM(key_bytes).encrypt(nonce, plaintext.encode(), b"agentshield-key")
    return nonce + ct


def _decrypt_pem(blob: bytes, hex_key: str) -> str:
    """Reverse of _encrypt_pem. Raises on tampered data."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    key_bytes = bytes.fromhex(hex_key)
    nonce, ct = blob[:12], blob[12:]
    return AESGCM(key_bytes).decrypt(nonce, ct, b"agentshield-key").decode()


# ── base ──────────────────────────────────────────────────────────

class KeyProvider(ABC):
    @abstractmethod
    def get_or_create_keypair(self, tenant_id: UUID) -> tuple[str, str]:
        """Return (private_pem, public_pem) for the tenant's active key."""

    @abstractmethod
    def sign(self, tenant_id: UUID, data: bytes) -> bytes:
        """Sign *data* with the tenant's private key. Return raw signature bytes."""

    @abstractmethod
    def verify(self, tenant_id: UUID, data: bytes, signature: bytes) -> None:
        """Verify *signature* against *data*. Raise ``PermissionError`` on failure."""


# ── LocalKeyProvider ──────────────────────────────────────────────

class LocalKeyProvider(KeyProvider):
    """
    File-system backed key store.

    Layout::

        {keys_dir}/
            {tenant_id}/
                private.pem          # plaintext (dev)
                private.pem.enc      # AES-256-GCM encrypted blob (prod)
                public.pem           # always plaintext
    """

    def __init__(self, keys_dir: Path, encryption_key_hex: str | None = None) -> None:
        self._keys_dir = keys_dir
        self._enc_key = encryption_key_hex
        self._keys_dir.mkdir(parents=True, exist_ok=True)
        # In-process cache to avoid disk reads on every request
        self._cache: dict[UUID, tuple[str, str]] = {}

    def _tenant_dir(self, tenant_id: UUID) -> Path:
        d = self._keys_dir / str(tenant_id)
        d.mkdir(parents=True, exist_ok=True)
        return d

    def get_or_create_keypair(self, tenant_id: UUID) -> tuple[str, str]:
        if tenant_id in self._cache:
            return self._cache[tenant_id]

        td = self._tenant_dir(tenant_id)
        pub_path = td / "public.pem"

        if self._enc_key:
            priv_path = td / "private.pem.enc"
        else:
            priv_path = td / "private.pem"

        if priv_path.exists() and pub_path.exists():
            pub_pem = pub_path.read_text()
            if self._enc_key:
                priv_pem = _decrypt_pem(priv_path.read_bytes(), self._enc_key)
            else:
                priv_pem = priv_path.read_text()
            self._cache[tenant_id] = (priv_pem, pub_pem)
            return priv_pem, pub_pem

        # Generate new pair
        priv_pem, pub_pem = _generate_rsa_pair()
        pub_path.write_text(pub_pem)
        if self._enc_key:
            priv_path.write_bytes(_encrypt_pem(priv_pem, self._enc_key))
        else:
            priv_path.write_text(priv_pem)
            # chmod 600 — owner-read only
            os.chmod(priv_path, 0o600)

        self._cache[tenant_id] = (priv_pem, pub_pem)
        return priv_pem, pub_pem

    def sign(self, tenant_id: UUID, data: bytes) -> bytes:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding
        from cryptography.hazmat.primitives.serialization import load_pem_private_key

        priv_pem, _ = self.get_or_create_keypair(tenant_id)
        priv_key = load_pem_private_key(priv_pem.encode(), password=None)
        return priv_key.sign(data, padding.PKCS1v15(), hashes.SHA256())

    def verify(self, tenant_id: UUID, data: bytes, signature: bytes) -> None:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding
        from cryptography.hazmat.primitives.serialization import load_pem_public_key
        from cryptography.exceptions import InvalidSignature

        _, pub_pem = self.get_or_create_keypair(tenant_id)
        pub_key = load_pem_public_key(pub_pem.encode())
        try:
            pub_key.verify(signature, data, padding.PKCS1v15(), hashes.SHA256())
        except InvalidSignature:
            raise PermissionError("KEY_SIGNATURE_INVALID") from None


# ── KMSKeyProvider ────────────────────────────────────────────────

class KMSKeyProvider(KeyProvider):
    """
    AWS KMS asymmetric signing provider.
    One CMK is shared across all tenants (multi-tenant via context).
    Requires: KMS_KEY_ARN env var, boto3 installed, valid AWS credentials.
    """

    def __init__(self, key_arn: str) -> None:
        self._key_arn = key_arn
        try:
            import boto3  # type: ignore
            self._client = boto3.client("kms")
        except ImportError as exc:
            raise RuntimeError("boto3 is required for KMSKeyProvider. pip install boto3.") from exc

    def get_or_create_keypair(self, tenant_id: UUID) -> tuple[str, str]:
        # KMS manages the key material; we only expose the public key
        resp = self._client.get_public_key(KeyId=self._key_arn)
        pub_der = resp["PublicKey"]
        from cryptography.hazmat.primitives.serialization import (
            Encoding, PublicFormat, load_der_public_key
        )
        pub_pem = load_der_public_key(pub_der).public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode()
        return "", pub_pem  # private key never leaves KMS

    def sign(self, tenant_id: UUID, data: bytes) -> bytes:
        resp = self._client.sign(
            KeyId=self._key_arn,
            Message=data,
            MessageType="RAW",
            SigningAlgorithm="RSASSA_PKCS1_V1_5_SHA_256",
        )
        return resp["Signature"]

    def verify(self, tenant_id: UUID, data: bytes, signature: bytes) -> None:
        resp = self._client.verify(
            KeyId=self._key_arn,
            Message=data,
            MessageType="RAW",
            Signature=signature,
            SigningAlgorithm="RSASSA_PKCS1_V1_5_SHA_256",
        )
        if not resp.get("SignatureValid", False):
            raise PermissionError("KEY_SIGNATURE_INVALID")


# ── VaultKeyProvider stub ─────────────────────────────────────────

class VaultKeyProvider(KeyProvider):
    """Stub for HashiCorp Vault / OpenBao transit secrets engine."""

    def __init__(self) -> None:
        raise NotImplementedError(
            "VaultKeyProvider is not yet implemented. "
            "Use LocalKeyProvider (dev) or KMSKeyProvider (AWS)."
        )

    def get_or_create_keypair(self, tenant_id: UUID) -> tuple[str, str]:  # type: ignore[override]
        raise NotImplementedError

    def sign(self, tenant_id: UUID, data: bytes) -> bytes:  # type: ignore[override]
        raise NotImplementedError

    def verify(self, tenant_id: UUID, data: bytes, signature: bytes) -> None:
        raise NotImplementedError


# ── Factory ───────────────────────────────────────────────────────

_provider_singleton: KeyProvider | None = None


def get_key_provider(settings: "Settings") -> KeyProvider:
    """Return the module-level singleton key provider, constructing it on first call."""
    global _provider_singleton
    if _provider_singleton is not None:
        return _provider_singleton

    provider_name = getattr(settings, "signing_key_provider", "local")

    if provider_name == "kms":
        key_arn = getattr(settings, "kms_key_arn", None)
        if not key_arn:
            raise RuntimeError("KMS_KEY_ARN must be set when SIGNING_KEY_PROVIDER=kms")
        _provider_singleton = KMSKeyProvider(key_arn)

    elif provider_name == "vault":
        _provider_singleton = VaultKeyProvider()  # raises NotImplementedError

    else:  # "local" (default)
        keys_dir_str = getattr(settings, "keys_dir", None)
        keys_dir = (
            Path(keys_dir_str)
            if keys_dir_str
            else Path(__file__).resolve().parents[2] / ".keys"
        )
        enc_key = getattr(settings, "key_encryption_key", None) or None
        # Validate hex key format if provided
        if enc_key:
            try:
                decoded = bytes.fromhex(enc_key)
                if len(decoded) != 32:
                    raise ValueError
            except ValueError:
                raise RuntimeError(
                    "KEY_ENCRYPTION_KEY must be exactly 64 hex characters (32 bytes). "
                    "Generate with: python3 -c \"import secrets; print(secrets.token_hex(32))\""
                )
        _provider_singleton = LocalKeyProvider(keys_dir, enc_key)

    return _provider_singleton
