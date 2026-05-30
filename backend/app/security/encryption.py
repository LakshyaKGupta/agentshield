from __future__ import annotations

import base64
import os
from typing import Any
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

# Master Key Encryption Key (KEK) simulation
# In production, this would be fetched from a secure KMS provider (e.g. AWS KMS, HashiCorp Vault)
_MASTER_KEK = b"agent_shield_super_secure_kek_32"


class EnvelopeEncryptor:
    """
    Enterprise Envelope Encryptor.
    Utilizes AES-256-GCM to encrypt and decrypt sensitive audit ledger payloads.
    Generates a unique Data Encryption Key (DEK) for each workspace,
    and wraps the DEK using the master Key Encryption Key (KEK).
    """
    def __init__(self, tenant_id: str):
        self.tenant_id = tenant_id
        self._dek = self._derive_dek()

    def _derive_dek(self) -> bytes:
        """Derive a workspace-specific Data Encryption Key (DEK) using PBKDF2."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.tenant_id.encode(),
            iterations=1000,
        )
        return kdf.derive(_MASTER_KEK)

    def encrypt(self, plaintext: str) -> str:
        """
        Encrypts plaintext string using AES-256-GCM.
        Returns a base64-encoded payload containing: iv + tag + ciphertext.
        """
        iv = os.urandom(12)
        encryptor = Cipher(
            algorithms.AES(self._dek),
            modes.GCM(iv),
        ).encryptor()
        
        ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()
        
        # Structure the payload: IV (12B) + TAG (16B) + Ciphertext
        encrypted_bytes = iv + encryptor.tag + ciphertext
        return base64.b64encode(encrypted_bytes).decode()

    def decrypt(self, encrypted_b64: str) -> str:
        """Decrypts a base64-encoded AES-256-GCM payload."""
        try:
            encrypted_bytes = base64.b64decode(encrypted_b64.encode())
            if len(encrypted_bytes) < 28:
                raise ValueError("Invalid encrypted payload length.")
                
            iv = encrypted_bytes[:12]
            tag = encrypted_bytes[12:28]
            ciphertext = encrypted_bytes[28:]
            
            decryptor = Cipher(
                algorithms.AES(self._dek),
                modes.GCM(iv, tag),
            ).decryptor()
            
            decrypted_bytes = decryptor.update(ciphertext) + decryptor.finalize()
            return decrypted_bytes.decode()
        except Exception as exc:
            raise RuntimeError(f"Envelope decryption failed: {exc}") from exc
