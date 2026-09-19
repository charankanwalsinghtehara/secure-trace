"""AES-GCM encryption for local document metadata storage."""

import base64
import os
import secrets

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


_KEY_ENV = "CRYPTATRACE_STORAGE_KEY"
_DEV_KEY = "cryptatrace-development-storage-key-change-before-deployment"


def _key() -> bytes:
    configured = os.environ.get(_KEY_ENV)
    if configured:
        try:
            decoded = base64.urlsafe_b64decode(configured + "=" * (-len(configured) % 4))
            if len(decoded) == 32:
                return decoded
        except ValueError:
            pass
    return __import__("hashlib").sha3_256((configured or _DEV_KEY).encode("utf-8")).digest()


def encrypt_bytes(value: bytes) -> str:
    nonce = secrets.token_bytes(12)
    ciphertext = AESGCM(_key()).encrypt(nonce, value, None)
    return base64.urlsafe_b64encode(nonce + ciphertext).decode("ascii")


def decrypt_bytes(value: str) -> bytes:
    encoded = base64.urlsafe_b64decode(value.encode("ascii"))
    return AESGCM(_key()).decrypt(encoded[:12], encoded[12:], None)
