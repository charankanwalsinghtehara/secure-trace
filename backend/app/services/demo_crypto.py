"""Development-only signing adapter.

This intentionally uses HMAC only to keep the air-gapped demo dependency-free.
Production must install and wire an audited ML-DSA implementation; this adapter
must never be used for evidentiary deployments.
"""

import base64
import hashlib
import hmac
import secrets


ALGORITHM = "DEMO-HMAC-SHA256 (REPLACE WITH ML-DSA-65)"


def generate_private_key() -> str:
    return secrets.token_hex(32)


def public_key_from_private(private_key: str) -> str:
    return hashlib.sha256(private_key.encode("ascii")).hexdigest()


def sign(payload: bytes, private_key: str) -> str:
    digest = hmac.new(private_key.encode("ascii"), payload, hashlib.sha256).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii")


def verify(payload: bytes, signature: str, private_key: str) -> bool:
    expected = sign(payload, private_key)
    return hmac.compare_digest(expected, signature)