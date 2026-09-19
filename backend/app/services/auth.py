"""Offline JWT authentication and password hashing helpers."""

import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from typing import Any


ALGORITHM = "HS256"
PBKDF2_ALGORITHM = "sha256"
PBKDF2_ITERATIONS = 310_000
TOKEN_TTL_SECONDS = 60 * 60 * 8


def _encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac(PBKDF2_ALGORITHM, password.encode("utf-8"), salt, PBKDF2_ITERATIONS)
    return f"pbkdf2_{PBKDF2_ALGORITHM}${PBKDF2_ITERATIONS}${_encode(salt)}${_encode(digest)}"


def verify_password(password: str, encoded: str) -> bool:
    try:
        scheme, iterations, salt, expected = encoded.split("$", 3)
        if scheme != f"pbkdf2_{PBKDF2_ALGORITHM}":
            return False
        actual = hashlib.pbkdf2_hmac(PBKDF2_ALGORITHM, password.encode("utf-8"), _decode(salt), int(iterations))
        return hmac.compare_digest(actual, _decode(expected))
    except (ValueError, TypeError):
        return False


def _secret() -> bytes:
    return os.environ.get("SECUREDOC_JWT_SECRET", "securedoc-development-secret-change-before-deployment").encode("utf-8")


def create_access_token(user_id: str, email: str) -> str:
    now = int(time.time())
    header = {"alg": ALGORITHM, "typ": "JWT"}
    payload = {"sub": user_id, "email": email, "iat": now, "exp": now + TOKEN_TTL_SECONDS}
    signing_input = f"{_encode(json.dumps(header, separators=(",", ":"), sort_keys=True).encode())}.{_encode(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode())}"
    signature = hmac.new(_secret(), signing_input.encode("ascii"), hashlib.sha256).digest()
    return f"{signing_input}.{_encode(signature)}"


def decode_access_token(token: str) -> dict[str, Any]:
    try:
        encoded_header, encoded_payload, encoded_signature = token.split(".", 2)
        signing_input = f"{encoded_header}.{encoded_payload}"
        expected = hmac.new(_secret(), signing_input.encode("ascii"), hashlib.sha256).digest()
        if not hmac.compare_digest(expected, _decode(encoded_signature)):
            raise ValueError("Invalid token signature")
        header = json.loads(_decode(encoded_header))
        payload = json.loads(_decode(encoded_payload))
        if header.get("alg") != ALGORITHM or header.get("typ") != "JWT":
            raise ValueError("Unsupported token")
        if not payload.get("sub") or int(payload.get("exp", 0)) <= int(time.time()):
            raise ValueError("Expired token")
        return payload
    except (ValueError, TypeError, KeyError, json.JSONDecodeError) as error:
        raise ValueError("Invalid access token") from error
