"""Interfaces for approved NIST post-quantum cryptography implementations."""

from typing import Protocol


class PqcSigner(Protocol):
    algorithm: str

    def sign(self, payload: bytes) -> bytes:
        ...

    def verify(self, payload: bytes, signature: bytes, public_key: bytes) -> bool:
        ...


class PqcKeyExchange(Protocol):
    algorithm: str

    def encapsulate(self, recipient_public_key: bytes) -> tuple[bytes, bytes]:
        ...

    def decapsulate(self, ciphertext: bytes, private_key: bytes) -> bytes:
        ...
