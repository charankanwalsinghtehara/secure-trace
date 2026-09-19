"""Format-neutral watermark framing for the first vertical slice."""

import hashlib
import json
import secrets


MAGIC = b"SDOC-WM-v1\x00"


def make_watermark_id() -> str:
    return secrets.token_hex(32)


def document_hash(content: bytes) -> str:
    return hashlib.sha3_256(content).hexdigest()


def embed(content: bytes, watermark_id: str, document_digest: str) -> bytes:
    frame = json.dumps(
        {"watermark_id": watermark_id, "document_hash": document_digest},
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return content + MAGIC + len(frame).to_bytes(4, "big") + frame


def extract(content: bytes) -> dict[str, str]:
    offset = content.rfind(MAGIC)
    if offset < 0:
        raise ValueError("No SecureDoc watermark found")
    start = offset + len(MAGIC)
    size = int.from_bytes(content[start : start + 4], "big")
    frame = json.loads(content[start + 4 : start + 4 + size].decode("utf-8"))
    if not frame.get("watermark_id") or not frame.get("document_hash"):
        raise ValueError("Invalid SecureDoc watermark frame")
    return frame