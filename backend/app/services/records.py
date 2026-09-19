"""Canonical signed decryption record contracts."""

from datetime import datetime
from pydantic import BaseModel, ConfigDict, Field


class DecryptionRecord(BaseModel):
    model_config = ConfigDict(frozen=True)

    event_id: str = Field(min_length=32)
    document_hash: str = Field(min_length=64)
    watermark_id: str = Field(min_length=32)
    recipient_id: str = Field(min_length=1)
    session_id: str = Field(min_length=32)
    timestamp: datetime
    signature_algorithm: str = "ML-DSA-65"
    signature: str = Field(min_length=1)