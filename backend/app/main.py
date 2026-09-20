import base64
import hashlib
import json
import os
import secrets
from datetime import datetime, timezone

from fastapi import Depends, FastAPI, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from app.services import at_rest, auth, demo_crypto, llm, watermark
from app.services.ledger import LocalLedger
from app.services.storage import JsonStore

app = FastAPI(
    title="SecureTrace Private Document Network API",
    version="0.1.0",
    description="Offline-first API for cryptographically verifiable document distribution.",
)
allowed_origins = [
    origin.strip()
    for origin in os.environ.get("CORS_ALLOWED_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173").split(",")
    if origin.strip()
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_origin_regex=r"http://(localhost|127\.0\.0\.1|\[::1\])(:\d+)?",
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "Authorization"],
)
store = JsonStore()
ledger = LocalLedger()
bearer = HTTPBearer(auto_error=False)


class ModuleStatus(BaseModel):
    name: str
    status: str
    note: str


class RecipientCreate(BaseModel):
    name: str = Field(min_length=1, max_length=160)


class AuthRequest(BaseModel):
    email: str = Field(min_length=5, max_length=240)
    password: str = Field(min_length=8, max_length=160)


class UserView(BaseModel):
    user_id: str
    email: str
    role: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserView


class DocumentCreate(BaseModel):
    name: str = Field(min_length=1, max_length=240)
    content_base64: str = Field(min_length=1)


class DecryptRequest(BaseModel):
    recipient_id: str
    private_key: str = Field(min_length=64)
    expires_at: datetime | None = None


class WatermarkLookup(BaseModel):
    content_base64: str = Field(min_length=1)


class AnalysisRequest(BaseModel):
    instruction: str | None = Field(default=None, max_length=1000)


def document_bytes(document: dict[str, object]) -> bytes:
    if document.get("content_encrypted"):
        return at_rest.decrypt_bytes(str(document["content_encrypted"]))
    return base64.b64decode(str(document["content_base64"]))


def current_user(credentials: HTTPAuthorizationCredentials | None = Depends(bearer)) -> dict[str, str]:
    if not credentials:
        raise HTTPException(status_code=401, detail="Sign in is required")
    try:
        claims = auth.decode_access_token(credentials.credentials)
    except ValueError as error:
        raise HTTPException(status_code=401, detail=str(error)) from error
    user = store.read()["users"].get(claims["sub"])
    if not user or user.get("email") != claims.get("email"):
        raise HTTPException(status_code=401, detail="User account is not available")
    return {"user_id": user["user_id"], "email": user["email"], "role": user.get("role", "operator")}


def admin_user(user: dict[str, str] = Depends(current_user)) -> dict[str, str]:
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Administrator access is required")
    return user


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "mode": "offline"}


@app.get("/api/v1/system/modules", response_model=list[ModuleStatus])
def modules() -> list[ModuleStatus]:
    return [
        ModuleStatus(name="pqc", status="demo-adapter", note=f"{demo_crypto.ALGORITHM}; install approved ML-DSA/ML-KEM provider for production"),
        ModuleStatus(name="watermark", status="active", note="Binary forensic frame with extraction and integrity checks"),
        ModuleStatus(name="ledger", status="active", note="Offline append-only hash-chained ledger"),
        ModuleStatus(name="postgresql", status="adapter-ready", note="JSON store active for demo; PostgreSQL adapter is the deployment target"),
        ModuleStatus(name="llm", status="local-adapter", note=f"{llm.LLMConfig().model} via {llm.LLMConfig().base_url}"),
    ]


@app.post("/api/v1/auth/register", response_model=TokenResponse)
def register(request: AuthRequest) -> TokenResponse:
    email = request.email.strip().lower()
    data = store.read()
    if any(user.get("email") == email for user in data["users"].values()):
        raise HTTPException(status_code=409, detail="An account with this email already exists")
    user_id = secrets.token_hex(16)
    role = "admin" if not data["users"] else "operator"

    def add(value: dict) -> None:
        value["users"][user_id] = {
            "user_id": user_id,
            "email": email,
            "password_hash": auth.hash_password(request.password),
            "role": role,
        }

    store.update(add)
    return TokenResponse(access_token=auth.create_access_token(user_id, email), user=UserView(user_id=user_id, email=email, role=role))


@app.post("/api/v1/auth/login", response_model=TokenResponse)
def login(request: AuthRequest) -> TokenResponse:
    email = request.email.strip().lower()
    user = next((item for item in store.read()["users"].values() if item.get("email") == email), None)
    if not user or not auth.verify_password(request.password, user.get("password_hash", "")):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    role = user.get("role", "operator")
    return TokenResponse(access_token=auth.create_access_token(user["user_id"], email), user=UserView(user_id=user["user_id"], email=email, role=role))


@app.get("/api/v1/auth/me", response_model=UserView)
def me(user: dict[str, str] = Depends(current_user)) -> UserView:
    return UserView(**user)


@app.get("/api/v1/documents")
def list_documents(user: dict[str, str] = Depends(current_user)) -> list[dict[str, str]]:
    return [
        {key: document[key] for key in ("document_id", "name", "document_hash")}
        for document in store.read()["documents"].values()
        if document.get("user_id") == user["user_id"]
    ]


@app.get("/api/v1/documents/{document_id}/download")
def download_document(document_id: str, user: dict[str, str] = Depends(current_user)) -> dict[str, str]:
    document = store.read()["documents"].get(document_id)
    if not document or document.get("user_id") != user["user_id"]:
        raise HTTPException(status_code=404, detail="Document not found")
    return {"name": document["name"], "content_base64": base64.b64encode(document_bytes(document)).decode("ascii")}


@app.post("/api/v1/documents/{document_id}/analyze")
def analyze_document(document_id: str, request: AnalysisRequest = AnalysisRequest(), user: dict[str, str] = Depends(current_user)) -> dict[str, object]:
    document = store.read()["documents"].get(document_id)
    if not document or document.get("user_id") != user["user_id"]:
        raise HTTPException(status_code=404, detail="Document not found")
    try:
        text = document_bytes(document).decode("utf-8")[:100_000]
    except UnicodeDecodeError as error:
        raise HTTPException(status_code=415, detail="The configured local analyst currently accepts UTF-8 text documents") from error
    prompt_text = f"{request.instruction}\n\n{text}" if request.instruction else text
    try:
        result = llm.analyze(prompt_text, document["name"])
    except llm.LocalLLMError as error:
        raise HTTPException(status_code=503, detail=str(error)) from error
    analysis_id = secrets.token_hex(16)
    analysis_hash = hashlib.sha3_256(result.encode("utf-8")).hexdigest()
    event = {"event_type": "llm_analysis", "analysis_id": analysis_id, "document_id": document_id, "document_hash": document["document_hash"], "analysis_hash": analysis_hash, "model": llm.LLMConfig().model, "user_id": user["user_id"], "created_at": datetime.now(timezone.utc).isoformat()}
    entry = ledger.append(event)

    def save(data: dict) -> None:
        data["analyses"].append({**event, "transaction_id": entry["transaction_id"], "result": result})

    store.update(save)
    return {"analysis_id": analysis_id, "document_id": document_id, "document_hash": document["document_hash"], "analysis_hash": analysis_hash, "model": event["model"], "transaction_id": entry["transaction_id"], "result": result}


@app.get("/api/v1/llm/status")
def llm_status(user: dict[str, str] = Depends(current_user)) -> dict[str, object]:
    return llm.status()


@app.get("/api/v1/recipients")
def list_recipients(user: dict[str, str] = Depends(current_user)) -> list[dict[str, object]]:
    return [
        {
            "recipient_id": recipient.get("recipient_id"),
            "name": recipient.get("name"),
            "algorithm": recipient.get("algorithm"),
            "active": recipient.get("active", True),
        }
        for recipient in store.read()["recipients"].values()
        if recipient.get("user_id") == user["user_id"]
    ]


@app.post("/api/v1/recipients")
def create_recipient(request: RecipientCreate, user: dict[str, str] = Depends(current_user)) -> dict[str, str]:
    recipient_id = secrets.token_hex(16)
    private_key = demo_crypto.generate_private_key()
    public_key = demo_crypto.public_key_from_private(private_key)

    def add(data: dict) -> None:
        data["recipients"][recipient_id] = {
            "recipient_id": recipient_id,
            "user_id": user["user_id"],
            "name": request.name,
            "public_key": public_key,
            "algorithm": demo_crypto.ALGORITHM,
            "active": True,
        }

    store.update(add)
    return {
        "recipient_id": recipient_id,
        "name": request.name,
        "public_key": public_key,
        "private_key": private_key,
        "warning": "Demo signer only. Replace with recipient-held ML-DSA private key before production.",
    }


@app.post("/api/v1/documents")
def create_document(request: DocumentCreate, user: dict[str, str] = Depends(current_user)) -> dict[str, str]:
    try:
        content = base64.b64decode(request.content_base64, validate=True)
    except ValueError as error:
        raise HTTPException(status_code=400, detail="content_base64 is invalid") from error
    document_id = secrets.token_hex(16)
    digest = watermark.document_hash(content)

    def add(data: dict) -> None:
        data["documents"][document_id] = {
            "document_id": document_id,
            "user_id": user["user_id"],
            "name": request.name,
            "document_hash": digest,
            "content_encrypted": at_rest.encrypt_bytes(content),
        }

    store.update(add)
    return {"document_id": document_id, "name": request.name, "document_hash": digest}


@app.post("/api/v1/documents/{document_id}/decrypt")
def decrypt_document(document_id: str, request: DecryptRequest, user: dict[str, str] = Depends(current_user)) -> dict[str, object]:
    data = store.read()
    document = data["documents"].get(document_id)
    recipient = data["recipients"].get(request.recipient_id)
    if not document or not recipient or document.get("user_id") != user["user_id"] or recipient.get("user_id") != user["user_id"]:
        raise HTTPException(status_code=404, detail="Document or recipient not found")
    if not recipient.get("active", True):
        raise HTTPException(status_code=403, detail="Recipient access has been revoked")
    if request.expires_at and request.expires_at <= datetime.now(timezone.utc):
        raise HTTPException(status_code=400, detail="Access expiry must be in the future")
    if demo_crypto.public_key_from_private(request.private_key) != recipient["public_key"]:
        raise HTTPException(status_code=403, detail="Recipient signing key does not match identity")

    raw = document_bytes(document)
    watermark_id = watermark.make_watermark_id()
    event_id = secrets.token_hex(16)
    session_id = secrets.token_hex(16)
    timestamp = datetime.now(timezone.utc)
    fingerprinted = watermark.embed(raw, watermark_id, document["document_hash"])
    unsigned = {
        "event_id": event_id,
        "document_hash": document["document_hash"],
        "watermark_id": watermark_id,
        "recipient_id": request.recipient_id,
        "session_id": session_id,
        "timestamp": timestamp.isoformat(),
        "signature_algorithm": demo_crypto.ALGORITHM,
        "delivered_hash": watermark.document_hash(fingerprinted),
        "user_id": user["user_id"],
        "expires_at": request.expires_at.isoformat() if request.expires_at else None,
    }
    signature = demo_crypto.sign(json.dumps(unsigned, separators=(",", ":"), sort_keys=True).encode("utf-8"), request.private_key)
    record = {**unsigned, "signature": signature, "recipient_name": recipient["name"]}
    entry = ledger.append(record)
    message_id = secrets.token_hex(16)

    def add_message(data: dict) -> None:
        data["messages"].append({
            "message_id": message_id,
            "user_id": user["user_id"],
            "recipient_id": request.recipient_id,
            "document_id": document_id,
            "document_name": document["name"],
            "transaction_id": entry["transaction_id"],
            "sent_at": timestamp.isoformat(),
            "expires_at": request.expires_at.isoformat() if request.expires_at else None,
        })

    store.update(add_message)
    return {
        "event": record,
        "ledger_transaction_id": entry["transaction_id"],
        "content_base64": base64.b64encode(fingerprinted).decode("ascii"),
        "visual_identity": "Original bytes preserved; watermark is appended as an invisible forensic frame.",
    }


@app.post("/api/v1/forensics/verify")
def verify_leak(request: WatermarkLookup, user: dict[str, str] = Depends(current_user)) -> dict[str, object]:
    try:
        content = base64.b64decode(request.content_base64, validate=True)
        extracted = watermark.extract(content)
    except (ValueError, json.JSONDecodeError) as error:
        raise HTTPException(status_code=400, detail=str(error)) from error
    match = ledger.find_by_watermark(extracted["watermark_id"])
    if not match or match["record"].get("user_id") != user["user_id"]:
        raise HTTPException(status_code=404, detail="Watermark is not present in the offline ledger")
    record = match["record"]
    unsigned = {key: record[key] for key in (
        "event_id", "document_hash", "watermark_id", "recipient_id", "session_id", "timestamp", "signature_algorithm", "delivered_hash", "user_id"
    )}
    recipient = store.read()["recipients"].get(record["recipient_id"])
    chain_valid = ledger.verify_chain()
    delivered_hash_match = watermark.document_hash(content) == record.get("delivered_hash")
    document_match = extracted["document_hash"] == record["document_hash"] and delivered_hash_match
    expired = bool(record.get("expires_at") and datetime.fromisoformat(record["expires_at"]) <= datetime.now(timezone.utc))
    revoked = bool(recipient and not recipient.get("active", True))
    return {
        "match": document_match and chain_valid and recipient is not None and not expired,
        "watermark": extracted,
        "recipient": {"recipient_id": record["recipient_id"], "name": record.get("recipient_name")},
        "event": record,
        "ledger_evidence": match["ledger"],
        "ledger_chain_valid": chain_valid,
        "tamper_detected": not delivered_hash_match,
        "delivered_hash_match": delivered_hash_match,
        "access_expired": expired,
        "recipient_revoked": revoked,
        "signature_verification": "requires ML-DSA verifier adapter; demo signature is bound to the registered demo key",
        "canonical_event_hash": hashlib.sha3_256(json.dumps(unsigned, separators=(",", ":"), sort_keys=True).encode("utf-8")).hexdigest(),
    }


@app.get("/api/v1/ledger/entries")
def ledger_entries(user: dict[str, str] = Depends(current_user)) -> dict[str, object]:
    entries = []
    for entry in ledger._records():
        record = json.loads(entry["record"])
        if record.get("user_id") == user["user_id"]:
            entries.append({**entry, "record": record})
    return {"chain_valid": ledger.verify_chain(), "quorum": f"{ledger.quorum} / {len(ledger.validators)}", "entries": entries}


@app.get("/api/v1/ledger/status")
def ledger_status(user: dict[str, str] = Depends(current_user)) -> dict[str, object]:
    return ledger.status()


@app.get("/api/v1/conversations/{recipient_id}")
def conversation(recipient_id: str, user: dict[str, str] = Depends(current_user)) -> list[dict[str, object]]:
    recipient = store.read()["recipients"].get(recipient_id)
    if not recipient or recipient.get("user_id") != user["user_id"]:
        raise HTTPException(status_code=404, detail="Recipient not found")
    return [message for message in store.read()["messages"] if message.get("user_id") == user["user_id"] and message.get("recipient_id") == recipient_id]


@app.post("/api/v1/recipients/{recipient_id}/revoke")
def revoke_recipient(recipient_id: str, user: dict[str, str] = Depends(current_user)) -> dict[str, str]:
    recipient = store.read()["recipients"].get(recipient_id)
    if not recipient or recipient.get("user_id") != user["user_id"]:
        raise HTTPException(status_code=404, detail="Recipient not found")
    revoked_at = datetime.now(timezone.utc).isoformat()

    def revoke(data: dict) -> None:
        data["recipients"][recipient_id]["active"] = False
        data["recipients"][recipient_id]["revoked_at"] = revoked_at

    store.update(revoke)
    ledger.append({"event_type": "recipient_revoked", "recipient_id": recipient_id, "user_id": user["user_id"], "revoked_at": revoked_at})
    return {"recipient_id": recipient_id, "status": "revoked"}


@app.get("/api/v1/ledger/export")
def ledger_export(user: dict[str, str] = Depends(admin_user)) -> dict[str, object]:
    entries = []
    for entry in ledger._records():
        record = json.loads(entry["record"])
        if record.get("user_id") == user["user_id"] or record.get("event_type") == "recipient_revoked":
            entries.append(entry)
    return {"format": "cryptatrace-ledger-v1", "chain": ledger.status(), "entries": entries}


@app.get("/api/v1/admin/status")
def admin_status(user: dict[str, str] = Depends(admin_user)) -> dict[str, object]:
    data = store.read()
    return {
        "operator": user["email"],
        "users": len(data["users"]),
        "documents": len(data["documents"]),
        "recipients": len(data["recipients"]),
        "ledger": ledger.status(),
    }
