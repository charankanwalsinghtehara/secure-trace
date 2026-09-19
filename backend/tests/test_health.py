import base64

from fastapi.testclient import TestClient

import app.main as main
from app.main import app
from app.services.ledger import LocalLedger
from app.services.storage import JsonStore


client = TestClient(app)


def test_health_is_offline_ready() -> None:
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok", "mode": "offline"}


def test_system_modules_expose_security_boundaries() -> None:
    response = client.get("/api/v1/system/modules")

    assert response.status_code == 200
    names = {module["name"] for module in response.json()}
    assert {"pqc", "watermark", "ledger", "postgresql"} <= names


def test_decrypt_watermark_and_verify_workflow(tmp_path) -> None:
    main.store = JsonStore(str(tmp_path / "metadata.json"))
    main.ledger = LocalLedger(str(tmp_path / "ledger.jsonl"))
    client = TestClient(app)

    auth = client.post("/api/v1/auth/register", json={"email": "ada@example.test", "password": "correct horse battery"}).json()
    headers = {"Authorization": f"Bearer {auth['access_token']}"}
    recipient_response = client.post("/api/v1/recipients", json={"name": "Ada Recipient"}, headers=headers)
    recipient = recipient_response.json()
    document = client.post(
        "/api/v1/documents",
        json={"name": "brief.txt", "content_base64": base64.b64encode(b"classified brief").decode("ascii")},
        headers=headers,
    ).json()
    stored_document = main.store.read()["documents"][document["document_id"]]
    assert "content_encrypted" in stored_document
    assert "content_base64" not in stored_document
    decrypted = client.post(
        f"/api/v1/documents/{document['document_id']}/decrypt",
        json={"recipient_id": recipient["recipient_id"], "private_key": recipient["private_key"]},
        headers=headers,
    )

    assert decrypted.status_code == 200
    evidence = client.post(
        "/api/v1/forensics/verify",
        json={"content_base64": decrypted.json()["content_base64"]},
        headers=headers,
    )

    assert evidence.status_code == 200
    assert evidence.json()["match"] is True
    assert evidence.json()["recipient"]["name"] == "Ada Recipient"
    assert evidence.json()["ledger_chain_valid"] is True

    tampered = bytearray(base64.b64decode(decrypted.json()["content_base64"]))
    tampered[0] ^= 1
    tampered_evidence = client.post(
        "/api/v1/forensics/verify",
        json={"content_base64": base64.b64encode(tampered).decode("ascii")},
        headers=headers,
    )

    assert tampered_evidence.status_code == 200
    assert tampered_evidence.json()["match"] is False
    assert tampered_evidence.json()["tamper_detected"] is True

    revoked = client.post(f"/api/v1/recipients/{recipient['recipient_id']}/revoke", headers=headers)
    assert revoked.status_code == 200
    blocked = client.post(
        f"/api/v1/documents/{document['document_id']}/decrypt",
        json={"recipient_id": recipient["recipient_id"], "private_key": recipient["private_key"]},
        headers=headers,
    )
    assert blocked.status_code == 403