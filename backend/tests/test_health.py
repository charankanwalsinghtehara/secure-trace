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
    recipients = client.get("/api/v1/recipients", headers=headers)
    assert recipients.status_code == 200
    assert recipients.json()[0]["active"] is True
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


def test_local_llm_analysis_is_audited(tmp_path, monkeypatch) -> None:
    main.store = JsonStore(str(tmp_path / "metadata.json"))
    main.ledger = LocalLedger(str(tmp_path / "ledger.jsonl"))
    client = TestClient(app)
    auth = client.post("/api/v1/auth/register", json={"email": "analyst@example.test", "password": "correct horse battery"}).json()
    headers = {"Authorization": f"Bearer {auth['access_token']}"}
    document = client.post(
        "/api/v1/documents",
        json={"name": "brief.txt", "content_base64": base64.b64encode(b"classified analysis text").decode("ascii")},
        headers=headers,
    ).json()
    monkeypatch.setattr(main.llm, "analyze", lambda text, name: '{"classification":"restricted","summary":"Local result"}')

    response = client.post(f"/api/v1/documents/{document['document_id']}/analyze", headers=headers)

    assert response.status_code == 200
    assert response.json()["result"] == '{"classification":"restricted","summary":"Local result"}'
    assert response.json()["transaction_id"]
    assert main.store.read()["analyses"][0]["analysis_hash"] == response.json()["analysis_hash"]


def test_legacy_recipients_without_active_flag_are_filtered_gracefully(tmp_path) -> None:
    main.store = JsonStore(str(tmp_path / "metadata.json"))
    main.ledger = LocalLedger(str(tmp_path / "ledger.jsonl"))
    client = TestClient(app)
    auth = client.post("/api/v1/auth/register", json={"email": "legacy@example.test", "password": "correct horse battery"}).json()
    headers = {"Authorization": f"Bearer {auth['access_token']}"}

    main.store.update(
        lambda data: data["recipients"].update(
            {
                "legacy-id": {
                    "recipient_id": "legacy-id",
                    "name": "Legacy",
                    "user_id": auth["user"]["user_id"],
                    "algorithm": "DEMO-HMAC-SHA256 (REPLACE WITH ML-DSA-65)",
                    "public_key": "abc",
                }
            }
        )
    )

    response = client.get("/api/v1/recipients", headers=headers)

    assert response.status_code == 200
    assert response.json()[0]["active"] is True