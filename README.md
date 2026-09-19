# CryptaTrace Private Document Network

Offline-first prototype for classified document sharing, session-bound forensic watermarking, recipient signatures, and permissioned ledger evidence.

## Modules

1. Identity and access control
2. Post-quantum cryptography (ML-KEM / ML-DSA adapters)
3. Document encryption and distribution
4. Decryption sessions
5. Invisible forensic watermarking
6. Recipient-side signing
7. Signed audit records
8. Permissioned offline ledger
9. PostgreSQL metadata/index
10. Watermark extraction and forensic verification
11. React operations console
12. Air-gapped deployment and security operations

## Development

Backend:

```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e .
uvicorn app.main:app --reload
```

Frontend:

```powershell
cd frontend
npm install
npm run dev
```

## Working workflow

The API now supports:

- `POST /api/v1/recipients` to create a local demo identity
- `POST /api/v1/documents` to register document bytes
- `POST /api/v1/documents/{document_id}/decrypt` to create a signed session and fingerprinted copy
- `POST /api/v1/forensics/verify` to extract the watermark and return ledger evidence

The local ledger replicates each entry to three validator logs and requires a two-validator quorum. It is a development DLT adapter, not a substitute for an audited permissioned blockchain deployment.

Authentication is local and offline: `POST /api/v1/auth/register` and `POST /api/v1/auth/login` issue signed JWT access tokens. Protected document, recipient, ledger, and forensic routes require `Authorization: Bearer <token>`.

The Ledger page reads `GET /api/v1/ledger/entries` and displays the replicated hash chain. Forensic verification recomputes the hash of the complete delivered payload, so changing the document bytes is reported as tampering even when the watermark frame remains readable.

Additional controls include AES-GCM encrypted document bytes at rest, browser-held recipient keys, delivery expiry, recipient revocation recorded on the ledger, persistent conversation attachment history, and administrator ledger export. Set `CRYPTATRACE_STORAGE_KEY` to a URL-safe base64-encoded 32-byte key before deployment; the built-in key is development-only.

The demo signer uses HMAC only because this environment has no PQC runtime installed. It is explicitly labeled in the API and must be replaced with an audited NIST ML-DSA-65 implementation before production. ML-KEM integration belongs at the same adapter boundary for document-key distribution.
