# SecureDoc project instructions

- Keep all runtime paths compatible with offline and air-gapped deployment.
- Use NIST-standardized post-quantum algorithms: ML-KEM for key establishment and ML-DSA for signatures.
- Treat PostgreSQL as metadata/index storage; the permissioned DLT is authoritative for audit evidence.
- Never place recipient private keys in the FastAPI service or PostgreSQL.
- Prefer explicit interfaces for cryptography, watermarking, and ledger adapters so implementations can be independently security reviewed.
- Do not introduce public cloud KMS or public blockchain dependencies.
