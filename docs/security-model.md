# Security Model

## Trust boundaries

- Recipient private signing keys remain outside FastAPI and PostgreSQL.
- The API receives public-key references and signatures, not private key material.
- PostgreSQL stores searchable metadata only; the permissioned DLT stores authoritative audit evidence.
- The development ledger replicates entries to three validators and requires a two-validator quorum; production should replace this with an audited BFT permissioned ledger.
- Ledger validators must be operated by separate offline authorities so one administrator cannot rewrite history.

## Cryptography

- Use NIST-standardized ML-KEM for recipient key establishment.
- Use NIST-standardized ML-DSA for recipient signatures.
- Use domain-separated canonical serialization before signing records.
- Reject records with mismatched document hashes, watermark IDs, timestamps, or signatures.

## Offline operation

The runtime must not call public blockchain networks, cloud KMS services, external identity providers, or telemetry services. Dependency wheels, container images, trust roots, and ledger node artifacts must be staged and integrity-checked before an air-gap transfer.

The initial implementation exposes interfaces for these security-sensitive adapters. Concrete providers must be selected, reviewed, and tested in the target air-gapped environment before production use.