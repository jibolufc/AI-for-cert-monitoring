# ADR-004: Controlled discovery lab without customer data

- Status: accepted
- Date: 2026-10-11

## Context

The project has no authorised customer or production cryptographic dataset.
Milestone 3 established inventory and PQC assessment contracts, but decoded
fixtures do not validate real certificate parsing or TLS observation. Pausing
would delay reusable engineering; treating synthetic evidence as production
would create false assurance.

## Decision

Build a controlled discovery lab with three evidence boundaries:

1. Generate real RSA and ECDSA X.509 artifacts for valid, expired,
   future-validity, CA, end-entity, SAN, and no-SAN scenarios.
2. Parse PEM and DER artifacts with a pinned PyCA `cryptography` dependency,
   deriving rather than accepting certificate algorithm metadata.
3. Perform a real TLS handshake only against loopback IP literals. Record the
   TLS version and cipher suite while leaving negotiated key establishment null
   unless a future protocol-specific collector can evidence it directly.

Add an evidence-maturity field to every event, inventory record, assessment,
and alert. Known collectors have allowed levels. Fixtures are simulation-only;
the file parser accepts generated or sanitised captures; the loopback probe is
generated evidence only. Authenticated-production and independently-verified
claims are represented in the portable schema but rejected at runtime until an
authenticated collector trust registry exists.

Because these fields change required contracts, Milestone 4 explicitly advances
the certificate event to v1.3, the inventory and assessment contracts to v1.1,
and the detection alert to v1.2.

## Consequences

Positive:

- Real cryptographic artifacts now exercise parsing and classification.
- The project can progress without confidential production data.
- Evidence quality and claim boundaries are machine-readable.
- A real local handshake tests certificate-versus-transport separation.
- The probe cannot be repurposed to scan external addresses.

Negative and residual:

- Generated certificates do not reproduce vendor, scale, topology, private-PKI,
  HSM, KMS, application-library, or operational edge cases.
- Self-signed lab certificates do not establish trust-chain behavior.
- The standard Python TLS interface used here does not directly expose the
  negotiated key-establishment group, so that field remains unknown.
- Private keys are unencrypted because the local TLS server needs them; they
  are synthetic test material and must never be reused or imported into a
  production key store.
- Production coverage and interoperability remain unverified.

## Rejected alternatives

- **Wait for customer data:** rejected because parsers, evidence contracts,
  safety checks, and migration workflows are independently testable.
- **Scan public or enterprise targets:** rejected because the milestone has no
  target authorisation and must not add an unrestricted network scanner.
- **Infer KEM from TLS cipher or certificate:** rejected because that would
  conflate distinct protocol evidence.
- **Label generated artifacts as verified production:** rejected because it
  would invalidate the evidence-backed product claim.
