# LLM Council review: Milestone 4 controlled discovery lab

Date: 2026-10-11

## Recommendation

Continue without customer data by building a generated cryptographic estate,
real artifact parsers, and loopback-only integration tests. Make evidence
maturity part of the data contract and prohibit synthetic-to-production claim
escalation.

## Independent perspectives

### Evidence analyst

Generated RSA and ECDSA certificates are real cryptographic artifacts and can
validate parsing, schema, evidence handling, and deterministic assessment. They
cannot establish enterprise discovery coverage, vendor compatibility, or
production readiness.

### Sceptic / red team

The primary risk is a polished demonstration being mistaken for production
assurance. Other risks include parser abuse, unrestricted TLS probing, leaked
test keys, and inferring key establishment from a certificate or cipher label.
The design bounds inputs, restricts the TLS probe to loopback, labels evidence,
and keeps unknown protocol evidence null.

### Alternative strategist

Public Certificate Transparency data could add variety, but it still lacks
private infrastructure and business context. Waiting for a customer would slow
development. Generated artifacts plus a future offline import kit are the most
reversible path.

### Practical implementation reviewer

PyCA `cryptography` provides portable parsing and certificate generation across
the supported Python versions. A JSON golden-scenario manifest gives stable
expected families and exposure outcomes even though generated keys and
fingerprints vary on each run.

### Risk and future reviewer

Evidence levels should survive future production integrations rather than be a
temporary test flag. Authenticated collectors, signed provenance, coverage
metrics, sanitisation, and tenancy remain later gates.

## Cross-examination

Agreement:

- Continue engineering without inventing customer evidence.
- Derive algorithm metadata from artifacts wherever possible.
- Keep certificate, TLS transport, and key-establishment evidence distinct.
- Make lab-only scope visible and enforceable.

Disagreement:

The main disagreement was whether to allow a general TLS target. The Chair
selected loopback-only because unrestricted probing adds security and
authorisation risk without improving this milestone's acceptance criteria.

Missing evidence:

- No target customer estate, authoritative CMDB, private PKI, KMS, HSM, or
  supplier inventory is available.
- Production scale and retention requirements remain unknown.
- PQC-capable certificate and TLS implementations are not part of the lab.

## Council challenge

Synthetic breadth can never prove real discovery completeness. The milestone is
acceptable only if reports retain the evidence level and certificate-only scope,
and if production readiness remains an explicit future pilot gate.

## Chair synthesis

Accept Milestone 4 as a controlled validation environment. Proceed next to a
fictional enterprise migration-management layer and offline customer evidence
bundle, while preserving an authorised pilot as the production proof gate.

Confidence: **HIGH** for local parser, evidence, and assessment validation;
**LOW** for production coverage because no production evidence exists.
