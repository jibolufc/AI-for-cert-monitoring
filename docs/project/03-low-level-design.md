# Low-Level Design

## 1. Scope

This LLD documents the implemented version 0.4.0 reference slice and marks
future interfaces as proposed. It should be updated whenever a schema version,
security invariant, persistence rule, or public command changes.

## 2. Package structure

| Module | Implemented responsibility |
|---|---|
| `models.py` | Strict domain parsing for certificate events and monitoring policy; evidence-claim enforcement |
| `schema_validation.py` | Cached JSON Schema Draft 2020-12 validation with format checking |
| `validation.py` | Exact-key, string, UUID, timestamp, and list guards |
| `normalization.py` | DNS/IDNA normalisation and policy matching |
| `pipeline.py` | CERT-001 enrichment, deterministic alert decision, severity, score, and explanation |
| `ct_collector.py` | Bounded decoded-fixture pages, provenance, replay, checkpoints, inventory creation |
| `state.py` | SQLite schema and atomic outcome/inventory persistence |
| `inventory.py` | Inventory projection and deterministic PQC exposure assessment |
| `discovery_lab.py` | Synthetic X.509 generation, PEM/DER parsing, and loopback TLS observation |
| `sinks.py` | JSONL development alert sink |
| `*_cli.py` | File-oriented command entry points |

## 3. Contract catalogue

| Contract | Version | Producer/consumer |
|---|---:|---|
| Canonical certificate event | 1.3 | Collectors and parsers / pipeline and inventory |
| CT observation page | 1.1 | Fixture source / CT collector |
| Monitoring policy | 1.1 | Policy owner / monitoring pipeline |
| Detection alert | 1.2 | Pipeline / JSONL or future SIEM adapter |
| Cryptographic inventory record | 1.1 | Inventory service / state and future graph |
| PQC assessment | 1.1 | Inventory service / future workflow and reporting |

Contracts reject unexpected fields. A producer must make an explicit version
upgrade; the implementation does not silently reinterpret older events.

## 4. Certificate event processing

### 4.1 Validation sequence

```text
JSON payload
  -> full JSON Schema validation
  -> exact domain keys and enum checks
  -> timestamp and certificate validity ordering
  -> algorithm family and parameter checks
  -> context validation
  -> provenance and evidence-level policy
  -> optional transport validation
  -> immutable CertificateEvent
```

Material constraints include:

- SHA-256 fingerprints and payload digests are 64 hexadecimal characters.
- Timestamps must include timezone information.
- `not_after` must be later than `not_before`.
- X.509 subject may be empty; SAN may carry identity under RFC 5280 semantics.
- KEM families are not valid certificate-signature families.
- Transport key establishment may be `null`; no value is inferred from a
  certificate or cipher-suite label.

### 4.2 Evidence-claim policy

| Collector | Allowed evidence level |
|---|---|
| `fixture-generator` | `simulated` |
| `ct-decoded-fixture` | `simulated` |
| `x509-file-parser` | `generated`, `sanitised-capture` |
| `tls-loopback-lab` | `generated` |

`authenticated-production` and `independently-verified` exist in portable
schemas but are rejected at runtime until a trusted collector registry exists.
An unknown collector cannot self-assert either level.

## 5. Monitoring rule design

### CERT-001: unknown DNS namespace

Inputs:

- certificate subject and SAN DNS names;
- environment;
- monitoring policy exact names and allowed suffixes.

Processing:

1. Lowercase and remove a final DNS dot.
2. Convert Unicode names using IDNA.
3. Permit a wildcard only as the complete leftmost label.
4. Compare suffixes only at DNS label boundaries.
5. Emit no alert when every name is covered.
6. Otherwise assign `high` in production and `medium` elsewhere.
7. Calculate score as a deterministic base plus a bounded increment for
   additional unmatched names.
8. Generate a UUIDv5 alert identifier from event, rule, policy ID, and policy
   version.

The result identifies a policy mismatch, not malicious issuance. The SOC
playbook requires evidence and ownership verification.

## 6. CT fixture collection

### 6.1 Bounds

The fixture adapter applies file/page and entry-size limits before downstream
processing. A future live adapter must separately define authenticated
transport, log trust, pagination, proof verification, timeouts, download limits,
and backoff.

### 6.2 Replay algorithm

For each source record:

1. Canonicalise raw JSON bytes.
2. Calculate SHA-256.
3. Query `(collector_id, source_record_id)`.
4. If absent, process and store.
5. If the stored digest matches, classify as duplicate and emit no second
   alert.
6. If it differs, raise a provenance conflict and stop.
7. Advance the page checkpoint only after every page entry has an outcome.

Rejected domain events are preserved as rejected evidence. Malformed pages fail
before state mutation.

## 7. Persistence model

The SQLite reference store maintains:

- collector checkpoint by collector ID;
- observation identity and raw/canonical payload;
- payload digest and processing status;
- canonical event or validation error;
- alert, inventory record, and assessment where produced;
- processing timestamp.

Observation outcome, inventory record, and assessment are committed in one
transaction. JSONL delivery is not atomic with SQLite; production requires a
transactional outbox.

## 8. Inventory projection

For one certificate event, `PqcInventoryService` creates a stable UUIDv5 record
for the X.509 public-key use. It preserves:

- observation identity and time;
- asset/service/business context without inventing missing values;
- function, protocol, implementation placeholders, and algorithm;
- certificate identity, validity, usages, and signature algorithm;
- optional transport observation;
- evidence confidence, evidence level, source evidence, and event provenance;
- a `certificate-only` scope and explicit limitations.

The current projection does not merge multiple observations into a golden asset
record. That requires correlation policy and conflict lineage.

## 9. PQC assessment algorithm

Inputs are the public-key family, certificate-signature family, inventory
context, and evidence. The algorithm is deterministic:

| Condition | Exposure result |
|---|---|
| RSA, elliptic-curve, or finite-field DH is observed | `quantum-vulnerable` |
| Any relevant family is unknown/other and no known vulnerable family exists | `unknown` |
| Hybrid is observed without deployment proof | `hybrid-unverified` |
| Only recognised PQC families are observed | `candidate-quantum-resistant` |

Known vulnerability dominates unknown evidence. Recognised PQC names do not
prove chain, protocol, implementation, peer, or fallback readiness. Missing
business context is returned and blocks final priority.

## 10. X.509 discovery laboratory

### 10.1 Synthetic factory

The factory can generate:

- RSA 2048, 3072, and 4096-bit certificates;
- ECDSA P-256 and P-384 certificates;
- valid, expired, and not-yet-valid periods;
- CA and end-entity profiles;
- SAN and no-SAN cases.

Keys are synthetic test material. They must never be imported into a production
store.

### 10.2 File parser

The parser:

1. Rejects files larger than one megabyte before parsing.
2. Accepts PEM or DER.
3. Uses PyCA `cryptography` to derive certificate properties.
4. Maps public-key and signature OIDs into the canonical algorithm model.
5. Extracts key usage, EKU, SAN, validity, issuer, subject, serial, and SHA-256
   fingerprint.
6. Does not place an absolute local file path into source evidence.
7. Validates the resulting canonical event before returning it.

### 10.3 Loopback TLS probe

The probe:

- accepts an IP literal, not a host name;
- requires the IP to be loopback;
- limits timeout to ten seconds;
- performs a local TLS client handshake;
- records TLS version and cipher suite;
- explicitly records that the peer was not identity-verified;
- leaves negotiated key establishment `null` because the selected Python API
  does not expose sufficient direct evidence.

## 11. Command interfaces

| Command | Required inputs | Output |
|---|---|---|
| `crypto-control-plane` | event, policy, output | Zero or one JSONL alert |
| `crypto-control-plane-ct-fixture` | fixture directory, policy, state, output | Collection counts, SQLite evidence, alerts |
| `crypto-control-plane-inventory` | event, output | Inventory and assessment JSON bundle |
| `crypto-control-plane-x509-lab` | certificate, evidence level, output | Parsed event, inventory, assessment bundle |

Commands return non-zero on invalid input or an unsupported evidence claim.
They are local development interfaces, not stable production APIs.

## 12. Proposed Milestone 5 data types

The next implementation should introduce separately versioned contracts:

### Enterprise catalogue record

- `asset_id`, `service_id`, `owner_id`, `environment`
- business criticality, data classification, protection lifetime
- authoritative source, source version, effective time
- supplier/product/version and lifecycle dates
- dependency references and evidence status

### Migration work item

- stable work ID and linked inventory/dependency IDs
- current and target cryptographic state by function/protocol
- wave, owner, approver, target date, readiness status
- blockers, prerequisites, rollback criteria, verification plan
- exception reference and decision history

### Decision record

- decision ID, type, actor identity, role, time
- object and version decided upon
- rationale, evidence references, conditions, and expiry
- cryptographic audit receipt where required

### Verification record

- approved target and change reference
- pre-change and post-change observations
- interoperability and negative-test results
- residual findings and regression checks
- verifier identity and independence level

## 13. Proposed migration state machine

```text
discovered
  -> context-required
  -> assessed
  -> planned
  -> approval-required
  -> approved
  -> implementation-external
  -> verification-required
  -> verified

Any active state -> blocked
Any approval state -> excepted (time bounded)
Verified -> regressed (new contradictory evidence)
```

Transitions must be policy-checked, identity-bound, append-audited, and reject
stale object versions.

## 14. Error-handling rules

- Contract errors: reject without partial downstream output.
- Replay conflicts: fail closed and preserve prior accepted evidence.
- Individual domain failures in a valid fixture page: store rejected outcome.
- Page envelope failure: no page state changes.
- Sink failure: report failure; production design must retry from an outbox.
- Unsupported evidence level: reject rather than downgrade silently.
- Missing business context: preserve exposure but withhold final priority.

## 15. Observability requirements for production

Metrics should include intake rate, schema failures, replay duplicates,
conflicts, checkpoint lag, parser latency, sink backlog, assessment counts,
unknown-field rates, evidence age, coverage gaps, workflow ageing, expired
exceptions, and verification regressions. Logs must use correlation IDs and
avoid leaking full certificate identities or infrastructure metadata by
default.

