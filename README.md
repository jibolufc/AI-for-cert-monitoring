# AI-assisted Cryptographic Control Plane

This repository is an incremental reference implementation for an
**evidence-backed cryptographic discovery and post-quantum cryptography (PQC)
migration control plane**. Certificate monitoring is its first discovery sensor,
not its final product boundary. It is deliberately **not** a certificate
authority, key-management service, migration executor, or autonomous remediation
system.

The first four milestones are executable end to end:

```text
certificate event
  -> schema/domain validation
  -> DNS-name enrichment
  -> CERT-001 unknown-domain detection
  -> deterministic risk explanation
  -> JSONL SIEM alert
  -> SOC playbook

decoded CT fixture pages
  -> full JSON Schema validation
  -> provenance envelope + SHA-256 evidence digest
  -> SQLite evidence/idempotency/checkpoint state
  -> canonical event pipeline

canonical certificate event v1.3
  -> cryptographic algorithm/function evidence
  -> inventory record with explicit coverage limits
  -> deterministic PQC exposure assessment
  -> missing-context and verification requirements
  -> atomic SQLite evidence + inventory persistence

generated RSA/ECDSA certificate or loopback TLS peer
  -> real X.509 parsing
  -> evidence-maturity enforcement
  -> certificate + transport observations kept separate
  -> inventory and PQC assessment bundle
```

## Trust boundary

- Detection and risk scoring are deterministic and reviewable.
- The current "AI" explanation adapter is a deterministic fallback. A future
  model may rephrase evidence, but must not decide whether an alert exists,
  change its severity, or invoke CA, HSM, KMS, trust-store, revocation, or
  production deployment operations.
- Inputs are treated as untrusted telemetry. The CT adapter consumes bounded,
  decoded local fixtures only. No live collector, credential, network call,
  issuance action, or remediation action exists in this repository.
- JSONL is a development sink, not a production SIEM transport.
- A source digest detects changed content; it does not authenticate a collector
  or prove that a domain belongs to the organization.
- `unknown` evidence never becomes quantum-resistant by default. ML-KEM,
  ML-DSA, SLH-DSA, or hybrid labels remain candidates requiring protocol,
  implementation, trust-chain, peer, and fallback verification.
- Certificate evidence does not prove which key-establishment mechanism was
  negotiated and does not represent complete enterprise cryptographic coverage.
- The Milestone 4 TLS probe accepts loopback IP literals only. It is a controlled
  lab component, not an Internet, enterprise-network, or vulnerability scanner.

## Quick start

Requires Python 3.11 or newer. Runtime schema validation uses the pinned
`jsonschema` 4.26.0 package and its non-GPL format-validation extra.

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e .
.venv/bin/python -m unittest discover -s tests -v

.venv/bin/python -m crypto_control_plane.cli \
  --event examples/events/unknown-domain-issued.json \
  --policy examples/policy.json \
  --output build/alerts.jsonl

.venv/bin/python -m crypto_control_plane.ct_cli \
  --fixture-dir examples/ct/pages \
  --policy examples/policy.json \
  --state build/ct-state.sqlite \
  --output build/ct-alerts.jsonl

.venv/bin/python -m crypto_control_plane.inventory_cli \
  --event examples/events/known-domain-issued.json \
  --output build/pqc-inventory-assessment.json

# Parse a generated or explicitly sanitised certificate file.
.venv/bin/python -m crypto_control_plane.discovery_lab_cli \
  --certificate /path/to/test-certificate.pem \
  --evidence-level generated \
  --output build/x509-discovery-bundle.json
```

The example produces a `CERT-001` alert because `lookalike-example.net` is not
covered by the configured organization DNS namespace. Use
`examples/events/known-domain-issued.json` to exercise the no-alert path.

## Repository map

- `docs/architecture/`: Council reviews and architecture decision records
- `docs/threat-model/`: security boundaries, threats, and mitigations
- `schemas/`: versioned JSON Schema Draft 2020-12 contracts
- `rules/`: machine-readable detection metadata
- `src/crypto_control_plane/`: validated pipeline implementation
- `examples/ct/pages/`: provider-neutral decoded CT pages for offline testing
- `docs/soc-playbooks/`: analyst response procedures
- `tests/`: unit and integration-style vertical-slice tests
- `examples/`: safe local fixtures and policy

## Evidence maturity

Every event, inventory record, and assessment carries one evidence level:

| Level | Meaning |
|---|---|
| `simulated` | Hand-authored scenario; logic demonstration only |
| `generated` | Locally generated cryptographic artifact |
| `public-observation` | Publicly observable evidence with limited ownership context |
| `sanitised-capture` | Explicitly sanitised sample from a controlled environment |
| `authenticated-production` | Authenticated, authorised production collector evidence |
| `independently-verified` | Evidence confirmed through an independent source or control |

Known local collectors have an allowlist of evidence levels. Fixtures cannot be
relabeled as production. The high-assurance levels are reserved and rejected at
runtime until an authenticated collector trust registry exists. The current
repository produces only `simulated` and `generated` evidence.

## Milestone 4: controlled discovery lab

All milestones remain a local reference implementation. Milestone 4 adds:

1. A generated RSA/ECDSA X.509 estate with valid, expired, future-validity,
   CA, end-entity, and no-SAN scenarios.
2. Real PEM/DER parsing for fingerprints, serials, identities, validity,
   public-key algorithms, signature algorithms, key usages, and EKUs.
3. An evidence-maturity contract propagated through events, inventory records,
   assessments, alerts, and durable state.
4. A bounded loopback-only TLS probe that records TLS version and cipher suite
   but leaves negotiated key establishment `null` when it is not evidenced.
5. Golden scenario expectations and adversarial tests for malformed artifacts,
   unsupported claims, non-loopback targets, and fixture evidence escalation.
6. A file-based lab CLI for generated or sanitised certificates.
7. PyCA `cryptography` pinned at 50.0.2 for Python 3.11 through 3.13.

The CT fixture contract is intentionally provider-neutral and is **not** an RFC
6962 or RFC 9162 wire response. A live adapter must separately implement and
test source authentication, TLS, timeouts, bounded downloads, pagination,
backoff, log-list trust, parsing, and proof verification as applicable.

Recommended next gates are:

1. Build a fictional enterprise catalogue with services, owners, data lifetime,
   suppliers, dependencies, current state, and target state.
2. Add migration waves, blockers, exceptions, approval gates, and verification
   criteria against the generated discovery corpus.
3. Add coverage accounting that distinguishes tested, observed, unknown, and
   out-of-scope assets.
4. Design an offline customer evidence bundle and sanitisation workflow.
5. Select an authorised read-only pilot source only when access becomes
   available; do not represent lab results as production coverage.

Do not add orchestration privileges until policy, approval, separation of
duties, audit, rollback, and environment-specific authorization are designed
and tested.
