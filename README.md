# AI-assisted Cryptographic Control Plane

This repository is an incremental reference implementation for an
**evidence-backed cryptographic discovery and post-quantum cryptography (PQC)
migration control plane**. Certificate monitoring is its first discovery sensor,
not its final product boundary. It is deliberately **not** a certificate
authority, key-management service, migration executor, or autonomous remediation
system.

The first three milestones are executable end to end:

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

canonical certificate event v1.2
  -> cryptographic algorithm/function evidence
  -> inventory record with explicit coverage limits
  -> deterministic PQC exposure assessment
  -> missing-context and verification requirements
  -> atomic SQLite evidence + inventory persistence
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

## Milestone 3: PQC inventory foundation

All milestones remain a local reference implementation. Milestone 3 adds:

1. Certificate event contract v1.2 with public-key, signature, key-usage, and
   optional business-context evidence.
2. A separately versioned cryptographic inventory record.
3. Explainable PQC exposure classifications: `quantum-vulnerable`,
   `candidate-quantum-resistant`, `hybrid-unverified`, or `unknown`.
4. Migration priority that remains `needs-context` or `needs-evidence` when the
   required inputs are absent.
5. Explicit certificate-only coverage limitations on every inventory record.
6. Atomic persistence of the source outcome, inventory record, and assessment.
7. Tests for classical, unknown, candidate-PQC, hybrid, replay, and fail-closed
   behavior.

The CT fixture contract is intentionally provider-neutral and is **not** an RFC
6962 or RFC 9162 wire response. A live adapter must separately implement and
test source authentication, TLS, timeouts, bounded downloads, pagination,
backoff, log-list trust, parsing, and proof verification as applicable.

Recommended next gates are:

1. Select one real read-only discovery source: live X.509/TLS parsing, private
   PKI, cloud certificate/KMS inventory, or an enterprise certificate manager.
2. Integrate authoritative asset, service, owner, data-classification, and
   protection-lifetime context.
3. Add dependency edges and evidence-conflict handling across multiple sources.
4. Measure discovery coverage instead of treating unobserved assets as safe.
5. Authenticate collector-to-control-plane provenance rather than relying only
   on a digest.
6. Add a production outbox/transport with delivery, redaction, tenancy,
   retention, dead-lettering, and metrics.
7. Add migration waves, target states, exceptions, approvals, and verification
   only after the evidence and policy authorities are defined.

Do not add orchestration privileges until policy, approval, separation of
duties, audit, rollback, and environment-specific authorization are designed
and tested.
