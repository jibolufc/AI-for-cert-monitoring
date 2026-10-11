# AI-assisted Cryptographic Control Plane

This repository is an incremental reference implementation for certificate
observability, deterministic anomaly detection, and governed AI assistance. It
is deliberately **not** a certificate authority, key-management service, or
autonomous remediation system.

The first two milestones are executable end to end:

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
```

The example produces a `CERT-001` alert because `lookalike-example.net` is not
covered by the configured organization DNS namespace. Use
`examples/events/known-domain-issued.json` to exercise the no-alert path.

## Repository map

- `docs/architecture/`: Council decision record and ADR-001
- `docs/threat-model/`: security boundaries, threats, and mitigations
- `schemas/`: versioned JSON Schema Draft 2020-12 contracts
- `rules/`: machine-readable detection metadata
- `src/crypto_control_plane/`: validated pipeline implementation
- `examples/ct/pages/`: provider-neutral decoded CT pages for offline testing
- `docs/soc-playbooks/`: analyst response procedures
- `tests/`: unit and integration-style vertical-slice tests
- `examples/`: safe local fixtures and policy

## Current scope and next gates

Milestones 1 and 2 remain a local reference implementation. Milestone 2 adds:

1. Full Draft 2020-12 schema and format validation.
2. Versioned policy and event-provenance contracts.
3. Fixture-driven, read-only decoded CT collection.
4. Durable SQLite evidence, outcome, idempotency, and checkpoint state.
5. Replay, restart, malformed-input, source-conflict, and size-limit tests.
6. Least-privilege GitHub CI across Python 3.11, 3.12, and 3.13.

The CT fixture contract is intentionally provider-neutral and is **not** an RFC
6962 or RFC 9162 wire response. A live adapter must separately implement and
test source authentication, TLS, timeouts, bounded downloads, pagination,
backoff, log-list trust, parsing, and proof verification as applicable.

Recommended next gates are:

1. Select and implement one real read-only CT provider/log adapter.
2. Authenticate collector-to-control-plane provenance rather than relying only
   on a digest.
3. Add an outbox and production event transport with explicit delivery
   semantics, retry, dead-lettering, redaction, and metrics.
4. Integrate authoritative domain and asset ownership data.
5. Evaluate an optional model-backed explainer against a fixed corpus.

Do not add orchestration privileges until policy, approval, separation of
duties, audit, rollback, and environment-specific authorization are designed
and tested.
