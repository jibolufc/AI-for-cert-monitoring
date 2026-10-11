# AI-assisted Cryptographic Control Plane

This repository is an incremental reference implementation for certificate
observability, deterministic anomaly detection, and governed AI assistance. It
is deliberately **not** a certificate authority, key-management service, or
autonomous remediation system.

The first vertical slice is executable end to end:

```text
certificate event
  -> schema/domain validation
  -> DNS-name enrichment
  -> CERT-001 unknown-domain detection
  -> deterministic risk explanation
  -> JSONL SIEM alert
  -> SOC playbook
```

## Trust boundary

- Detection and risk scoring are deterministic and reviewable.
- The current "AI" explanation adapter is a deterministic fallback. A future
  model may rephrase evidence, but must not decide whether an alert exists,
  change its severity, or invoke CA, HSM, KMS, trust-store, revocation, or
  production deployment operations.
- Inputs are treated as untrusted telemetry. No live collectors, credentials,
  network calls, issuance actions, or remediation actions exist in this slice.
- JSONL is a development sink, not a production SIEM transport.

## Quick start

Requires Python 3.11 or newer and has no runtime dependencies.

```bash
python3 -m unittest discover -s tests -v

PYTHONPATH=src python3 -m crypto_control_plane.cli \
  --event examples/events/unknown-domain-issued.json \
  --policy examples/policy.json \
  --output build/alerts.jsonl
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
- `docs/soc-playbooks/`: analyst response procedures
- `tests/`: unit and integration-style vertical-slice tests
- `examples/`: safe local fixtures and policy

## Current scope and next gates

Milestone 1 is a local reference slice only. Recommended next gates are:

1. Schema conformance tooling and signed event provenance.
2. One read-only collector behind a stable adapter contract.
3. Durable idempotency, replay handling, and a production event bus.
4. SIEM transport with authentication, retry, dead-lettering, and redaction.
5. An optional model-backed explainer evaluated against a fixed corpus.

Do not add orchestration privileges until policy, approval, separation of
duties, audit, rollback, and environment-specific authorization are designed
and tested.
