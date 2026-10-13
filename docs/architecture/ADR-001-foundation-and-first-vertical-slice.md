# ADR-001: Contract-first deterministic certificate monitoring slice

- Status: accepted
- Date: 2026-10-11
- Amended by: ADR-002 and ADR-007

## Context

The target system may eventually ingest certificate events from ACME, cloud
certificate managers, cert-manager, Certificate Transparency, TLS discovery,
Vault, HSM-backed services, and AD CS. It may also provide AI-assisted analysis
and governed lifecycle workflows. Building all integrations at once would hide
trust assumptions and prevent early end-to-end verification.

## Decision

Implement the first slice as a synchronous, dependency-light Python pipeline:

1. Accept a versioned canonical certificate event.
2. Perform strict domain validation and DNS-name normalization.
3. Enrich the event against an explicit organization DNS policy.
4. Evaluate deterministic rule `CERT-001` (unknown DNS namespace).
5. Create a deterministic alert ID and risk score.
6. Add a deterministic, advisory explanation from structured evidence.
7. Append the alert to a local JSONL development sink.
8. Provide a corresponding SOC playbook and automated tests.

The schemas are language-neutral JSON Schema Draft 2020-12 documents. Detection
results do not depend on an LLM. No component can issue, renew, revoke, install,
or delete certificates or keys.

## Consequences

Positive:

- The first milestone is locally executable and auditable.
- Collector and SIEM adapters can evolve around stable contracts.
- Tests capture security-relevant normalization and policy behavior.
- A future model adapter can be evaluated without changing alert semantics.

Negative:

- The local validator implements the security-critical subset of the published
  schemas; independent full JSON Schema conformance tooling is still required.
- JSONL lacks production delivery, integrity, retry, and access controls.
- DNS allowlists do not establish legal or operational domain ownership.
- The synchronous path is not a scale architecture.

## Guardrails for later milestones

- Sign or otherwise authenticate collector-to-control-plane events.
- Define tenancy, replay, idempotency, retention, and redaction policies.
- Treat model output as untrusted advisory content; validate structured output.
- Require deterministic policy and appropriate human approval for high-impact
  cryptographic operations.
- Isolate any future executor from analysis services and use narrow, expiring,
  environment-scoped credentials.
