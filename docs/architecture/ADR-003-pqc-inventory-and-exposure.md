# ADR-003: Evidence-backed cryptographic inventory and PQC exposure

- Status: accepted
- Date: 2026-10-11

## Context

Milestones 1 and 2 proved deterministic certificate alerting and replay-safe
evidence intake. The product goal is broader: an evidence-backed cryptographic
discovery and PQC migration control plane. Certificate observations are useful
discovery evidence, but they do not establish negotiated key establishment,
application implementations, business ownership, dependency paths, or complete
cryptographic coverage.

## Decision

Introduce two separately versioned and validated artifacts:

1. A cryptographic inventory record that preserves the source observation,
   cryptographic function, algorithm details, asset context, evidence confidence,
   and explicit coverage limitations.
2. A deterministic PQC assessment that classifies known classical public-key
   exposure, marks unknown evidence as unknown, treats PQC algorithms as
   candidates requiring deployment verification, and refuses to finalise
   migration priority without required business context.

Extend the canonical certificate event to version 1.2 with decoded public-key,
certificate-signature, key-usage, extended-key-usage, and optional business
context. Persist validated inventory records and assessments atomically with the
source processing outcome.

## Safety semantics

- RSA, elliptic-curve, and finite-field DH families are classified as
  quantum-vulnerable evidence.
- ML-KEM, ML-DSA, and SLH-DSA evidence is `candidate-quantum-resistant`, not a
  declaration of system safety or migration completion.
- A hybrid label is `hybrid-unverified` until the protocol, implementation,
  peers, trust chain, and fallback behavior are tested.
- Known vulnerable evidence dominates unknown evidence; an unknown field cannot
  hide a known classical exposure.
- Certificate key usage indicates permitted capability, not proof of runtime
  protocol negotiation.
- Missing evidence stays explicit and blocks unsupported conclusions.

## Consequences

Positive:

- The same intake foundation now produces auditable discovery and assessment
  artifacts for the future migration control plane.
- Business context and algorithm exposure are separated, allowing exposure to
  be identified without inventing migration priority.
- Coverage limitations travel with each record and reduce false confidence.
- Later TLS, code, cloud, KMS, HSM, private-PKI, and vendor collectors can target
  the same inventory boundary.

Negative and residual:

- Algorithm values are supplied by decoded fixtures; live X.509 parsing and
  independent verification are not implemented.
- The current inventory covers certificates only and contains no resolved
  dependency graph.
- CT observations generally lack authoritative owner, service, data-lifetime,
  implementation, and supplier context.
- SQLite remains a single-process reference store.
- The version 1.2 event contract intentionally requires producers to provide
  explicit cryptographic evidence or `unknown`; version 1.1 events fail closed.

## Rejected alternatives

- **Treat missing fields as safe:** rejected because absence of evidence is not
  evidence of quantum resistance.
- **Declare ML-DSA/ML-KEM observations compliant:** rejected because algorithms
  alone do not establish protocol, chain, implementation, or relying-party
  readiness.
- **Infer TLS key establishment from the certificate:** rejected because
  certificate authentication/signatures and negotiated key establishment are
  distinct evidence domains.
- **Build migration orchestration now:** rejected until discovery coverage,
  authoritative ownership, policy, approvals, separation of duties, audit, and
  rollback controls exist.
