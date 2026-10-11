# ADR-006: Safe reference foundations for Milestones 6 to 9

- **Status:** accepted
- **Date:** 2026-10-11

## Context

Milestone 5 established non-executing migration governance. The remaining
roadmap calls for evidence exchange, a read-only pilot, production control-plane
foundations, and optional integrations. This repository has no customer data,
written pilot authorisation, production identity provider, operational service,
or independently assessed execution environment.

## Decision

Implement all remaining capabilities as a local reference release while
preserving the real-world decision gates:

1. Reconcile repeated inventory observations deterministically, retain every
   source record, and label contradictory states as conflicts rather than
   silently selecting truth.
2. Export CBOM-style and dependency views without claiming conformance to an
   external CBOM standard.
3. Produce sanitised, Ed25519-signed offline bundles. The signature protects
   manifest integrity; signer trust and observation evidence maturity remain
   separate. Sanitisation and signing never upgrade evidence.
4. Require a versioned, time-bounded, independently approved, read-only scope
   before pilot measurement. The included pilot is simulated and cannot satisfy
   Gate G3.
5. Demonstrate tenant scoping, optimistic versioning, RBAC, separation of
   duties, audit, and transactional outbox semantics in local SQLite. This does
   not satisfy production availability, identity, recovery, or assurance gates.
6. Represent integrations as evidence-bound proposals with no execution
   authority. Reject issuance, revocation, rotation, deletion, trust changes,
   deployment, and generic execution.

## Consequences

Positive:

- the end-to-end governance shape is executable without inventing production
  evidence or connecting to customer systems;
- evidence conflicts, source trust, signer trust, and migration completion stay
  separate;
- future adapters have explicit least-authority and approval boundaries;
- local tests exercise tenant isolation, stale-write prevention, and
  separation-of-duties rules.

Negative and residual:

- SQLite is a reference persistence layer, not the production topology;
- the offline bundle uses an embedded self-signed public key until an external
  trust registry is approved;
- no real pilot, production SLO, disaster recovery, privacy assessment,
  penetration test, or external integration has occurred;
- CBOM output is a project-specific reference representation.

## Rejected alternatives

- **Declare all roadmap exit gates complete:** rejected because code and
  simulated evidence cannot replace authorisation, production operation, or
  independent assurance.
- **Treat a valid bundle signature as production evidence:** rejected because a
  signature authenticates bytes only relative to a trusted key; it does not
  prove the observations are complete or true.
- **Add direct PKI/KMS/HSM execution:** rejected because credential, approval,
  rollback, blast-radius, and operational controls are absent.
