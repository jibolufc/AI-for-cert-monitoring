# AI-Assisted Cryptographic Control Plane

## Project progress summary

**Project status:** Work in progress

**Current version:** 0.9.0

**Current milestone:** Milestone 6 implemented; Milestones 7-9 reference foundations implemented with external gates open

**Last updated:** 11 October 2026

## Project overview

This project is developing an **evidence-backed cryptographic discovery and
post-quantum cryptography (PQC) migration control plane**.

Its purpose is to help organisations discover where cryptography is being used,
record the supporting evidence, identify cryptographic components that may be
affected by quantum computing, and manage future migration work in a controlled
and auditable way.

Certificate monitoring is the first working discovery capability. The intended
product is broader and will eventually include cryptographic inventory,
dependencies, ownership, migration planning, approvals, exceptions, and
verification.

## Work completed

### Milestone 1 — Certificate monitoring foundation

- Created a versioned certificate-event format.
- Added strict validation and DNS-name normalisation.
- Added deterministic detection of certificates containing unapproved DNS
  namespaces.
- Added risk scoring, evidence-based explanations, alert output, and a SOC
  playbook.

### Milestone 2 — Evidence intake and replay protection

- Added a controlled Certificate Transparency fixture collector.
- Added evidence provenance and SHA-256 content digests.
- Added SQLite storage for observations, outcomes, and checkpoints.
- Added duplicate detection, restart support, and fail-closed provenance
  conflict handling.

### Milestone 3 — Cryptographic inventory and PQC assessment

- Added cryptographic inventory records linked to source evidence.
- Added deterministic identification of quantum-vulnerable RSA and
  elliptic-curve certificate evidence.
- Added support for representing ML-KEM, ML-DSA, SLH-DSA, hybrid, and unknown
  algorithm evidence.
- Added explicit handling of missing ownership, business criticality, data
  classification, and protection-lifetime information.
- Prevented PQC algorithm names from being treated as proof that a deployment is
  quantum-safe.

### Milestone 4 — Controlled discovery laboratory

- Added generation of real RSA and elliptic-curve X.509 test certificates.
- Added PEM and DER certificate parsing.
- Added discovery of certificate fingerprints, identities, validity periods,
  public-key algorithms, key sizes, curves, signatures, key usages, and extended
  key usages.
- Added a bounded loopback TLS test that records the TLS version and cipher
  suite without scanning external systems.
- Added evidence-maturity levels that distinguish simulated, generated,
  sanitised, public-observation, authenticated-production, and independently
  verified evidence.
- Added controls preventing laboratory evidence from being presented as
  authenticated production evidence.

### Milestone 5 — PQC migration management

- Added a fictional six-service enterprise catalogue with assets, owners,
  suppliers, business context, cryptographic uses, and dependencies.
- Added deterministic migration priorities, waves, blockers, and function-
  specific target compatibility.
- Added separately versioned work-item, decision, exception, verification, and
  coverage-report contracts.
- Added controls for dependency cycles, ownership conflicts, evidence
  escalation, stale decisions, self-approval, expired exceptions, and
  incomplete or non-independent verification.
- Added separate discovery-coverage and verified-migration measures.
- Kept all implementation activity outside the control plane; it remains a
  planning, governance, and verification reference implementation.

### Milestone 6 — Evidence reconciliation and offline exchange

- Added deterministic multi-observation correlation that retains all record IDs
  and exposes contradictory algorithm states.
- Added CBOM-style and dependency-graph exports.
- Added field-level sanitisation that preserves cryptographic properties without
  upgrading evidence maturity.
- Added Ed25519 manifest signing and import validation. Embedded self-signed
  keys establish local integrity only; signer trust is separate.

### Milestone 7 — Authorised pilot reference gate

- Added time-bounded, independently approved, read-only scope contracts.
- Added fail-closed expiry, self-authorisation, source-authentication, and asset-
  scope checks.
- Added denominator-based coverage reporting. The included run is simulated and
  does not claim that a real pilot has taken place.

### Milestone 8 — Production control-plane reference foundation

- Added tenant-scoped workflow persistence, optimistic version enforcement,
  role checks, separation of duties, audit records, and transactional outbox
  records in local SQLite.
- Production identity, availability, recovery, SLO, privacy, and independent
  assurance gates remain open.

### Milestone 9 — Proposal-only integration boundary

- Added validated proposals for ticketing, CMDB, PKI, KMS/HSM, and deployment-
  evidence integration families.
- All proposals have `execution_authority: none`; cryptographic and deployment
  mutations are rejected.

## Current evidence

- Nine roadmap milestones are represented in the reference design; Milestones
  7-9 retain explicit external acceptance gates.
- The repository contains versioned JSON schemas, architecture decisions, a
  threat model, examples, command-line demonstrations, and automated tests.
- The current automated suite contains **75 tests**.
- The current full run passes on Python 3.13. The loopback TLS test passes when
  run outside the restricted test sandbox. A fresh 3.12 run remains pending a
  test environment containing the pinned project dependencies.
- Milestone 4 is recorded in commit `be71182` and the supporting project
  documentation is recorded in later local commits.

## Current limitations

The project is a local reference implementation and remains under development.
It does not currently:

- connect to customer or production data sources;
- claim complete discovery of an organisation's cryptographic estate;
- provide authenticated production collectors;
- discover every form of cryptography used in applications, code, KMS, HSM,
  private PKI, cloud services, or supplier products;
- operate as a production multi-user or multi-tenant service;
- execute certificate, key, trust-store, or production migration changes;
- prove that an organisation is quantum-safe;
- carry independent certification, audit, or penetration-test assurance.

These limitations are intentional at the current stage. The project is proving
the data contracts, evidence boundaries, deterministic assessment rules, safety
controls, and migration-management design before production integrations or
change authority are introduced.

## Next external validation gates

The next work is evidence, not another feature milestone: obtain written pilot
authority and a bounded read-only source; validate an external signer trust
registry; review privacy and retention; select a production identity/tenant
architecture; demonstrate backup, recovery, SLOs, and independent security
testing; then review each proposed adapter before granting any authority.

## Overall position

The project has progressed beyond a concept or presentation. It has executable
code, real cryptographic test artifacts, machine-readable contracts, persistent
evidence handling, documented security boundaries, and repeatable automated
tests.

It should presently be described as a **working reference implementation under
active development**, not as a finished production product. The completed work
now demonstrates both evidence-backed discovery and controlled PQC migration
management using explicitly simulated enterprise data. It also demonstrates the
safe architecture of later roadmap stages without claiming their external gates
have been passed.

