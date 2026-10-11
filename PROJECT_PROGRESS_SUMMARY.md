# AI-Assisted Cryptographic Control Plane

## Project progress summary

**Project status:** Work in progress  
**Current version:** 0.4.0  
**Current milestone:** Milestone 4 completed  
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

## Current evidence

- Four incremental implementation milestones are recorded in Git history.
- The repository contains versioned JSON schemas, architecture decisions, a
  threat model, examples, command-line demonstrations, and automated tests.
- The current automated suite contains **46 tests**.
- The suite has passed on Python 3.12 and Python 3.13, including the real local
  TLS handshake test when run outside the restricted test sandbox.
- The current working implementation is recorded in commit `be71182`.
- The project documentation pack is recorded in commit `fd2d7ea`.

## Current limitations

The project is a local reference implementation and remains under development.
It does not currently:

- connect to customer or production data sources;
- claim complete discovery of an organisation's cryptographic estate;
- provide authenticated production collectors;
- discover every form of cryptography used in applications, code, KMS, HSM,
  private PKI, cloud services, or supplier products;
- operate as a multi-user or multi-tenant production service;
- execute certificate, key, trust-store, or production migration changes;
- prove that an organisation is quantum-safe;
- carry independent certification, audit, or penetration-test assurance.

These limitations are intentional at the current stage. The project is proving
the data contracts, evidence boundaries, deterministic assessment rules, safety
controls, and migration-management design before production integrations or
change authority are introduced.

## Next planned milestone

**Milestone 5 — PQC migration management** will add a fictional enterprise
catalogue so that the migration workflow can be developed without customer
data. Planned capabilities include:

- assets, services, owners, suppliers, and business context;
- cryptographic dependency relationships;
- current and target cryptographic states;
- migration priority and waves;
- blockers and prerequisites;
- exceptions and approval records;
- verification criteria and post-change evidence;
- separate reporting of discovery coverage and migration completion.

## Overall position

The project has progressed beyond a concept or presentation. It has executable
code, real cryptographic test artifacts, machine-readable contracts, persistent
evidence handling, documented security boundaries, and repeatable automated
tests.

It should presently be described as a **working reference implementation under
active development**, not as a finished production product. The completed work
provides the technical foundation for building and demonstrating PQC migration
management in the next milestone.

