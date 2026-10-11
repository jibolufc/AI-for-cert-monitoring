# Project evidence pack

**Project:** AI-assisted Cryptographic Control Plane  
**Product goal:** Evidence-backed cryptographic discovery and post-quantum
cryptography (PQC) migration management  
**Document baseline:** Version 0.4.0, Milestones 1-4  
**Prepared:** 2026-10-11  
**Implementation baseline:** commit `be71182`

## Purpose

This pack explains what the project is, why it exists, how it is designed, what
has actually been implemented, how it is tested, and what remains to be built.
It is suitable for a portfolio review, architecture review, technical due
diligence, funding conversation, controlled pilot proposal, or internal project
approval.

It is not a claim of formal certification, production deployment, enterprise
coverage, regulatory compliance, or successful migration of a real estate.
Those claims require authorised production evidence and independent review.

## Status vocabulary

Every material claim should use one of these states:

| State | Meaning |
|---|---|
| Implemented | Present in the repository and linked to executable evidence |
| Partially implemented | A working reference slice exists but production controls or breadth are missing |
| Planned | Defined as a requirement or design, but not represented as working code |
| Out of scope | Deliberately excluded from the current product boundary |

## Document register

| Document | Review question answered |
|---|---|
| [Product Requirements Document](01-product-requirements-document.md) | What problem does the product solve, for whom, and under what acceptance criteria? |
| [High-Level Design](02-high-level-design.md) | What are the system boundaries, components, trust zones, and major flows? |
| [Low-Level Design](03-low-level-design.md) | How do the implemented modules, contracts, state, rules, and failure paths work? |
| [Requirements Traceability Matrix](04-requirements-traceability-matrix.md) | Which requirements are linked to design, code, and tests? |
| [Verification and Validation Plan](05-verification-and-validation-plan.md) | How will correctness, security properties, and fitness for use be demonstrated? |
| [Security, Risk and Assurance Plan](06-security-risk-and-assurance-plan.md) | What can go wrong, which controls exist, and which assurance claims are forbidden? |
| [Delivery Roadmap and Governance](07-delivery-roadmap-and-governance.md) | How does the reference implementation become a governed migration platform? |
| [Project Evidence and Demonstration Guide](08-project-evidence-and-demo-guide.md) | How can a reviewer independently reproduce the current claims? |

Related engineering records:

- `docs/architecture/ADR-001` through `ADR-004`: accepted architecture decisions
- `docs/threat-model/THREAT_MODEL.md`: detailed threat inventory and invariants
- `schemas/`: machine-readable interface contracts
- `tests/`: executable verification evidence
- `examples/`: simulated and generated scenarios

## Evidence hierarchy

The strongest current project evidence is:

1. Version-controlled source and architecture decisions.
2. Machine-enforced JSON Schema and domain validation.
3. Deterministic rules with reproducible outputs.
4. Automated tests across supported Python versions.
5. Real, locally generated X.509 artifacts and a loopback TLS handshake.
6. Explicit evidence-maturity labels and coverage limitations.

The current project does **not** yet have:

- authenticated production collectors;
- customer or enterprise asset coverage;
- authoritative CMDB, PKI, KMS, HSM, IAM, or supplier integrations;
- multi-tenant security or production service availability;
- a migration workflow, approval engine, or production executor;
- an independent penetration test or external assurance report.

## Recommended review order

1. Read the PRD and HLD.
2. Inspect the traceability matrix.
3. Run the demonstration guide and tests.
4. Review the LLD and threat model.
5. Decide whether the next gate is portfolio acceptance, a fictional-enterprise
   migration simulation, or an authorised read-only pilot.

