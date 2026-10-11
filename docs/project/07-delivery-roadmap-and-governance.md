# Delivery Roadmap and Governance

## 1. Completed foundation

| Milestone | Outcome | Evidence |
|---|---|---|
| 1 | Contract-first certificate monitoring vertical slice | Commit `bfdc4ff`, ADR-001, pipeline tests |
| 2 | Replay-safe bounded intake and durable evidence | Commit `20e5705`, ADR-002, CT tests |
| 3 | Cryptographic inventory and deterministic PQC exposure | Commit `887fdb3`, ADR-003, inventory tests |
| 4 | Controlled real X.509 and loopback TLS discovery lab | Commit `be71182`, ADR-004, discovery tests |
| 5 | Deterministic migration planning and governance using a fictional enterprise | ADR-005, migration schemas, planner/workflow tests |
| 6 | Conflict-preserving reconciliation and integrity-protected offline evidence | ADR-006, roadmap module, bundle tests |
| 7 | Read-only pilot authorisation and measurement reference gate | ADR-006, pilot schema and negative tests |
| 8 | Tenant-scoped workflow, audit, and outbox reference foundation | ADR-006, SQLite transaction and isolation tests |
| 9 | Proposal-only integration boundary | ADR-006, proposal schema and mutation rejection tests |

These commits are local project evidence unless and until deliberately pushed
and reviewed on GitHub.

## 2. Reference implementation status and external gates

### Milestone 6 — Evidence reconciliation and offline bundle: locally implemented

- multi-observation correlation with conflict lineage;
- CBOM-style export and dependency graph views;
- sanitisation tool and customer-controlled offline evidence bundle;
- signed manifest, import validation, and data-quality report;
- report generation for technical and executive audiences.

Local exit met with simulated/generated data. External trust establishment and
customer acceptance remain open.

### Milestone 7 — Authorised read-only pilot: reference gate implemented

- select one bounded source and obtain written authorisation;
- implement collector authentication and scope policy;
- add authoritative asset denominator and ownership enrichment;
- operate read-only, measure quality, and report unknowns;
- perform privacy and security review.

Real exit open: written authority, bounded source, authenticated collection,
privacy/security review, and measured real-world error rates are absent.

### Milestone 8 — Production control-plane foundation: local reference implemented

- tenant and identity architecture;
- durable stream, evidence storage, transactional workflow, and outbox;
- UI/API, RBAC, separation of duties, audit export;
- SLOs, recovery, observability, secure delivery pipeline;
- independent security testing.

Real exit open: no approved production identity, service, SLO, recovery test,
secure-delivery evidence, or independent security assessment exists.

### Milestone 9 — Optional controlled integrations: proposal boundary implemented

- integrate ticketing, CMDB, PKI, KMS/HSM, and deployment evidence;
- add narrowly scoped action proposals or external change triggers;
- consider isolated execution only after a separate risk decision.

Real exit open: no organisational adapter is connected or authorised. Every
reference proposal has no execution authority.

## 3. Governance roles

| Role | Accountable decision |
|---|---|
| Product owner | Product outcomes, scope, and user acceptance |
| Security/cryptography authority | Algorithm policy and target-state approval |
| Enterprise architect | System and dependency architecture |
| Data owner | Collection purpose, classification, retention, and access |
| Service owner | Migration plan, implementation, and operational acceptance |
| Change authority | Production change approval and scheduling |
| Risk owner | Exception and residual-risk acceptance |
| Independent verifier | Evidence sufficiency for high-risk completion |
| Engineering team | Implementation, tests, operations, and defect resolution |

One person may perform multiple roles in a prototype, but the production design
must identify incompatible duties and compensating review.

## 4. Decision gates

| Gate | Decision | Minimum evidence |
|---|---|---|
| G0 Concept | Continue problem discovery | Problem statement and stakeholder need |
| G1 Reference architecture | Accept design direction | PRD, HLD, threat model, ADRs |
| G2 Reference implementation | Accept technical feasibility | LLD, source, schemas, tests, evidence guide |
| G3 Pilot | Permit bounded real data | Authorisation, source scope, privacy/security review, stop plan |
| G4 Production | Operate as a service | SLOs, access model, recovery, monitoring, pen test, runbooks |
| G5 Migration execution | Permit change authority | Separation of duties, adapter review, dry run, rollback, independent approval |

Passing one gate does not imply the next.

## 5. Delivery controls

- Use short-lived branches and reviewed pull requests.
- Require tests, schema compatibility review, threat-model delta, and
  traceability update for material changes.
- Pin external build actions and dependencies where practical.
- Produce a release evidence manifest with commit, environment, tests, schema
  versions, known issues, and artifact hashes.
- Sign releases and produce an SBOM before pilot distribution.
- Never mix secrets, customer evidence, or synthetic private keys into source
  control.

## 6. Backlog priority method

Prioritise features using:

1. assurance or safety risk reduced;
2. evidence needed for the next gate;
3. user value and decision enabled;
4. dependency order;
5. reversibility and learning value;
6. engineering and operating cost.

This places evidence reconciliation before a broad UI and authenticated
read-only discovery before any execution authority.

## 7. Change control

Material changes require an ADR when they alter:

- trust boundaries or privilege;
- evidence or assurance semantics;
- canonical contract compatibility;
- data retention/classification;
- deterministic decision authority;
- workflow states and approval rules;
- production deployment or external integrations.

## 8. Immediate external-evidence backlog

1. Build an isolated cloud/VPC staging environment using synthetic data only.
2. Demonstrate workload identity, RBAC, private networking, encryption, secrets,
   central logs, deployment controls, backup, and restore in that environment.
3. Obtain written authorisation for one bounded read-only source; do not treat
   the cloud deployment itself as permission to use production data.
4. Approve source authentication, privacy, retention, and stop controls.
5. Establish an external signer trust registry for bundle import.
6. Validate production identity and tenant isolation architecture.
7. Demonstrate observability, SLOs, recovery, and secure delivery.
8. Commission independent security testing.
9. Review each integration adapter and its credentials separately.
10. Run the full suite on Python 3.11, 3.12, and 3.13.

## 9. Recommended cloud progression

The recommended route is two deliberately separate environments:

1. **Synthetic staging in a VPC:** prove infrastructure controls and operating
   procedures without customer data or production credentials.
2. **Authorised read-only pilot:** connect one explicitly approved source after
   Gate G3 evidence exists, with an authoritative scope denominator, stop
   conditions, and no cryptographic change authority.

A successful VPC deployment is infrastructure evidence. It is not evidence of
enterprise discovery coverage, data authority, migration completion, or
production readiness unless the relevant gates are independently satisfied.

