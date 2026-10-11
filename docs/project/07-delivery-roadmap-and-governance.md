# Delivery Roadmap and Governance

## 1. Completed foundation

| Milestone | Outcome | Evidence |
|---|---|---|
| 1 | Contract-first certificate monitoring vertical slice | Commit `bfdc4ff`, ADR-001, pipeline tests |
| 2 | Replay-safe bounded intake and durable evidence | Commit `20e5705`, ADR-002, CT tests |
| 3 | Cryptographic inventory and deterministic PQC exposure | Commit `887fdb3`, ADR-003, inventory tests |
| 4 | Controlled real X.509 and loopback TLS discovery lab | Commit `be71182`, ADR-004, discovery tests |
| 5 | Deterministic migration planning and governance using a fictional enterprise | ADR-005, migration schemas, planner/workflow tests |

These commits are local project evidence unless and until deliberately pushed
and reviewed on GitHub.

## 2. Recommended roadmap

### Milestone 6 — Evidence reconciliation and offline bundle

- multi-observation correlation with conflict lineage;
- CBOM-style export and dependency graph views;
- sanitisation tool and customer-controlled offline evidence bundle;
- signed manifest, import validation, and data-quality report;
- report generation for technical and executive audiences.

Exit: realistic data can be exchanged and assessed without uncontrolled direct
connectivity.

### Milestone 7 — Authorised read-only pilot

- select one bounded source and obtain written authorisation;
- implement collector authentication and scope policy;
- add authoritative asset denominator and ownership enrichment;
- operate read-only, measure quality, and report unknowns;
- perform privacy and security review.

Exit: evidence-backed pilot report with measured, not assumed, coverage and
error rates.

### Milestone 8 — Production control-plane foundation

- tenant and identity architecture;
- durable stream, evidence storage, transactional workflow, and outbox;
- UI/API, RBAC, separation of duties, audit export;
- SLOs, recovery, observability, secure delivery pipeline;
- independent security testing.

Exit: approved production service for discovery and migration governance, still
without autonomous cryptographic changes.

### Milestone 9 — Optional controlled integrations

- integrate ticketing, CMDB, PKI, KMS/HSM, and deployment evidence;
- add narrowly scoped action proposals or external change triggers;
- consider isolated execution only after a separate risk decision.

Exit: verified end-to-end organisational workflow with explicit authority.

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

## 8. Immediate next backlog

1. Define observation-to-catalogue reconciliation and conflict-lineage rules.
2. Add a signed offline evidence-bundle contract and import validator.
3. Add sanitisation controls that preserve the properties under test.
4. Produce CBOM-style and dependency-graph exports.
5. Generate local technical and executive reports from the same evidence.
6. Extend the threat model and traceability matrix.
7. Run the full suite on Python 3.11, 3.12, and 3.13.

