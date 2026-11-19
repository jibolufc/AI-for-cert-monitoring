# Gate G4 Production-Preparation Plan

## Current decision

Gate G4 production preparation is the active next milestone. The G3
synthetic-staging control set has zero remaining controls, with seven
demonstrated and G3-C05 accepted as not applicable to the current secretless
scope. This does not constitute a G3 production pass. G4 preparation continues
using synthetic data and non-public infrastructure only and does not authorise a
production service, public endpoint, production traffic, real-data intake, or
cryptographic migration execution.

The machine-checkable contract fixes all of those authorities to disabled or
`none`. Even a fully evidenced preparation report returns
`g4_gate_passed: false`; only an accountable external governance record may
authorise operation as a production service.

### Foundation tranche: 19 November 2026

The local foundation drafts for G4-C01, G4-C02, G4-C09 and G4-C10 are prepared:

- [`G4-C01 service ownership`](../operations/G4-C01-service-ownership.md)
- [`G4-C02 candidate service-level objectives`](../operations/G4-C02-service-level-objectives.md)
- [`G4-C09 data protection and retention`](../operations/G4-C09-data-protection-retention.md)
- [`G4-C10 operating runbooks`](../operations/G4-C10-operating-runbooks.md)

All four controls remain `planned`. Named owners, approved targets, enforcement
evidence and exercised runbooks are deliberately unresolved, so document
existence cannot make the gate pass. The current assessment remains `blocked`
with zero demonstrated and ten remaining controls.

## Required preparation evidence

| ID | Control | Minimum evidence |
|---|---|---|
| G4-C01 | Service ownership | Named accountable service and security owners, support boundaries, escalation path |
| G4-C02 | Service-level objectives | Defined indicators, objectives, error budgets, measurement source, review cadence |
| G4-C03 | Production identity and access | Approved identity provider, tenant boundary, JIT access, MFA, RBAC and separation-of-duties tests |
| G4-C04 | Monitoring and alerting | Service, security and data-quality telemetry with tested routing and actionable alerts |
| G4-C05 | Incident response | Exercised incident plan, severity model, communications, evidence preservation and lessons process |
| G4-C06 | Backup, failover and recovery | Independently observed backup, restore, failover, RPO and RTO exercise evidence |
| G4-C07 | Secure delivery and supply chain | Reviewed CI/CD, pinned dependencies, SBOM, signing, provenance and rollback evidence |
| G4-C08 | Independent security testing | Scoped penetration test and tracked resolution or accountable acceptance of findings |
| G4-C09 | Data protection and retention | Approved classification, minimisation, encryption, residency, retention and deletion controls |
| G4-C10 | Operating runbooks and support | Exercised deployment, rollback, recovery, access, incident and support runbooks with named on-call ownership |

## Explicit non-goals

- passing G3 through synthetic evidence;
- declaring the current Lambda stack a production service;
- connecting customer, employer, CA, certificate inventory or credential data;
- granting issuance, revocation, rotation, deployment, deletion, trust-change or
  generic execution authority;
- treating a checklist or self-attestation as an independent security review;
- starting a penetration test against any third-party or public target without
  written scope and authorisation.

## Run the preparation assessment

```bash
.venv/bin/python -m crypto_control_plane.g4_readiness_cli \
  --plan examples/g4/synthetic-production-preparation-plan.json \
  --output build/g4/readiness-report.json \
  --as-of 2026-11-19T14:00:00Z
```

The initial expected result is `blocked`, with ten controls remaining. When all
ten preparation controls have evidence references the status may become
`g4-preparation-ready`, but `g4_gate_passed`, production operating authority,
and migration execution authority remain false or `none`.

## Relationship to G3 and G5

An external accountable G3 decision remains a prerequisite for any real-data
pilot. G4 preparation can reduce later engineering and governance delay, but
cannot supersede that decision. G5 is a separate decision about migration change
authority and remains prohibited even after a future G4 approval.
