# G4-C01 Service Ownership and Support Boundary

## Control state

**Prepared, not demonstrated.** This document defines the ownership model, but
the accountable individuals and independent approval are still unassigned.

## Service boundary

The service under preparation is the AI-assisted Cryptographic Control Plane
reference implementation. Its intended responsibility is evidence-backed
cryptographic discovery, inventory, risk prioritisation and proposal-only PQC
migration governance.

It is not a certificate authority, HSM or KMS, secret store, production PKI,
migration executor, vulnerability scanner, or autonomous remediation system.
It has no authority to issue, revoke, rotate, delete, deploy or change trust.

## Required accountable roles

| Role | Accountable individual | Current state | Required evidence |
|---|---|---|---|
| Service owner | UNASSIGNED | Open | Written acceptance of scope, funding, service risk and operating objectives |
| Security owner | UNASSIGNED | Open | Written acceptance of security architecture, risks, incident obligations and assurance plan |
| Data owner | UNASSIGNED | Open | Approved classification, lawful purpose, source authority, retention and deletion decision before real data |
| Operations owner | UNASSIGNED | Open | Accepted support hours, alert routing, runbooks, recovery objectives and on-call model |
| Change approver | UNASSIGNED | Open | Separation from requester and authority for production change decisions |

One person may hold more than one role during preparation, but requester and
approver must remain different for production-affecting decisions. Any combined
role must be explicitly accepted as a segregation-of-duties risk.

## Responsibility model

| Activity | Service owner | Security owner | Data owner | Operations owner | Change approver |
|---|---|---|---|---|---|
| Product and service scope | A | C | C | C | I |
| Threat model and security exceptions | C | A | C | C | I |
| Data-source and retention approval | C | C | A | C | I |
| Monitoring and incident response | I | C | I | A | I |
| Production deployment or rollback | I | C | I | R | A |
| PQC migration recommendation | A | C | C | I | I |
| Cryptographic change execution | Prohibited | Prohibited | Prohibited | Prohibited | Prohibited |

`A` means accountable, `R` responsible, `C` consulted and `I` informed.

## Support and escalation boundary

- Current phase: local and synthetic production preparation only.
- Public endpoint: disabled.
- Production traffic: disabled.
- Real data: disabled.
- Support commitment: none until an operations owner accepts a documented model.
- Security event escalation: preserve evidence, disable the affected synthetic
  test path, notify the security owner when assigned, and do not resume on an
  assumption of safety.
- Availability event escalation: stop deployment, preserve stack and application
  evidence, follow the rollback runbook, and escalate to the service and
  operations owners when assigned.

## Demonstration criteria

G4-C01 remains `planned` until:

1. all five roles have named accountable individuals or approved role-combination decisions;
2. service and security owners provide written acceptance;
3. support hours and escalation contacts are recorded outside the public repository;
4. one tabletop escalation demonstrates that the correct owners are reached; and
5. the exercise record is independently reviewed and referenced by immutable or hashed evidence.

