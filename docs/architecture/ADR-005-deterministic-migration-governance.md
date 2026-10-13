# ADR-005: Deterministic migration governance without execution authority

- Status: accepted
- Date: 2026-10-11

## Context

Milestones 1-4 established certificate monitoring, replay-safe evidence,
certificate-focused inventory/PQC assessment, and controlled real X.509/TLS
discovery. The project goal also includes migration management, but there is no
authorised production estate, authoritative ownership source, approved target
policy, or change authority.

A credible reference implementation must demonstrate how discovery becomes
governed work without presenting fictional data as production coverage or
allowing a planning service to perform cryptographic changes.

## Decision

Implement Milestone 5 around six separately validated contracts:

1. Enterprise catalogue with assets, services, owners, suppliers, business/data
   context, cryptographic uses, target states, and dependencies.
2. Migration work item with current/target states, priority, wave, blockers,
   version, approval identity, and verification criteria.
3. Human decision record bound to an exact work-item version.
4. Time-bounded exception with risk ownership and compensating controls.
5. Independent verification record with pre/post evidence and named checks.
6. Report that keeps discovery coverage and migration progress separate.

Use a fictional six-service enterprise and simulated evidence. Reject duplicate
identities, conflicting asset ownership, unknown dependencies, self-dependency,
dependency cycles, and evidence-level escalation.

Use function-specific target compatibility:

- key establishment: ML-KEM or a protocol-defined hybrid candidate;
- digital signature and certificate authentication: ML-DSA, SLH-DSA, or a
  protocol-defined hybrid candidate.

Target names remain planning candidates. A `supported` value does not prove
protocol, product, peer, chain, or fallback interoperability.

Migration priority and wave assignment are deterministic. Missing evidence or
required business context remains unassigned. Target readiness and hard
dependency failures create explicit blockers.

Require human approval, prevent requester self-approval, reject stale decisions,
and keep implementation external. Permit `verified` only after an independent
verifier supplies pre-change and post-change evidence and every approved
criterion passes. Failed verification becomes `regressed`; inconclusive
verification stays open.

## Consequences

Positive:

- The control plane now demonstrates discovery-to-governance flow without real
  customer data.
- Dependencies, ownership, evidence, targets, decisions, exceptions, and
  verification are machine-readable and traceable.
- Missing evidence and unsupported targets cannot silently become plans.
- Coverage cannot be used as a substitute for migration completion.
- Planning and verification remain separated from privileged execution.

Negative and residual:

- The catalogue is hand-authored simulation rather than reconciled discovery.
- Priority rules are reference policy, not an organisation-approved risk model.
- Supplier readiness values are fictional and do not establish product support.
- Workflow state is in-memory/file-oriented; no durable multi-user concurrency,
  identity provider, RBAC service, or tamper-evident audit log exists.
- There is no automated dependency correlation or actual migration execution.

## Rejected alternatives

- **Add a production executor now:** rejected because scope, identity, approval,
  rollback, and environment authority are not established.
- **Use one overall readiness percentage:** rejected because it would conflate
  estate visibility with verified migration.
- **Allow algorithm labels to complete work:** rejected because deployed
  interoperability and downgrade behavior require direct verification.
- **Allow blocked work to be approved normally:** rejected because exceptions
  need distinct risk ownership, expiry, and compensating controls.
- **Use an LLM to assign authoritative waves:** rejected because security-
  critical prioritisation must be deterministic, reviewable, and versioned.
