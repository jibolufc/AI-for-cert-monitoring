# ADR-009: G4 preparation without production authority

- **Status:** accepted for the local reference implementation
- **Date:** 2026-11-19

## Context

The controlled G3 synthetic test demonstrated reviewed deployment-window
handling and hash-consistent restore, but six G3 controls, a real source,
written authority, and an external G3 decision remain open. Production planning
can proceed without weakening those boundaries if preparation evidence is kept
separate from operating authority.

## Decision

Add a provider-neutral G4 preparation contract and deterministic assessor. It
tracks ten production-service control areas while requiring synthetic data,
disabled public and production traffic, and no operating or migration execution
authority.

The assessor has two outcomes:

- `blocked`: one or more preparation controls or governance prerequisites are
  absent or inconsistent;
- `g4-preparation-ready`: all declared preparation controls have evidence
  references, but production operation is still unauthorised.

Every report fixes `g4_gate_passed` to `false`,
`production_operating_authority` to `none`, and
`migration_execution_authority` to `none`.

## Consequences

- G4 design, SLO, runbook and assurance preparation can proceed alongside G3
  closure without connecting real data.
- Missing production controls remain machine-visible.
- A completed preparation checklist cannot silently become production approval.
- Independent evidence verification and accountable governance remain external.

## Rejected alternatives

- **Treat the AWS synthetic stack as production:** rejected because it has no
  production identity, service ownership, SLO, failover exercise, penetration
  test or support model.
- **Wait for all G3 activity before planning G4:** rejected because reversible
  documentation and contract work can expose gaps early without increasing live
  authority.
- **Combine G4 and G5:** rejected because operating a service and authorising
  cryptographic changes have different risks, credentials and approvals.
