# ADR-008: G3 readiness without implied collection authority

Status: accepted for the local reference implementation

## Context

Gate G3 permits a bounded real-data pilot only after written authorisation,
named source scope, privacy and security review, and an owned stop plan exist.
The project currently has no approved real source or real dataset. Infrastructure
readiness is useful evidence, but it must not be confused with permission to
collect data or with successful enterprise discovery.

## Decision

Add a provider-neutral, machine-checkable G3 readiness contract and deterministic
assessor. The contract records the source and asset denominator, validity window,
data classification and retention, independent reviewers, stop conditions,
prohibited mutation operations, and eight staging controls.

The assessor has three outcomes:

- `blocked`: one or more declared prerequisites are absent or inconsistent;
- `synthetic-staging-ready`: synthetic controls are evidenced, but G3 is not passed;
- `g3-decision-required`: real-pilot declarations are complete enough for an
  accountable external decision, but the tool does not grant that decision.

Every report fixes `g3_gate_passed` to `false` and
`collection_execution_authority` to `none`. Only an external governance record
may authorise a real pilot. This repository still contains no live collector.

## Consequences

- Synthetic staging can progress without customer data or production credentials.
- Missing controls and governance evidence are visible and reproducible.
- A completed checklist cannot silently become collection authority.
- Evidence references are declarations; independent verification of artifacts
  remains a human assurance activity.
- Cloud-provider deployment modules are deferred until a provider, account,
  region, cost owner, identity model, and teardown authority are explicitly chosen.

## Rejected alternatives

- Mark G3 passed from a synthetic run: rejected because it conflates technical
  readiness with legal, privacy, data-owner, and operational authority.
- Connect a convenient public or production endpoint: rejected because source
  availability is not authorisation.
- Make the initial contract cloud-provider-specific: rejected because it would
  create premature architecture and operating-cost commitments.
