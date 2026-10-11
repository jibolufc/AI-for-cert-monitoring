# LLM Council review: remaining roadmap milestones

## Recommendation

Build a single version 0.9 reference release covering Milestones 6 to 9, but
record Milestone 6 as locally implemented and Milestones 7 to 9 as executable
reference foundations whose external exit gates remain open.

## Why

The repository can safely demonstrate reconciliation, offline evidence
exchange, pilot authorisation checks, tenant-scoped workflow semantics, audit,
outbox, and proposal-only integrations using generated or simulated evidence.
It cannot establish a real authorised pilot, a production service, or verified
organisational integrations without external evidence and authority.

## Council challenge

The strongest objection is that implementing later-stage interfaces may create
an appearance of readiness beyond the evidence. The design therefore emits an
explicit `production_gates_passed: false`, keeps simulated pilot status visible,
and gives every integration proposal `execution_authority: none`.

The red-team review also rejected automatic evidence escalation. Bundle
sanitisation, integrity signing, and signer trust are independent attributes;
none upgrades the evidence level of the enclosed observations.

## Alternatives

1. Stop after Milestone 6. This is the lowest-risk approach but leaves key
   tenancy and integration boundaries untested.
2. Build a UI before persistence and authorisation semantics. Rejected because
   presentation would precede the controls it needs to represent.
3. Connect a live source immediately. Rejected because written scope, source
   authentication, privacy review, and a stop plan are not available.

## Confidence

**MODERATE-HIGH** for the local reference architecture and negative security
controls. **LOW** for production readiness, because no real operational or
independent evidence exists.

## What would change the recommendation?

Written pilot authority, a bounded source, a real asset denominator, approved
identity and tenant architecture, recovery/SLO evidence, independent security
testing, and reviewed adapter-specific credentials would allow the corresponding
external gates to move from open to assessed.
