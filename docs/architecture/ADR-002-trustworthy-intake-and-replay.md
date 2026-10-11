# ADR-002: Trustworthy intake contracts and replay-safe fixture collection

- Status: accepted
- Date: 2026-10-11

## Context

Milestone 1 proved the canonical event-to-alert path with hand-authored events.
It did not prove full schema conformance, evidence preservation, restart
behavior, replay handling, or a collector boundary. Connecting directly to a
live CT service at this point would combine unproven parsing, transport,
pagination, trust, and operational behavior.

## Decision

Implement a provider-neutral decoded CT fixture source behind a narrow source
protocol. Validate every page, event, policy, and alert using JSON Schema Draft
2020-12 plus domain checks. Add a versioned provenance envelope containing the
collector identity/version, source-record identity, raw-entry SHA-256, stated
verification state, and source cursor.

Persist the following in SQLite:

- collector checkpoints;
- the canonical raw CT entry;
- payload digest;
- canonical event;
- accepted, alerted, or rejected outcome;
- generated alert or validation error; and
- processing time.

Treat a repeated source identity with the same digest as a duplicate. Treat the
same source identity with a different digest as a provenance conflict and fail
closed. Checkpoint only after a fully processed page. A restart resumes after
the last completed page; a partial-page retry is safe because completed entries
are idempotent.

## Consequences

Positive:

- Tests exercise pagination, restart, replay, conflict, evidence, and alerting
  without external network or credential dependencies.
- Raw evidence and policy versions are linked to detection outputs.
- A future live adapter has a small, testable contract.
- CI validates the supported Python versions with read-only permissions and
  immutable action commit pins.

Negative and residual:

- A SHA-256 digest detects changed bytes but does not authenticate the source.
- The decoded fixture contract is not an implementation of CT wire protocols or
  cryptographic proof verification.
- SQLite is a single-process reference store, not a distributed event system.
- Appending an alert to JSONL and recording SQLite state are not one atomic
  transaction. A production integration needs a transactional outbox and
  explicit delivery semantics.
- Policy ownership remains illustrative rather than authoritative.

## Rejected alternatives

- **Live CT first:** rejected because transport and parsing failures would mask
  contract and replay defects.
- **In-memory deduplication:** rejected because it does not survive restart.
- **Digest described as a signature:** rejected because an unauthenticated hash
  provides integrity comparison, not source authenticity.
- **LLM extraction of CT records:** rejected because parsing and detection must
  remain deterministic and auditable.
