# LLM Council review: Milestone 2 trustworthy intake

Date: 2026-10-11

## Recommendation

Add full contract validation, provenance, durable idempotency, checkpoints, and
a fixture-driven CT source before implementing any live collector or model call.

## Independent perspectives

### Evidence analyst

Milestone 1 had a tested deterministic pipeline but only hand-authored events
and a domain validator implementing the security-critical subset of the JSON
contracts. The repository had no durable collector state or independent CI.
Certificate Transparency is useful evidence of observed public certificates,
but it neither proves organization ownership nor prevents misissuance.

### Sceptic / red team

The principal risks are trusting unauthenticated observations, reusing source
identities with changed content, duplicate alert floods, checkpoint gaps,
unbounded payloads, and describing a decoded fixture as a live CT protocol
implementation. The design therefore labels provenance `unverified`, bounds
files/entries/pages, fails on identity/content conflicts, and documents the
transport gap.

### Alternative strategist

A live CT client, cloud-certificate API, or internal TLS scanner would provide
more realistic data. Each is a valid later adapter, but none removes the need
for the same canonical contracts, idempotency, checkpoints, and evidence model.
Building those reusable controls first is the more reversible decision.

### Practical implementation reviewer

SQLite provides sufficient durability and transactional behavior for a
single-process reference implementation. A provider-neutral fixture source
allows deterministic tests. Full Draft 2020-12 validation requires one pinned
runtime dependency; GitHub CI then tests Python 3.11 through 3.13.

### Risk and future reviewer

The source protocol, canonical event, provenance envelope, and state boundary
can support later CT, cloud, private-PKI, and TLS-discovery adapters. A future
distributed deployment must replace local SQLite/JSONL delivery with an
authenticated event transport, transactional outbox, tenancy controls, and
operational SLOs.

## Cross-examination

Agreement:

- Preserve raw evidence and identify the policy used for every alert.
- Make restart and replay behavior testable before live ingestion.
- Do not call a digest authentication or a fixture a live CT collector.
- Keep parsing, detection, scoring, and explanation deterministic.

Disagreement:

The main disagreement was whether the immediate user value of live CT data
outweighs the architectural sequencing cost. The Chair rejected live transport
for this milestone because failure attribution and safe replay matter more than
an early demonstration feed.

Weak assumptions and missing evidence:

- The future CT provider and its wire contract are not selected.
- Throughput, retention, tenancy, latency, and availability targets are unknown.
- The example domain policy is not an authoritative ownership registry.
- SQLite concurrency beyond one collector process is not established.

## Council challenge

The strongest counterargument is that all fixture behavior may pass while a
real provider fails on scale, malformed certificates, log inconsistency, or
transport behavior. This is valid; Milestone 2 proves the intake boundary and
replay controls, not production CT compatibility.

## Chair synthesis

Proceed with fixture-driven trustworthy intake and require the next milestone
to select one real source, define its trust model, and test it against captured
non-sensitive payloads before any production deployment.

Confidence: **HIGH** for the sequencing and local control model; **MODERATE** for
its fit to a future production topology because operational requirements remain
unknown.
