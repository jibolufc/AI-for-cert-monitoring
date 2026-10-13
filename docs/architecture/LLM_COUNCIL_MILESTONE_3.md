# LLM Council review: Milestone 3 PQC inventory foundation

Date: 2026-10-11

## Recommendation

Reprioritise the next increment around the clarified product goal: establish a
strict, evidence-backed cryptographic inventory and deterministic PQC exposure
model before adding live transport or migration orchestration.

## Independent perspectives

### Evidence analyst

The repository already preserved certificate identity and provenance but did
not record public-key or signature algorithms, cryptographic function, asset
ownership, business impact, data lifetime, or coverage limitations. Those gaps
prevented defensible PQC discovery and prioritisation.

### Sceptic / red team

The main failure mode is false assurance: a public certificate feed can look
like a cryptographic inventory while missing private PKI, application libraries,
runtime negotiation, embedded cryptography, keys, HSMs, KMS platforms, suppliers,
and dependencies. Every record therefore carries `certificate-only` scope and
limitations, while missing evidence remains explicit.

### Alternative strategist

A real CT or TLS adapter would produce more realistic observations, but it would
still lack a reusable inventory and assessment contract. A vendor-neutral
normalisation boundary lets future native and third-party collectors contribute
evidence without coupling the control plane to one scanner.

### Practical implementation reviewer

Extending the decoded fixture contract provides a deterministic vertical slice:
certificate evidence becomes an inventory record, an explainable assessment,
and durable state. Separate schemas make future generalisation possible without
allowing certificate-specific assumptions to leak into every collector.

### Risk and future reviewer

The model must distinguish signatures from key establishment and algorithm
presence from operational readiness. AI may later correlate or explain these
records, but it must not determine exposure, approve exceptions, declare
migration complete, or execute cryptographic changes.

## Cross-examination

Agreement:

- Certificate monitoring is a discovery sensor, not the complete product.
- Unknown data must not become a low-risk or quantum-safe result.
- PQC and hybrid evidence require protocol and implementation verification.
- Asset ownership, data lifetime, dependencies, and supplier status are needed
  for migration sequencing.

Disagreement:

The principal sequencing dispute was whether to implement a live collector
before the inventory model. The Chair selected the inventory boundary because
the user clarified that migration management, rather than CT monitoring, is the
primary product outcome. Live adapters remain a following gate.

Missing evidence:

- Target customer environment and first production integration are not chosen.
- Authoritative CMDB, PKI, KMS, HSM, and ownership sources are unknown.
- Required retention, tenancy, throughput, and deployment topology are unknown.
- Migration policy and regulatory deadlines are not encoded.

## Council challenge

The strongest counterargument is that a schema-rich local model may appear more
complete than it is. The milestone counters this by preserving provenance,
labelling scope, emitting missing-context fields, and refusing to call candidate
PQC or hybrid evidence safe.

## Chair synthesis

Accept the inventory and PQC exposure foundation as Milestone 3. The next gate
should add a real read-only discovery source plus authoritative asset enrichment,
then measure coverage and evidence quality before any orchestration privilege.

Confidence: **HIGH** for the data and safety boundary; **MODERATE** for production
fit until the target environment and first integration are selected.
