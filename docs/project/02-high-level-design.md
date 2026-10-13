# High-Level Design

## 1. Architectural intent

The system is a control plane for evidence, decisions, and migration governance.
It is not itself a cryptographic data plane. Applications, PKI platforms, TLS
stacks, KMS/HSM products, and cloud services continue to perform cryptographic
operations.

The architecture follows five rules:

1. Evidence precedes conclusions.
2. Missing evidence remains visible.
3. Deterministic policy owns security-critical decisions.
4. Approval and execution are separate trust boundaries.
5. Migration completion requires post-change verification.

## 2. Context

```text
Evidence sources                  Cryptographic control plane                 Consumers
----------------                  ---------------------------                 ---------
CT / X.509 files  ───────┐        Intake + source trust                       SOC / SIEM
TLS endpoints     ───────┤              │                                     PKI team
Cloud PKI/KMS     ───────┤              v                                     Asset owners
Private PKI/HSM   ───────┼────> Canonical observations ───> Inventory ─────> Risk/compliance
Code/config/SBOM  ───────┤              │                     │               Change governance
CMDB/IAM          ───────┤              v                     v               Executives
Supplier evidence ───────┘        Policy assessment      Migration workflow
                                                                     │
                                                approved, isolated adapter (future only)
                                                                     │
                                                                     v
                                                              External platforms
```

## 3. Logical components

| Component | Responsibility | Current status |
|---|---|---|
| Collector adapters | Acquire bounded evidence from an authorised source | Fixture, file, and loopback lab implemented |
| Intake gateway | Authenticate source, enforce limits, validate contract, attach receipt metadata | Contract validation implemented; authentication planned |
| Evidence ledger | Preserve raw observation, digest, provenance, outcome, and lineage | SQLite reference implementation |
| Normalisation service | Convert source-specific data into canonical observations | Certificate path implemented |
| Inventory service | Produce cryptographic-use records with coverage limits | Certificate slice implemented |
| Correlation and graph service | Link assets, services, identities, dependencies, suppliers, and relying parties | Local conflict-preserving reconciliation and fictional dependency graph implemented; authoritative sources open |
| Policy and assessment service | Classify exposure, missing context, priority gates, and policy findings | Deterministic certificate/PQC slice implemented |
| Detection service | Produce operational alerts and playbook links | CERT-001 implemented |
| AI advisory service | Summarise evidence, suggest questions or plans, never silently decide | Deterministic fallback only |
| Migration workflow | Manage target state, waves, owners, approvals, exceptions, and verification | Local deterministic reference workflow implemented |
| Reporting and API | Expose coverage, evidence maturity, exposure, work, and audit history | Planned |
| Execution adapter | Apply narrowly approved changes with rollback and evidence | Out of scope until governance gates pass |

## 4. Trust zones

```text
Zone 0: Untrusted evidence sources
   │ authenticated, bounded collection (target)
   v
Zone 1: Intake and parsing
   │ validated canonical contract
   v
Zone 2: Evidence and inventory data
   │ read-only evidence references
   +----------> Zone 3: Policy and advisory analysis
   │                         │ proposed work
   │                         v
   +----------> Zone 4: Human approval and workflow
                                  │ narrowly scoped authorisation
                                  v
                         Zone 5: Isolated execution (future)
```

The current implementation occupies local equivalents of Zones 1-3 and has no
production authority.

## 5. Principal data flows

### 5.1 Observation to inventory

1. Collector reads an authorised, bounded source.
2. Intake validates source envelope and payload schema.
3. Evidence identity and canonical digest are calculated.
4. Replay is classified as new, duplicate, or conflict.
5. Source-specific evidence is normalised without erasing provenance.
6. Inventory record and assessment are created.
7. Observation, outcome, inventory, and assessment commit atomically.

### 5.2 Observation to alert

1. Canonical certificate event is validated.
2. DNS identities are normalised.
3. Versioned policy evaluates the observation.
4. Deterministic severity, score, and alert identifier are created.
5. Advisory explanation is attached without decision authority.
6. Alert is validated and delivered to a sink.

### 5.3 Inventory to migration work (target)

1. Evidence is reconciled with authoritative asset and ownership sources.
2. Dependency paths and cryptographic functions are resolved.
3. Policy proposes priority and identifies missing evidence.
4. Owner selects a supported target state and verification plan.
5. Approvers accept the work, risk, exception, or deferral.
6. Change occurs in an external controlled delivery process.
7. Pre/post tests and new discovery evidence verify the outcome.
8. Coverage, residual risk, and regression status are recalculated.

## 6. Data domains

The target model has separately governed domains:

- **Observation:** what a source reported or a parser derived.
- **Evidence:** provenance, maturity, verification, integrity, scope, and time.
- **Inventory:** a cryptographic use linked to an asset or service.
- **Dependency:** a directional relationship that can block or constrain change.
- **Policy finding:** deterministic evaluation against a versioned policy.
- **Recommendation:** advisory output that requires review.
- **Migration item:** governed work with target, owner, dates, dependencies, and
  verification criteria.
- **Decision:** approval, rejection, exception, or risk acceptance by an actor.
- **Verification:** evidence that an approved result was achieved.

These domains must not be collapsed into a single mutable status record.

## 7. Deployment view

### Current reference deployment

- Local Python CLI processes.
- Local JSON fixtures and generated certificates.
- SQLite evidence state.
- JSONL/file output.
- Loopback-only TLS connection.
- No credentials, tenant boundary, public API, or production service.

### Target production deployment

- Collectors isolated by source and network scope.
- Authenticated ingestion endpoint with tenant binding and quotas.
- Sandboxed parsers for hostile artifacts.
- Durable event stream and immutable evidence/object storage.
- Transactional inventory and workflow stores.
- Separate policy, advisory, and approval services.
- Identity-aware API and user interface.
- Tamper-evident audit export and monitored SIEM integration.
- Optional execution adapters isolated by environment and privilege.

No cloud or platform choice is fixed by this HLD; selection requires scale,
residency, integration, cost, and operating-model requirements.

## 8. Availability and recovery concept

Production readiness requires:

- per-source checkpoints and replay-safe ingestion;
- retry with bounded backoff and dead-letter handling;
- transactional outbox for downstream delivery;
- backup and point-in-time recovery for policy, inventory, workflow, and audit;
- evidence-object integrity checks;
- documented recovery time and recovery point objectives;
- degraded operation that stops execution before it loses auditability.

The local SQLite store demonstrates semantics, not these service levels.

## 9. Security architecture

- Source authentication and tenant binding occur before high-assurance evidence
  labels are accepted.
- Parser processes receive no cloud or cryptographic-administration credentials.
- Evidence is append-oriented; corrections are new linked assertions.
- Policy changes use review, versioning, effective dates, and rollback.
- AI outputs are untrusted content with structured validation and citations.
- Human approval is identity-bound and separated from request creation.
- Execution credentials are narrow, expiring, environment-scoped, and absent
  from analysis services.
- Sensitive infrastructure metadata is encrypted and field-authorised.

## 10. Key architecture decisions

1. Contract-first deterministic monitoring slice — ADR-001.
2. Replay-safe evidence intake before live collection — ADR-002.
3. Inventory and PQC assessment remain separate artifacts — ADR-003.
4. Real controlled discovery without misrepresenting lab data — ADR-004.
5. Deterministic migration governance without execution authority — ADR-005.
6. Safe reconciliation, bundle, pilot, tenancy, and integration foundations — ADR-006.
7. External-review remediation and assurance-preserving controls — ADR-007.

## 11. Architecture limitations

The current architecture does not prove complete discovery, chain validation,
runtime KEM negotiation, application compatibility, supplier readiness, scale,
tenant isolation, service availability, or production security. Those are
explicit future validation gates.

## 12. Version 0.9 reference-release components

The `roadmap` component adds four bounded layers: evidence reconciliation and
offline exchange; pilot-authorisation checks; tenant-scoped workflow/audit/
outbox persistence; and proposal-only integration records. Trust remains
asymmetric: an offline signer can protect integrity without proving observation
truth, and an approved proposal conveys no execution authority.

