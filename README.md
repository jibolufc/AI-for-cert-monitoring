# AI-assisted Cryptographic Control Plane

This repository is an incremental reference implementation for an
**evidence-backed cryptographic discovery and post-quantum cryptography (PQC)
migration control plane**. Certificate monitoring is its first discovery sensor,
not its final product boundary. It is deliberately **not** a certificate
authority, key-management service, migration executor, or autonomous remediation
system.

Milestones 1 through 6 and the safe reference foundations for Milestones 7
through 9 are executable end to end:

```text
certificate event
  -> schema/domain validation
  -> DNS-name enrichment
  -> CERT-001 unknown-domain detection
  -> deterministic risk explanation
  -> JSONL SIEM alert
  -> SOC playbook

decoded CT fixture pages
  -> full JSON Schema validation
  -> provenance envelope + SHA-256 evidence digest
  -> SQLite evidence/idempotency/checkpoint state
  -> canonical event pipeline

canonical certificate event v1.3
  -> cryptographic algorithm/function evidence
  -> inventory record with explicit coverage limits
  -> deterministic PQC exposure assessment
  -> missing-context and verification requirements
  -> atomic SQLite evidence + inventory persistence

generated RSA/ECDSA/EdDSA/DSA certificate or loopback TLS peer
  -> real X.509 parsing
  -> evidence-maturity enforcement
  -> certificate + transport observations kept separate
  -> inventory and PQC assessment bundle

fictional enterprise catalogue
  -> ownership + business/data context
  -> validated acyclic dependency graph
  -> function-specific target compatibility
  -> deterministic priority + migration waves
  -> blocked, approval-required, or matching-target verification work items
  -> version-bound decisions and time-bounded exceptions
  -> independent post-change verification gate
  -> separate discovery coverage and migration progress

inventory observations
  -> conflict-preserving reconciliation
  -> CBOM-style + dependency graph exports
  -> sanitisation without evidence escalation
  -> Ed25519 manifest integrity for offline exchange
  -> bounded simulated pilot measurement
  -> tenant-scoped workflow + audit + transactional outbox
  -> proposal-only integrations with no execution authority
```

## Trust boundary

- Detection and risk scoring are deterministic and reviewable.
- The current "AI" explanation adapter is a deterministic fallback. A future
  model may rephrase evidence, but must not decide whether an alert exists,
  change its severity, or invoke CA, HSM, KMS, trust-store, revocation, or
  production deployment operations.
- Inputs are treated as untrusted telemetry. The CT adapter consumes bounded,
  decoded local fixtures only. No live collector, credential, network call,
  issuance action, or remediation action exists in this repository.
- JSONL is a development sink, not a production SIEM transport.
- A source digest detects changed content; it does not authenticate a collector
  or prove that a domain belongs to the organization.
- `unknown` evidence never becomes quantum-resistant by default. ML-KEM,
  ML-DSA, SLH-DSA, or hybrid labels remain candidates requiring protocol,
  implementation, trust-chain, peer, and fallback verification.
- Certificate evidence does not prove which key-establishment mechanism was
  negotiated and does not represent complete enterprise cryptographic coverage.
- The Milestone 4 TLS probe accepts loopback IP literals only. It is a controlled
  lab component, not an Internet, enterprise-network, or vulnerability scanner.

## Quick start

Requires Python 3.11 or newer. Runtime schema validation uses the pinned
`jsonschema` 4.26.0 package and its non-GPL format-validation extra.

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e .
.venv/bin/python -m unittest discover -s tests -v

.venv/bin/python -m crypto_control_plane.cli \
  --event examples/events/unknown-domain-issued.json \
  --policy examples/policy.json \
  --output build/alerts.jsonl

.venv/bin/python -m crypto_control_plane.ct_cli \
  --fixture-dir examples/ct/pages \
  --policy examples/policy.json \
  --state build/ct-state.sqlite \
  --output build/ct-alerts.jsonl

.venv/bin/python -m crypto_control_plane.inventory_cli \
  --event examples/events/known-domain-issued.json \
  --output build/pqc-inventory-assessment.json

# Parse a generated or explicitly sanitised certificate file.
.venv/bin/python -m crypto_control_plane.discovery_lab_cli \
  --certificate /path/to/test-certificate.pem \
  --evidence-level generated \
  --output build/x509-discovery-bundle.json

# Build a simulated, dependency-aware PQC migration plan.
.venv/bin/python -m crypto_control_plane.migration_cli \
  --catalog examples/migration/fictional-enterprise.json \
  --output build/migration-plan.json

# Build the safe Milestones 6-9 reference evidence set.
.venv/bin/python -m crypto_control_plane.roadmap_cli \
  --event examples/events/known-domain-issued.json \
  --event examples/events/unknown-domain-issued.json \
  --output-dir build/reference-release
```

The example produces a `CERT-001` alert because `lookalike-example.net` is not
covered by the configured organization DNS namespace. Use
`examples/events/known-domain-issued.json` to exercise the no-alert path.

## Repository map

- `docs/architecture/`: Council reviews and architecture decision records
- `docs/project/`: PRD, HLD, LLD, traceability, assurance, roadmap, and evidence pack
- `docs/threat-model/`: security boundaries, threats, and mitigations
- `schemas/`: versioned JSON Schema Draft 2020-12 contracts
- `rules/`: machine-readable detection metadata
- `src/crypto_control_plane/`: validated pipeline implementation
- `examples/ct/pages/`: provider-neutral decoded CT pages for offline testing
- `examples/migration/`: fictional enterprise migration-planning data
- `docs/soc-playbooks/`: analyst response procedures
- `tests/`: unit and integration-style vertical-slice tests
- `examples/`: safe local fixtures and policy

## Evidence maturity

Every event, inventory record, and assessment carries one evidence level:

| Level | Meaning |
|---|---|
| `simulated` | Hand-authored scenario; logic demonstration only |
| `generated` | Locally generated cryptographic artifact |
| `public-observation` | Publicly observable evidence with limited ownership context |
| `sanitised-capture` | Explicitly sanitised sample from a controlled environment |
| `authenticated-production` | Authenticated, authorised production collector evidence |
| `independently-verified` | Evidence confirmed through an independent source or control |

Known local collectors have an allowlist of evidence levels. Fixtures cannot be
relabeled as production. The high-assurance levels are reserved and rejected at
runtime until an authenticated collector trust registry exists. The current
repository produces only `simulated` and `generated` evidence.

## Milestone 4: controlled discovery lab

All milestones remain a local reference implementation. Milestone 4 adds:

1. A generated RSA/ECDSA X.509 estate with valid, expired, future-validity,
   CA, end-entity, and no-SAN scenarios.
2. Real PEM/DER parsing for fingerprints, serials, identities, validity,
   public-key algorithms, signature algorithms, key usages, and EKUs.
3. An evidence-maturity contract propagated through events, inventory records,
   assessments, alerts, and durable state.
4. A bounded loopback-only TLS probe that records TLS version and cipher suite
   but leaves negotiated key establishment `null` when it is not evidenced.
5. Golden scenario expectations and adversarial tests for malformed artifacts,
   unsupported claims, non-loopback targets, and fixture evidence escalation.
6. A file-based lab CLI for generated or sanitised certificates.
7. PyCA `cryptography` pinned at 50.0.2 for Python 3.11 through 3.13.

The CT fixture contract is intentionally provider-neutral and is **not** an RFC
6962 or RFC 9162 wire response. A live adapter must separately implement and
test source authentication, TLS, timeouts, bounded downloads, pagination,
backoff, log-list trust, parsing, and proof verification as applicable.

Milestone 5 implements the fictional-catalogue, workflow, and separate-metrics
gates that were identified by this laboratory milestone.

## Milestone 5: migration management domain

Milestone 5 adds a deterministic, non-executing migration-management layer:

1. A six-service fictional enterprise catalogue with owners, assets, suppliers,
   data classifications, protection lifetimes, cryptographic uses, and
   dependencies.
2. A dependency graph that fails closed on unknown references, self-dependency,
   cycles, duplicate identities, and conflicting asset ownership.
3. Function-specific target validation: ML-KEM or hybrid for key establishment;
   ML-DSA, SLH-DSA, or hybrid for signature/authentication uses.
4. Deterministic priorities and waves that preserve missing context and missing
   evidence as unassigned work.
5. Versioned work items, human decision records, time-bounded exceptions, and
   independent verification records.
6. Guards against self-approval, stale decisions, expired exceptions, target
   mismatch, incomplete test evidence, and non-independent verification.
7. Separate discovery coverage and migration-progress measures. The fictional
   baseline reports 83.33% simulated discovery coverage and 0% verified
   migration; neither is a production claim.

No workflow method performs a production change. Implementation occurs in an
external controlled change process, and a work item becomes `verified` only
after all approved criteria pass with pre-change and post-change evidence.

Recommended next gates are:

1. Add observation-to-catalogue reconciliation with conflict lineage.
2. Create a signed offline evidence bundle and sanitisation workflow.
3. Add local graph and portfolio reports without implying production coverage.
4. Obtain explicit authorisation before designing the first read-only pilot
   collector.

## Milestones 6 to 9: safe reference release

Version 0.9 adds executable foundations for the rest of the roadmap:

1. **Milestone 6 implemented locally:** multi-observation reconciliation with
   conflict lineage, sanitisation, CBOM-style and dependency exports, and
   Ed25519-signed offline bundles. Bundle integrity, signer trust, and evidence
   maturity remain separate.
2. **Milestone 7 reference gate:** a time-bounded, independently approved,
   read-only scope contract and denominator-based coverage report. The included
   demonstration is simulated; no real pilot has been authorised or run.
3. **Milestone 8 reference foundation:** tenant-scoped SQLite workflow state,
   optimistic version checks, role and separation-of-duties enforcement, audit,
   and transactional outbox records. This is not a production topology.
4. **Milestone 9 proposal boundary:** ticketing, CMDB, PKI, KMS/HSM, and
   deployment-evidence adapters can be represented as evidence-bound proposals.
   Issuance, revocation, rotation, deletion, deployment, trust changes, and
   generic execution are rejected.

The reference-release summary always reports `production_gates_passed: false`.

## Version 0.9.1: external reassessment remediation

The reproducible D1-D4 findings are remediated: matching current/target PQC
families enter verification instead of migration, Ed25519/Ed448/DSA are
classified as classical exposure, offline import recomputes evidence maturity,
and the named risk owner must approve an exception. D5 policy consolidation and
D6 standards-governance ownership remain open in
`docs/project/09-external-review-findings-register.md`.
Real Gate G3-G5 closure still requires external authorisation, authenticated
sources, privacy/security review, service operations, recovery and SLO evidence,
independent testing, and adapter-specific approval.
