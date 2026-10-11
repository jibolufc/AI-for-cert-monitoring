# Product Requirements Document

## 1. Document control

| Field | Value |
|---|---|
| Product | AI-assisted Cryptographic Control Plane |
| Product version | 0.4.0 reference implementation |
| Document status | Baseline for review |
| Date | 2026-10-11 |
| Product owner | To be assigned |
| Technical owner | Repository owner |
| Implementation status | Milestones 1-4 implemented locally |

## 2. Product statement

The product is an evidence-backed cryptographic discovery and PQC migration
control plane. It collects bounded observations, normalises them into portable
contracts, creates a cryptographic inventory, classifies exposure using
deterministic policy, and will govern migration work through accountable human
decisions and verifiable completion evidence.

Certificate monitoring is the first sensor and reference vertical slice. It is
not the final product boundary.

## 3. Problem

PQC migration is not only an algorithm-replacement exercise. Organisations
need to know:

- where cryptography is used;
- which function each primitive performs;
- which assets, services, owners, data, suppliers, and relying parties depend
  on it;
- how reliable each observation is and what it does not prove;
- which systems require earlier action because protected data must remain
  confidential for a long period;
- whether products and protocols support an approved target state;
- how changes are approved, verified, rolled back, and evidenced.

Without those controls, an organisation can produce an inventory yet still be
unable to prioritise or prove a migration.

## 4. Standards context

The design uses the functional distinction established by the final NIST PQC
standards:

- FIPS 203 specifies ML-KEM for key establishment:
  <https://csrc.nist.gov/pubs/fips/203/final>
- FIPS 204 specifies ML-DSA for digital signatures:
  <https://csrc.nist.gov/pubs/fips/204/final>
- FIPS 205 specifies SLH-DSA for digital signatures:
  <https://csrc.nist.gov/pubs/fips/205/final>

NIST's PQC programme states that organisations should identify vulnerable
algorithm use and begin migration planning:
<https://csrc.nist.gov/projects/post-quantum-cryptography>

NIST IR 8547 is transition guidance and remains identified as an initial public
draft at this document date. Its proposed dates must therefore be treated as
planning inputs, not silently converted into universal legal deadlines:
<https://csrc.nist.gov/pubs/ir/8547/ipd>

## 5. Users and stakeholders

| Persona | Need |
|---|---|
| Cryptography or PKI lead | Evidence of algorithms, certificates, protocols, trust relationships, and migration state |
| Security architect | Dependency and target-state views with explicit assumptions |
| Asset or service owner | Assigned, understandable migration work and acceptance criteria |
| Risk and compliance reviewer | Traceable decisions, exceptions, approvals, evidence, and coverage gaps |
| SOC analyst | Actionable certificate anomalies with source evidence and playbooks |
| Platform or application engineer | Implementation-specific compatibility requirements and test results |
| Executive sponsor | Exposure, coverage, blockers, forecast, and residual-risk reporting |
| Auditor or independent reviewer | Immutable provenance, change history, control evidence, and reproducibility |

## 6. Goals

1. Build an evidence-backed, continuously reconcilable cryptographic inventory.
2. Preserve the distinction between observed fact, inference, recommendation,
   approval, execution, and verified outcome.
3. Prioritise PQC work using cryptographic exposure, data lifetime, business
   criticality, dependency, supplier, and readiness evidence.
4. Manage migration waves, blockers, exceptions, approvals, rollback criteria,
   and verification evidence.
5. Make coverage and unknowns visible rather than treating missing evidence as
   safety.
6. Keep AI advisory and bounded; deterministic policy and accountable humans
   retain authority for material decisions.

## 7. Non-goals

The current product is not:

- a certificate authority, KMS, HSM, secret manager, or trust store;
- an autonomous certificate or key lifecycle executor;
- a vulnerability scanner authorised to probe arbitrary networks;
- proof that any real organisation is quantum-safe;
- a replacement for protocol-specific interoperability testing;
- a compliance certification engine;
- a guarantee that every cryptographic use can be discovered automatically.

## 8. Product scope by capability

| Capability | Current state | Target state |
|---|---|---|
| Canonical certificate observations | Implemented | Multiple authenticated collectors |
| Schema and domain validation | Implemented | Contract compatibility and producer conformance programme |
| Certificate anomaly detection | Implemented | Governed rule catalogue and production SIEM delivery |
| Replay-safe fixture intake | Implemented | Distributed, authenticated intake with transactional delivery |
| Cryptographic inventory | Partially implemented | Multi-source CBOM with reconciliation and lineage |
| PQC exposure assessment | Partially implemented | Policy-versioned portfolio prioritisation |
| Real X.509 parsing | Implemented for controlled files | Sandboxed production parsing and chain verification |
| TLS evidence | Implemented for loopback lab | Authorised scoped collectors with protocol evidence |
| Dependency graph | Planned | Versioned service, protocol, supplier, and relying-party graph |
| Migration workflow | Planned | Waves, tasks, approvals, exceptions, rollback, verification |
| AI assistance | Deterministic explanation only | Evidence-grounded recommendation with evaluation and guardrails |
| Execution | Out of scope now | Optional isolated executor after governance gates |

## 9. Functional requirements

### Discovery and evidence

- **FR-001:** Accept only versioned, validated observation contracts.
- **FR-002:** Preserve source identity, collection time, payload digest,
  verification state, evidence level, and cursor where applicable.
- **FR-003:** Reject replay conflicts where a source identity is reused with
  different content.
- **FR-004:** Parse X.509 evidence to derive, not merely accept, algorithm and
  certificate properties.
- **FR-005:** Keep certificate, transport, code, key-store, and configuration
  observations distinct until correlation is supported by evidence.
- **FR-006:** Attach explicit scope and coverage limitations to inventory data.
- **FR-007:** Support future collectors for CT, TLS, cloud certificate managers,
  private PKI, KMS/HSM, code/configuration, and supplier evidence.

### Inventory and assessment

- **FR-010:** Create stable inventory records linked to their observations.
- **FR-011:** Represent cryptographic function separately from algorithm name.
- **FR-012:** Classify RSA, elliptic-curve, and finite-field public-key evidence
  as quantum-vulnerable for PQC planning.
- **FR-013:** Treat ML-KEM, ML-DSA, SLH-DSA, and hybrid labels as candidates
  requiring deployment and interoperability verification.
- **FR-014:** Preserve unknown values and prevent them from becoming safe
  defaults.
- **FR-015:** Block final migration priority when required business context is
  missing.
- **FR-016:** Correlate assets, services, owners, data lifetime, suppliers,
  dependencies, and cryptographic uses in the target product.

### Migration management

- **FR-020:** Define an approved target state per cryptographic function and
  protocol, not one universal replacement algorithm.
- **FR-021:** Group work into migration waves based on exposure, urgency,
  dependency order, readiness, and change risk.
- **FR-022:** Record owner, accountable approver, planned dates, blockers,
  dependencies, rollback criteria, and verification criteria.
- **FR-023:** Manage time-bounded exceptions with rationale, compensating
  controls, expiry, and named approval.
- **FR-024:** Require pre-change approval and post-change verification evidence
  for material migrations.
- **FR-025:** Reconcile post-change discovery against the approved target and
  detect regression.
- **FR-026:** Report coverage separately from migration completion.

### Detection and assistance

- **FR-030:** Evaluate security-critical detections and priority gates using
  deterministic, versioned policy.
- **FR-031:** Produce explanations linked to evidence and policy versions.
- **FR-032:** Prevent an AI component from silently changing evidence, severity,
  approval, or execution state.
- **FR-033:** Route alerts and workflow events to controlled downstream systems
  with delivery evidence in the target product.

## 10. Non-functional requirements

- **NFR-001 Security:** Fail closed for invalid contracts and unsupported
  evidence claims.
- **NFR-002 Auditability:** Every material conclusion must identify its input
  evidence, rule or model version, and decision actor.
- **NFR-003 Privacy:** Minimise, classify, redact, encrypt, and retain sensitive
  infrastructure metadata according to policy.
- **NFR-004 Availability:** The future service must define recovery objectives,
  backpressure, retry, and degradation modes before production use.
- **NFR-005 Isolation:** Collection, analysis, approval, and execution must have
  separate trust and privilege boundaries.
- **NFR-006 Portability:** External contracts use versioned JSON Schema; core
  decisions must not depend on a single vendor's data model.
- **NFR-007 Explainability:** Assessment outcomes must be reproducible without
  access to an LLM.
- **NFR-008 Testability:** Each mandatory requirement needs an objective
  acceptance test or an explicitly recorded evidence gap.
- **NFR-009 Scalability:** The target architecture must partition by tenant and
  source and support asynchronous processing; SQLite is not the scale design.
- **NFR-010 Accessibility:** Human workflows and reports must be usable without
  requiring cryptography-specialist knowledge for every field.

## 11. Success measures

The measures must never combine coverage and migration into one misleading
percentage.

| Measure | Definition |
|---|---|
| Discovery coverage | In-scope assets with at least one current observation divided by known in-scope assets |
| Context completeness | Inventory records with required owner, service, criticality, classification, and lifetime fields |
| Evidence maturity | Distribution of records by evidence level and verification state |
| Exposure backlog | In-scope quantum-vulnerable uses not yet assigned to an approved wave |
| Dependency readiness | Migration items whose blocking dependencies have an accepted target and tested path |
| Migration verified | Items with approved change, required tests, post-change evidence, and no unresolved regression |
| Exception health | Active, expired, and overdue exceptions by owner and risk |
| Detection quality | Validated true/false positive rates by rule and evidence source |

No production target is set until an authorised pilot establishes the asset
denominator, data quality, operating model, and acceptable error rates.

## 12. Acceptance criteria for the current reference release

1. All published example payloads conform to their schemas.
2. Invalid or unexpected event fields fail closed.
3. DNS matching is normalised and restricted to label boundaries.
4. Alert identifiers and PQC assessments are deterministic.
5. Fixture replay is idempotent and changed-content conflicts fail closed.
6. Source evidence, provenance, inventory, and assessment are linked.
7. Unknown algorithm evidence is never labelled quantum-resistant.
8. Generated X.509 certificates are parsed for RSA/ECDSA properties.
9. The lab TLS probe refuses non-loopback targets.
10. Transport evidence does not invent negotiated key establishment.
11. Fixtures and generated evidence cannot claim production assurance.
12. The complete automated test suite passes on the supported Python versions.

## 13. Dependencies and assumptions

- Python 3.11 or later.
- Pinned `jsonschema[format-nongpl]` and `cryptography` dependencies.
- The current repository operates locally and has no production credentials.
- Future production use assumes legal authorisation, collector identity,
  authoritative scope, secure hosting, operational ownership, and incident
  response.

## 14. Open product decisions

1. First authorised pilot source and accountable data owner.
2. Tenant and identity model.
3. Authoritative asset and ownership sources.
4. Workflow system of record and separation-of-duties model.
5. Policy ownership and exception authority.
6. Evidence retention, residency, and redaction rules.
7. Deployment model and service-level objectives.
8. Whether execution will remain external or use an isolated adapter.

