# Security, Risk and Assurance Plan

## 1. Assurance position

The current implementation demonstrates controlled engineering properties. It
does not demonstrate production security, full discovery coverage, compliance,
or successful migration of a real organisation.

Permitted current claims:

- versioned evidence and assessment contracts exist;
- deterministic reference rules are executable and tested;
- generated X.509 artifacts are parsed using a real cryptographic library;
- replay, conflict, evidence escalation, malformed input, and external target
  refusal have automated tests;
- current limitations are documented.

Prohibited current claims:

- the product has discovered an enterprise estate;
- a customer or organisation is quantum-safe;
- the product validates complete TLS or PKI security;
- the product is certified, independently audited, or production hardened;
- its AI autonomously manages cryptography;
- its current evidence is authenticated production evidence.

## 2. Assets requiring protection

- Source observations and their provenance.
- Cryptographic inventory and dependency intelligence.
- Asset identities, owners, classifications, and data lifetimes.
- Policies, assessments, migration targets, and exception records.
- Approval identities and audit history.
- Future collector and execution credentials.
- Availability and integrity of migration-status reporting.

## 3. Primary threat scenarios

| Scenario | Consequence | Current or required control |
|---|---|---|
| Forged or mislabelled evidence | Incorrect exposure or false completion | Strict contracts now; authenticated collector registry required |
| Missing source represented as complete coverage | Hidden vulnerable systems | Explicit coverage limits; authoritative denominator required |
| Correlation merges unrelated assets | Wrong owner or unsafe migration | Source lineage, conflict representation, review thresholds |
| Algorithm label represented as protocol proof | False PQC assurance | Function-specific evidence and verification-required states |
| Policy tampering | Suppressed work or manipulated priority | Version, approval, signature, effective date, rollback |
| AI prompt or evidence injection | Misleading advice or unsafe action | Treat output as untrusted; deterministic decisions; no credentials |
| Privilege convergence | One compromise can decide and execute | Separate collector, analysis, approval, and execution identities |
| Exception never expires | Permanent unmanaged exposure | Mandatory expiry, owner, approver, escalation, reporting |
| Sensitive inventory disclosure | High-value infrastructure intelligence leaks | Encryption, tenant isolation, field authorisation, redaction, audit |
| Dependency/supplier change | Verified item silently regresses | Continuous reconciliation and regression state |
| Parser or fixture resource abuse | Denial of service | Bounds now; sandbox, quota, and isolation required |
| Audit deletion or rewrite | Inability to prove decisions | Append-oriented records and tamper-evident external export |

The detailed repository threat model remains the authoritative technical threat
inventory for implemented milestones.

## 4. Control objectives

### Evidence trust

- Authenticate collector workload and source account.
- Bind evidence to tenant, collector, scope, time, and software version.
- Use digest/signature semantics accurately; a hash is not authentication.
- Prevent an unknown collector from self-asserting a high assurance level.
- Retain raw evidence or a defensible reference and transformation history.

### Decision integrity

- Version policy and record the exact version used.
- Make priority and transition gates deterministic.
- Require reasoned, named approval for exceptions and material changes.
- Prevent requesters from approving their own high-risk work.
- Reject decisions against stale object versions.

### AI governance

- Limit AI to evidence correlation, summarisation, drafting, and options.
- Require structured outputs with source references and confidence.
- Evaluate hallucination, omission, injection, and inconsistent recommendation.
- Never give a model direct CA, HSM, KMS, trust-store, or deployment authority.
- Log accepted, rejected, and edited recommendations for evaluation.

### Execution safety

- Prefer external change systems until integrated execution is justified.
- If added, isolate each adapter and environment.
- Use narrow, short-lived credentials and explicit approved change payloads.
- Provide dry-run, idempotency, rollback, rate limits, and a kill switch.
- Require independent post-change evidence before marking verified.

## 5. Risk register

| ID | Risk | Likelihood | Impact | Current disposition |
|---|---|---:|---:|---|
| R-001 | Lab success mistaken for production readiness | Medium | High | Mitigated by evidence levels and claim boundaries |
| R-002 | Certificate discovery misses non-certificate cryptography | High | High | Accepted for current scope; multi-source roadmap required |
| R-003 | Missing ownership blocks prioritisation | High | High | Explicitly blocks final priority; catalogue planned |
| R-004 | Dependency graph is incomplete or stale | High | High | Planned reconciliation and confidence model |
| R-005 | PQC support differs across protocol peers/products | High | High | Verification required; no algorithm-only completion |
| R-006 | SQLite/JSONL used beyond reference scale | Medium | High | Architecture limitation; replace before production |
| R-007 | Sensitive discovery data is exposed | Medium | High | Local-only now; privacy controls required before pilot |
| R-008 | AI scope expands into ungoverned automation | Medium | Critical | Explicit authority boundary and future approval gate |
| R-009 | Standards or supplier roadmaps change | High | Medium | Versioned policy, target state, and periodic review |
| R-010 | Documentation drifts from code | Medium | Medium | Traceability and release evidence review |

Risk owners, target dates, treatment cost, and residual ratings must be assigned
before an authorised pilot.

## 6. Assurance artefacts by gate

| Gate | Required evidence |
|---|---|
| Reference release | Source, schemas, tests, ADRs, threat model, traceability, reproducible run |
| Pilot approval | Scope/authorisation, data assessment, architecture review, operating model, rollback/stop procedure |
| Production approval | Secure build evidence, access model, pen test, recovery test, monitoring, incident plan, residual-risk acceptance |
| Migration completion | Approved target, change reference, interoperability tests, post-change discovery, independent verification where required |

## 7. Compliance mapping approach

Do not claim compliance from this repository alone. When a target organisation
and jurisdiction are known:

1. identify applicable obligations and internal control framework;
2. map control objectives to system capabilities and operating procedures;
3. record inherited, shared, and customer responsibilities;
4. attach objective evidence and test frequency;
5. identify gaps and approved remediation;
6. obtain qualified legal, compliance, and audit review where required.

## 8. Review cadence

- Every schema or security-boundary change: update LLD, traceability, and threat
  model in the same change.
- Every release: reproduce tests and archive the evidence manifest.
- Quarterly during development: review risk register and standards assumptions.
- Before each pilot or new source: perform source-specific threat modelling.
- Before execution capability: conduct an independent architecture and security
  review.

