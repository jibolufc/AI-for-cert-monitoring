# Verification and Validation Plan

## 1. Objective

Verification asks whether the system was built according to its requirements
and design. Validation asks whether it is suitable for the intended user and
operational problem. The current repository provides substantial verification
for a local reference slice and limited validation of the broader product need.

## 2. Test levels

| Level | Purpose | Current evidence |
|---|---|---|
| Contract | Reject malformed or incompatible data | Full JSON Schema and domain tests |
| Unit | Verify normalisation, decisions, mappings, and failure rules | Python `unittest` suite |
| Component | Exercise collector, state, inventory, parser, and CLI boundaries | CT, inventory, discovery tests |
| Integration | Exercise multi-module local paths | Fixture-to-state/alert/inventory tests |
| Cryptographic artifact | Parse real generated PEM/DER certificates | Golden X.509 corpus |
| Protocol | Observe a real bounded TLS handshake | Loopback TLS test |
| Security negative | Demonstrate refusal and fail-closed properties | Oversize, malformed, replay conflict, evidence escalation, external target tests |
| System/operational | Validate deployed service behavior | Not yet available |
| User acceptance | Validate analyst and migration-owner workflows | Not yet available |
| Independent assurance | External review or penetration test | Not yet available |

## 3. Current automated acceptance suite

The baseline has 61 tests covering:

- schema and format conformance;
- DNS policy normalisation and boundary behavior;
- deterministic alerts and assessments;
- invalid-input rejection;
- CT pagination, checkpoint restart, replay, provenance conflict, and size bounds;
- inventory classification, unknown handling, hybrid/PQC verification status,
  missing business context, and function correctness;
- real generated RSA/ECDSA X.509 parsing;
- validity, CA, SAN/no-SAN, PEM/DER, malformed, and oversized cases;
- evidence-maturity enforcement;
- loopback TLS observation and non-loopback refusal;
- CLI output bundles.
- fictional catalogue, ownership, dependency, target, priority, wave, decision,
  exception, verification, and separate-metric behavior.

Supported verification environments are Python 3.11-3.13 in project metadata
and CI intent. The latest local evidence records complete passing runs on Python
3.12 and 3.13. A clean run should be attached to every release candidate.

## 4. Reproduction procedure

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e .
.venv/bin/python -m unittest discover -s tests -v
git diff --check
```

Record:

- commit SHA and branch;
- operating system and Python version;
- dependency resolution or lock evidence;
- start/end time;
- passed, failed, errored, and skipped counts;
- complete failure output;
- reviewer identity where evidence is used for a gate.

## 5. Golden-scenario validation

`examples/lab/scenarios.json` is the controlled expected-result manifest.
Changes require review because a changed expectation can hide a regression.
Golden scenarios must include at least:

- RSA 2048 valid end entity;
- ECDSA P-256 valid end entity;
- RSA 3072 expired certificate;
- ECDSA P-384 not-yet-valid certificate;
- RSA 4096 CA without SAN.

Future migration scenarios should add services, owners, data lifetimes,
dependencies, target states, blockers, exceptions, and expected wave outcomes.

## 6. Production-readiness validation gates

### Gate A: authenticated pilot intake

- Written authorisation and target scope.
- Collector identity bound to tenant and source.
- TLS and credential handling reviewed.
- Bounded collection, timeout, retry, and stop controls tested.
- Raw evidence protected and retention approved.
- Coverage denominator supplied by an authoritative source.

### Gate B: inventory quality

- Sample records independently compared with source systems.
- False merge and missed merge rates measured.
- Unknown and stale evidence rates reported.
- Asset, owner, and dependency conflicts remain visible.
- No unsupported completeness claim.

### Gate C: migration workflow

- Role and separation-of-duties matrix approved.
- State transitions and stale-write prevention tested.
- Exception expiry and escalation demonstrated.
- Before/after verification and regression paths exercised.
- Audit export reviewed by a non-developer stakeholder.

### Gate D: production service

- Threat model and data-protection assessment updated.
- Dependency and container scanning completed.
- Penetration test findings resolved or accepted.
- Backup restore, failover, and incident runbooks exercised.
- Monitoring, on-call ownership, SLOs, and support model approved.

### Gate E: optional execution

- Business need proves that integrated execution is preferable to an external
  change system.
- Narrow adapter design and environment boundaries approved.
- Dual control, just-in-time access, dry run, rollback, and kill switch tested.
- Analysis and AI services have no access to execution credentials.
- Independent security approval obtained.

## 7. Test data strategy

Use data in increasing order of assurance:

1. Hand-authored simulated fixtures for rule edge cases.
2. Generated cryptographic artifacts for parser and protocol behavior.
3. Explicitly sanitised captures for realistic variation.
4. Authenticated production observations in an authorised pilot.
5. Independently verified samples for assurance measurement.

Never relabel a lower level. Sanitisation must preserve the property under test,
remove secrets and unauthorised identifiers, document transformations, and
retain source approval outside the repository.

## 8. Milestone 5 verification result

1. Fictional enterprise catalogue and dependency graph contracts validate.
2. Migration work, decision, exception, and verification contracts validate.
3. Deterministic wave assignment handles required context and unknowns.
4. Cycles, conflicting ownership, unsupported targets, stale decisions, expired
   exceptions, and missing verification fail safely.
5. Coverage and migration completion are reported separately.
6. Existing tests remain passing and the new requirements have tests.
7. ADR, threat model, PRD, LLD, and traceability matrix are updated.

