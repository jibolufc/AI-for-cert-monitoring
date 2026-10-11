# Project Evidence and Demonstration Guide

## 1. Claim being demonstrated

The repository is a working local reference implementation of an
evidence-backed cryptographic discovery and PQC assessment foundation. It
demonstrates deterministic certificate monitoring, replay-safe evidence intake,
certificate-focused inventory and assessment, real generated X.509 parsing,
and a bounded loopback TLS observation.

It does not demonstrate production estate coverage or completed PQC migration.

## 2. Evidence baseline

```bash
git log --oneline --decorate -5
git status --short --branch
git show --stat --oneline be71182
```

Expected milestone history:

```text
be71182 Build controlled cryptographic discovery lab
887fdb3 Build PQC inventory and exposure foundation
20e5705 Build trustworthy CT intake milestone
bfdc4ff Build initial certificate monitoring control plane
```

If the current commit differs, record it and review the delta instead of
assuming that this guide still describes the code exactly.

## 3. Environment setup

```bash
python3 --version
python3 -m venv .venv
.venv/bin/python -m pip install -e .
.venv/bin/python -m pip freeze
```

The repository currently pins `cryptography==50.0.2` and
`jsonschema[format-nongpl]==4.26.0`.

## 4. Automated proof

```bash
.venv/bin/python -m unittest discover -s tests -v
git diff --check
```

Expected baseline: 46 passing tests. Do not hide failures or skips. A platform
that prevents local socket creation may block the loopback test; run that test
in an authorised local or CI environment and record the constraint separately.

## 5. Demonstration A — deterministic certificate alert

```bash
.venv/bin/python -m crypto_control_plane.cli \
  --event examples/events/unknown-domain-issued.json \
  --policy examples/policy.json \
  --output build/alerts.jsonl
```

Review:

- rule ID `CERT-001`;
- unmatched name evidence;
- policy ID/version;
- deterministic severity, score, and alert ID;
- advisory explanation authority;
- source evidence and provenance.

Then run the known-domain example and confirm it produces no alert.

## 6. Demonstration B — replay-safe evidence intake

```bash
.venv/bin/python -m crypto_control_plane.ct_cli \
  --fixture-dir examples/ct/pages \
  --policy examples/policy.json \
  --state build/ct-state.sqlite \
  --output build/ct-alerts.jsonl
```

Run it a second time. The same source records should be duplicates and should
not produce duplicate alerts. The tests separately demonstrate failure when a
source identity is reused with changed content.

## 7. Demonstration C — PQC inventory assessment

```bash
.venv/bin/python -m crypto_control_plane.inventory_cli \
  --event examples/events/known-domain-issued.json \
  --output build/pqc-inventory-assessment.json
```

Review:

- evidence and observation linkage;
- cryptographic function and algorithm;
- certificate signature as a separate algorithm field;
- `certificate-only` coverage limitation;
- quantum-vulnerable classification for classical public-key evidence;
- missing context and verification requirements.

## 8. Demonstration D — real X.509 parsing

Use the test suite's generated certificate corpus or generate a synthetic
certificate through `SyntheticCertificateFactory`. Then run:

```bash
.venv/bin/python -m crypto_control_plane.discovery_lab_cli \
  --certificate /path/to/generated-certificate.pem \
  --evidence-level generated \
  --output build/x509-discovery-bundle.json
```

Review the derived fingerprint, public-key family/size or curve, signature
algorithm/OID/hash, validity, SAN, key usage, EKU, inventory record, and PQC
assessment. Confirm that an absolute input path is not leaked into evidence.

## 9. Demonstration E — security boundaries

The most efficient proof is to run the named tests:

```bash
.venv/bin/python -m unittest \
  tests.test_discovery_lab.DiscoveryLabTests.test_loopback_probe_refuses_external_target \
  tests.test_discovery_lab.DiscoveryLabTests.test_fixture_cannot_be_upgraded_to_production_evidence \
  tests.test_discovery_lab.DiscoveryLabTests.test_unknown_collector_cannot_claim_production_evidence \
  tests.test_ct_collector.CertificateTransparencyCollectorTests.test_source_identity_reuse_with_changed_content_fails_closed
```

These show that the implementation refuses external TLS targets, unsupported
evidence escalation, and provenance conflict.

## 10. Reviewer checklist

- [ ] Repository and commit identity recorded.
- [ ] Working tree state recorded.
- [ ] Dependency versions recorded.
- [ ] Complete tests executed and results retained.
- [ ] At least one positive and one no-alert scenario reproduced.
- [ ] Replay/idempotency behavior reproduced.
- [ ] Inventory and assessment output reviewed.
- [ ] Real X.509 parsing demonstrated.
- [ ] Security refusal cases demonstrated.
- [ ] PRD-to-test traceability sampled.
- [ ] Threat model and limitations reviewed.
- [ ] No production, certification, coverage, or migration-completion claim made
      without additional evidence.

## 11. Evidence manifest template

```text
Review date:
Reviewer:
Repository:
Branch:
Commit SHA:
Operating system:
Python version:
Dependency evidence:
Test result:
Skipped tests and reason:
Demonstrations completed:
Findings:
Known limitations accepted:
Decision: accept / accept with conditions / reject
Decision authority:
```

## 12. What proves the next stage

Milestone 5 should be considered proven only when fictional enterprise scenarios
can demonstrate:

- discovery records linked to owners and services;
- dependency-aware planning;
- explicit current and target states by cryptographic function;
- deterministic wave and blocker decisions;
- time-bounded exceptions and approval history;
- before/after verification evidence;
- separate coverage and migration metrics;
- safe handling of unknowns, conflicts, cycles, expiry, and regression.

