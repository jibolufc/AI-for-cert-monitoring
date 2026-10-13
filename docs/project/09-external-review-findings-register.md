# External Review Findings Register

## 1. Review position

This register records the disposition of the findings supplied in the external
reassessment dated 11 October 2026. It is implementation evidence for a work in
progress, not independent certification or production assurance.

## 2. Findings and disposition

| ID | Finding | Disposition | Implemented evidence | Verification evidence |
|---|---|---|---|---|
| D1 | Current PQC candidate was treated as urgent migration work | Remediated | Matching current/target PQC family routes to `verify`, `verification`, and `verification-required`; differing targets still require approval | `test_current_pqc_target_routes_to_verification_not_migration`; `test_different_pqc_target_still_requires_migration_approval` |
| D2 | EdDSA and DSA X.509 algorithms were unclassified | Remediated | Ed25519/Ed448 map to classical elliptic curve; DSA has a quantum-vulnerable family across code and schemas | `test_eddsa_and_dsa_certificates_are_classified_as_classical` |
| D3 | Re-signed self-signed bundle could inflate its evidence claim | Remediated | Import recomputes weakest enclosed evidence and rejects mismatches or enclosed high-assurance claims | `test_import_recomputes_and_rejects_inflated_evidence_claim` |
| D4 | Exception approver did not have to equal the named risk owner | Remediated for current contract | The named risk owner must approve; implicit delegation is rejected | `test_exception_requires_named_risk_owner_approval` |
| D5 | Portfolio priority models may diverge and policy is hard-coded | Open design debt | No false claim of resolution; consolidate into a versioned policy service before production pilot decisions | Future policy-equivalence, versioning, approval, rollback, and migration tests |
| D6 | Standards roadmap needs an active governance process | Open governance item | Standards references remain informational; assign owner and review cadence before external pilot | Approved standards register, dated review evidence, and change-control record |

## 3. Acceptance boundary

The remediated findings are supported by local code and automated tests. They
do not close authenticated collector, production identity, multi-tenant
service, recovery, privacy, penetration-testing, or independent-assurance
gates. D5 and D6 remain open and must not be described as complete.
