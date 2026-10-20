# External Review Findings Register

## 1. Review position

This register records the disposition of the findings supplied in the external
reassessment dated 11 October 2026. It is implementation evidence for a work in
progress, not independent certification or production assurance.

## 2. Findings and disposition

| ID | Finding | Disposition | Implemented evidence | Verification evidence |
|---|---|---|---|---|
| D1 | Current PQC candidate was treated as urgent migration work | Remediated (two steps) | Step 1: matching current/target PQC family routes to `verify`, `verification`, `verification-required`. Step 2 (follow-up review, 20 Oct 2026): any use already protected by PQC or hybrid (`candidate-quantum-resistant`, `hybrid-unverified`) with a different target is `low`, `wave-3`, still approval-required, so it cannot take early-wave capacity from quantum-vulnerable uses. Exposure that contradicts the current algorithm family fails closed | `test_current_pqc_target_routes_to_verification_not_migration`; `test_different_pqc_target_requires_approval_at_low_priority`; `test_hybrid_use_with_pure_pqc_target_is_not_urgent`; `test_exposure_that_contradicts_algorithm_family_fails_closed` |
| D2 | EdDSA and DSA X.509 algorithms were unclassified | Remediated | Ed25519/Ed448 map to classical elliptic curve; DSA has a quantum-vulnerable family across code and schemas | `test_eddsa_and_dsa_certificates_are_classified_as_classical` |
| D3 | Re-signed self-signed bundle could inflate its evidence claim | Remediated | Import recomputes weakest enclosed evidence and rejects mismatches or enclosed high-assurance claims | `test_import_recomputes_and_rejects_inflated_evidence_claim` |
| D4 | Exception approver did not have to equal the named risk owner | Remediated (two steps) | Step 1: approver must equal the exception's `risk_owner_id`. Step 2 (follow-up review, 20 Oct 2026): step 1 was bypassable because the exception author chose `risk_owner_id`. The risk owner now comes from the catalogue service (`risk_owner_id`, an owner with role `risk-owner`, never the requester) and is copied into the work item (schema 1.1). An exception must name exactly that owner; a service with no catalogue risk owner cannot accept exceptions. Identities remain caller-declared until production identity (G4) | `test_exception_requires_named_risk_owner_approval`; `test_work_item_carries_catalogue_risk_owner`; `test_exception_cannot_self_nominate_a_risk_owner`; `test_exception_rejected_when_catalogue_names_no_risk_owner`; `test_catalogue_risk_owner_must_be_a_distinct_risk_owner_role` |
| D5 | Portfolio priority models may diverge and policy is hard-coded | Open design debt | No false claim of resolution; consolidate into a versioned policy service before production pilot decisions | Future policy-equivalence, versioning, approval, rollback, and migration tests |
| D6 | Standards roadmap needs an active governance process | Open governance item | Standards references remain informational; assign owner and review cadence before external pilot | Approved standards register, dated review evidence, and change-control record |

## 3. Acceptance boundary

The remediated findings are supported by local code and automated tests. They
do not close authenticated collector, production identity, multi-tenant
service, recovery, privacy, penetration-testing, or independent-assurance
gates. D5 and D6 remain open and must not be described as complete.
