# Requirements Traceability Matrix

## 1. Purpose

This matrix links requirements to design, implementation, and executable
verification. A row marked planned is a controlled gap, not evidence of
completion.

## 2. Implemented and partial requirements

| Requirement | Status | Design/code evidence | Test evidence |
|---|---|---|---|
| FR-001 Versioned validated observations | Implemented | `schemas/`, `SchemaRegistry`, `CertificateEvent` | `test_published_examples_conform_to_full_schemas`, `test_legacy_certificate_contract_requires_explicit_upgrade` |
| FR-002 Preserve provenance | Implemented for fixtures/lab | `CertificateEvent.provenance`, `CertificateTransparencyCollector` | `test_collects_pages_preserves_evidence_and_alerts` |
| FR-003 Reject changed-content replay | Implemented | `CollectorState.check_duplicate` | `test_replay_is_idempotent_and_emits_no_second_alert`, `test_source_identity_reuse_with_changed_content_fails_closed` |
| FR-004 Derive X.509 properties | Implemented in lab | `X509CertificateDiscovery` | `test_golden_generated_corpus`, RSA/ECDSA parameter test, EdDSA/DSA classification test |
| FR-005 Separate evidence domains | Partial | Optional event `transport`, inventory `transport_observation` | `test_loopback_probe_records_tls_without_inventing_key_establishment` |
| FR-006 Carry coverage limits | Implemented for certificate inventory | `PqcInventoryService._record` | `test_classical_certificate_is_quantum_vulnerable_and_high_priority` |
| FR-010 Stable linked inventory | Implemented | UUIDv5 record, observation ID | `test_assessment_is_deterministic`, CT collector tests |
| FR-011 Separate function and algorithm | Implemented for certificate uses | `cryptographic_use.function` and `.algorithm` | Inventory schema and inventory tests |
| FR-012 Identify classical exposure | Implemented | `QUANTUM_VULNERABLE`, assessment rules | Classical certificate priority and EdDSA/DSA classification tests |
| FR-013 PQC/hybrid requires verification | Implemented | Assessment findings PQC-005/PQC-006 | `test_pqc_algorithms_are_candidates_not_declared_safe`, `test_hybrid_label_requires_protocol_verification` |
| FR-014 Preserve unknown | Implemented | Assessment algorithm | `test_unknown_algorithm_never_becomes_quantum_safe` |
| FR-015 Block unsupported priority | Implemented | Missing-context and priority logic | `test_missing_business_context_blocks_prioritisation` |
| FR-016 Enterprise correlation | Implemented for local evidence and fictional catalogue | `EvidenceReconciler`, catalogue dependency validation | Reconciliation, conflict, unknown-dependency, and cycle tests |
| FR-020 Function-specific target state | Implemented for reference policy | Target compatibility in `MigrationPlanner` | `test_functionally_invalid_supported_target_is_blocked` |
| FR-021 Migration waves | Implemented for simulated catalogue | Deterministic priority, migration waves, and matching-target verification lane | Catalogue, current-target verification, and differing-target migration tests |
| FR-022 Governed work items | Partial local implementation | Versioned work-item contract and `MigrationWorkflow` | Planning, stale-decision, and verification tests |
| FR-023 Exceptions | Implemented locally | Separate expiry/risk-owner/compensating-control contract | Active, expired, and named-risk-owner approval tests |
| FR-024 Change approval/verification | Implemented locally without execution | Decision and verification contracts; separation checks | Self-approval, stale decision, and complete verification tests |
| FR-025 Regression detection | Implemented for local evidence | Failed verification produces `regressed`; reconciliation preserves contradictory post-change states | Verification and reconciliation tests |
| FR-026 Coverage reporting | Implemented for explicit catalogue scope | Separate coverage/progress report | `test_coverage_and_migration_progress_are_separate` |
| FR-030 Deterministic detection | Implemented | `CertificateMonitoringPipeline` | Pipeline test suite |
| FR-031 Evidence-linked explanation | Partial | Deterministic explanation and alert evidence | `test_unknown_domain_produces_high_severity_alert` |
| FR-032 AI cannot change decisions | Implemented structurally | No model call; explainer receives decided result | Determinism and alert schema tests |
| NFR-001 Fail closed | Implemented for local interfaces | Exact-key/domain/schema validation | Invalid fingerprint, timestamp, field, wildcard, file-size, and malformed-certificate tests |
| NFR-002 Auditability | Partial | Provenance, policy version, deterministic IDs, SQLite state | CT collection and deterministic-ID tests |
| NFR-006 Portable contracts | Implemented | JSON Schema Draft 2020-12 | Full-schema tests |
| NFR-007 Reproducible assessment | Implemented | Deterministic rules | `test_assessment_is_deterministic`, `test_alert_identifier_is_deterministic` |
| FR-033 Controlled delivery | Partial local reference | Transactional SQLite audit and outbox; proposal-only adapters | Control-plane transaction and proposal tests |
| NFR-005 Isolation | Partial local reference | Tenant-qualified storage, role and separation checks | Tenant, role, self-approval, and stale-version tests |
| NFR-008 Testability | Implemented for current scope | `tests/` | 80 automated tests |

## 3. Planned requirements and required proof

| Requirement | Status | Required implementation evidence | Required acceptance evidence |
|---|---|---|---|
| FR-007 Multi-source collectors | Planned | Authenticated source adapters and conformance kit | Authorised integration tests; reconciliation and coverage report |
| NFR-003 Privacy | Planned beyond local use | Data classification, encryption, redaction, retention | Privacy review and access-control tests |
| NFR-004 Availability | Planned | Service SLOs, queueing, recovery design | Load, failover, restore, and game-day evidence |
| NFR-009 Scalability | Planned | Distributed deployment and partition model | Representative performance and capacity results |
| NFR-010 Accessibility | Planned | User research and accessible UI | Accessibility audit and task-completion study |

## 4. Security invariant traceability

| Invariant | Implementation | Evidence |
|---|---|---|
| Invalid input produces no alert | Validation precedes pipeline decision | Pipeline negative tests |
| Explanation cannot create/change alert | Decision calculated before explainer call | Pipeline structure and deterministic tests |
| DNS suffixes match label boundaries | `matches_policy` | Boundary and IDNA tests |
| Source identity cannot change bytes silently | Digest conflict check | CT provenance-conflict test |
| Unknown is never quantum-safe | Assessment decision order | Unknown and mixed-evidence tests |
| Observation/inventory/assessment commit together | SQLite transaction | CT persistence tests |
| Generated/fixture evidence cannot claim production | Evidence allowlist and reserved levels | Evidence escalation tests |
| TLS lab cannot reach external targets | Loopback IP validation | `test_loopback_probe_refuses_external_target` |
| Cipher/certificate does not invent KEM | Nullable transport field | Loopback TLS test |
| Dependency graph fails closed | Topological validation and identity checks | Cycle, unknown dependency, and conflicting ownership tests |
| Requester cannot self-approve | Version-bound workflow guard | Self-approval and stale-decision tests |
| Exceptions expire | Exception time and state validation | Active and expired exception tests |
| Verification requires independent pre/post evidence | Verification target, actor, criteria, and evidence gates | Complete/incomplete verification tests |
| Coverage is not completion | Separate report objects and percentages | Separate-metrics test |
| Conflicts are not silently resolved | Reconciliation lineage and conflict state | Roadmap reconciliation tests |
| Signing does not upgrade evidence | Separate evidence claim and signer trust | Bundle trust-boundary tests |
| Bundle manifest cannot inflate evidence | Import recomputes the weakest enclosed evidence level | Re-signed inflated-claim test |
| Bundle tampering fails closed | Manifest names, sizes, SHA-256, and Ed25519 | Bundle tamper test |
| Pilot scope is authorised and current | Read-only scope, expiry, independent approver | Pilot negative tests |
| Tenant data is isolated | Tenant-qualified storage and lookup | Tenant snapshot test |
| Workflow updates are versioned | Expected-version transition | Stale workflow test |
| Integrations cannot execute changes | Proposal schema and blocked mutation verbs | Integration proposal test |
| Current PQC target is verified, not re-migrated | Matching family routes to verification; differing family remains migration work | Matching and differing target tests |
| Named risk owner owns exception acceptance | Approver must equal risk-owner ID | Risk-owner mismatch test |

## 5. Traceability maintenance rule

A change is incomplete if it adds or materially changes a mandatory requirement
without updating:

1. its identifier and acceptance criterion;
2. the HLD/LLD or an ADR;
3. its contract and compatibility statement;
4. automated or manual verification evidence;
5. the known limitation or risk entry where applicable.

