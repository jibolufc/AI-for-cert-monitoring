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
| FR-004 Derive X.509 properties | Implemented in lab | `X509CertificateDiscovery` | `test_golden_generated_corpus`, `test_rsa_and_ecdsa_parameters_are_derived_from_certificate` |
| FR-005 Separate evidence domains | Partial | Optional event `transport`, inventory `transport_observation` | `test_loopback_probe_records_tls_without_inventing_key_establishment` |
| FR-006 Carry coverage limits | Implemented for certificate inventory | `PqcInventoryService._record` | `test_classical_certificate_is_quantum_vulnerable_and_high_priority` |
| FR-010 Stable linked inventory | Implemented | UUIDv5 record, observation ID | `test_assessment_is_deterministic`, CT collector tests |
| FR-011 Separate function and algorithm | Implemented for certificate uses | `cryptographic_use.function` and `.algorithm` | Inventory schema and inventory tests |
| FR-012 Identify classical exposure | Implemented | `QUANTUM_VULNERABLE`, assessment rules | `test_classical_certificate_is_quantum_vulnerable_and_high_priority` |
| FR-013 PQC/hybrid requires verification | Implemented | Assessment findings PQC-005/PQC-006 | `test_pqc_algorithms_are_candidates_not_declared_safe`, `test_hybrid_label_requires_protocol_verification` |
| FR-014 Preserve unknown | Implemented | Assessment algorithm | `test_unknown_algorithm_never_becomes_quantum_safe` |
| FR-015 Block unsupported priority | Implemented | Missing-context and priority logic | `test_missing_business_context_blocks_prioritisation` |
| FR-030 Deterministic detection | Implemented | `CertificateMonitoringPipeline` | Pipeline test suite |
| FR-031 Evidence-linked explanation | Partial | Deterministic explanation and alert evidence | `test_unknown_domain_produces_high_severity_alert` |
| FR-032 AI cannot change decisions | Implemented structurally | No model call; explainer receives decided result | Determinism and alert schema tests |
| NFR-001 Fail closed | Implemented for local interfaces | Exact-key/domain/schema validation | Invalid fingerprint, timestamp, field, wildcard, file-size, and malformed-certificate tests |
| NFR-002 Auditability | Partial | Provenance, policy version, deterministic IDs, SQLite state | CT collection and deterministic-ID tests |
| NFR-006 Portable contracts | Implemented | JSON Schema Draft 2020-12 | Full-schema tests |
| NFR-007 Reproducible assessment | Implemented | Deterministic rules | `test_assessment_is_deterministic`, `test_alert_identifier_is_deterministic` |
| NFR-008 Testability | Implemented for current scope | `tests/` | 46 automated tests |

## 3. Planned requirements and required proof

| Requirement | Status | Required implementation evidence | Required acceptance evidence |
|---|---|---|---|
| FR-007 Multi-source collectors | Planned | Authenticated source adapters and conformance kit | Authorised integration tests; reconciliation and coverage report |
| FR-016 Enterprise correlation | Planned | Catalogue and dependency graph contracts | Known-estate fixture plus conflict/cycle tests |
| FR-020 Function-specific target state | Planned | Target-policy contract and compatibility rules | Approved scenario decisions and protocol tests |
| FR-021 Migration waves | Planned | Prioritisation and wave planner | Deterministic scenario outcomes and owner review |
| FR-022 Governed work items | Planned | Workflow state machine and RBAC | Positive/negative transition tests and audit export |
| FR-023 Exceptions | Planned | Expiry, approver, rationale, compensating controls | Expiry and unauthorised-approval tests |
| FR-024 Change approval/verification | Planned | Decision and verification records | Separation-of-duties and stale-version tests |
| FR-025 Regression detection | Planned | Post-change reconciliation | Controlled before/after scenario |
| FR-026 Coverage reporting | Planned | Authoritative scope denominator and status model | Reconciled pilot coverage sample |
| FR-033 Controlled delivery | Planned | Transactional outbox and authenticated adapter | Failure/retry/idempotency tests |
| NFR-003 Privacy | Planned beyond local use | Data classification, encryption, redaction, retention | Privacy review and access-control tests |
| NFR-004 Availability | Planned | Service SLOs, queueing, recovery design | Load, failover, restore, and game-day evidence |
| NFR-005 Isolation | Planned | Service identities and privilege boundaries | Architecture review and abuse-case tests |
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

## 5. Traceability maintenance rule

A change is incomplete if it adds or materially changes a mandatory requirement
without updating:

1. its identifier and acceptance criterion;
2. the HLD/LLD or an ADR;
3. its contract and compatibility statement;
4. automated or manual verification evidence;
5. the known limitation or risk entry where applicable.

