# Threat model: Milestones 1 to 9 reference release

## Assets

- Integrity and provenance of certificate observations
- Organization DNS policy and ownership context
- Alert integrity, severity, evidence, and audit trail
- Collector checkpoints, idempotency records, and preserved raw observations
- Cryptographic inventory records, algorithm evidence, and PQC assessments
- Asset ownership, business criticality, classification, and protection lifetime
- Certificate metadata that may expose internal names or infrastructure
- Future credentials and cryptographic workflow authority (not present today)
- Evidence-maturity labels and the boundary between lab and production claims
- Local TLS target selection and parsed certificate artifacts
- Migration catalogue ownership, dependency, supplier, and target-state data
- Work-item versions, human decisions, exceptions, and verification evidence
- Separation between discovery coverage and verified migration progress

## Trust boundaries

```text
untrusted event / decoded CT fixture
       |
       v
full schema + domain validation ---- versioned policy file
       |
       v
provenance digest + SQLite evidence/idempotency/checkpoint state
       |
       v
deterministic detection/scoring
       |
       +----> advisory explanation (no decision authority)
       |
       v
inventory record + deterministic PQC assessment
       |
       v
catalogue + dependency validation
       |
       v
deterministic migration plan ----> human decision / time-bounded exception
       |                                      |
       |                                      v
       +----------------------------> external implementation
                                              |
                                              v
                                  independent verification evidence
```

Event, CT fixture, policy, SQLite, and JSONL files can be modified by a local
actor. The digest supports comparison but is not a signature or tamper-evident
audit record.

## Threats and current mitigations

| Threat | Impact | Current mitigation | Residual / future control |
|---|---|---|---|
| Forged event | False alert or concealed issuance | Strict shape/type/time validation; evidence fields retained | Authenticated collectors and signed provenance |
| Source ID reused with changed content | Evidence substitution | Stored digest comparison fails closed | Source authentication and tamper-evident log |
| Duplicate/replayed observation | Alert flooding | Durable source identity/digest idempotency | Distributed idempotency key and retention policy |
| Checkpoint loss or cycle | Missed data or infinite collection | SQLite checkpoints, page-completion updates, cursor-cycle and page limits | Replicated state, monitoring, recovery procedure |
| Policy tampering | Suppressed or flooded alerts | Policy is explicit and fail-closed on invalid data | Signed/versioned policy, change approval, independent ownership source |
| DNS normalization bypass | Unknown name treated as trusted | Lowercase, trailing-dot removal, IDNA normalization, wildcard restrictions, label-boundary suffix matching | Differential tests with production parser and public-suffix awareness |
| Replay/duplicate event | Alert flooding | Deterministic alert identifier | Durable deduplication store and replay window |
| Prompt/model manipulation | Misleading response or unsafe action | No model call; explanation cannot change detection/severity; no executor | Structured output validation, evaluation, isolation, human review |
| Sensitive-name leakage | Infrastructure disclosure | Local-only sink and minimal fields | Classification, redaction, encryption, tenant isolation, retention policy |
| Malicious JSON volume | Resource exhaustion | Bounded local CLI use only | Payload/field limits, streaming parser, quotas, backpressure |
| JSONL injection | Corrupted downstream parsing | One encoded JSON object per line | Authenticated structured transport and schema enforcement |
| Privilege creep | Unauthorized issuance/revocation/key action | No credentials, network calls, or action interfaces | Separate executor, least privilege, approvals, audit, rollback |
| Algorithm-label spoofing | False PQC-readiness claim | Closed algorithm family enum, OID shape validation, provenance retained | Parse signed source artifacts; independently verify implementations and chains |
| Classical EdDSA/DSA left unknown | Understated quantum exposure | Ed25519/Ed448 and DSA are explicitly classified as classical; DSA is in the quantum-vulnerable set | Maintain algorithm/OID conformance corpus |
| Missing coverage presented as safety | Unmanaged vulnerable cryptography remains hidden | Explicit `certificate-only` coverage and limitations; unknown stays unknown | Coverage metrics across network, code, cloud, PKI, KMS, and HSM collectors |
| Business-context poisoning | Incorrect migration order | Evidence fields remain separate from deterministic classification | Authoritative CMDB/owner sources, change approval, conflict handling |
| PQC or hybrid label treated as deployment proof | Premature completion claim | Status is `candidate-quantum-resistant` or `hybrid-unverified`, never safe/compliant | Protocol interoperability, chain, implementation, and relying-party verification |
| Sensitive inventory disclosure | Attacker gains infrastructure and dependency intelligence | Local-only reference storage | Encryption, tenant isolation, field-level authorization, audit, retention controls |
| Fixture promoted to production evidence | Test result presented as customer assurance | Known collectors have allowed evidence levels; fixture sources are simulation-only | Authenticated collector identity and signed evidence envelopes |
| Local TLS probe used for network scanning | Unauthorised access or SSRF-style reachability | IP literals only; loopback addresses only; bounded timeout; no redirect or credential support | Separate reviewed production collector with explicit scope and egress policy |
| Certificate parser resource abuse | Memory/CPU exhaustion or parser exploitation | One-megabyte input bound, pinned parser dependency, malformed input fails closed | Sandboxed parser service, quotas, dependency monitoring |
| TLS cipher label used as KEM proof | False conclusion about key establishment | Negotiated key establishment is explicitly `null` unless directly evidenced | Protocol-specific telemetry and independent handshake verification |
| Synthetic private key leakage | Lab key reused or mistaken for production material | Factory returns ephemeral, unencrypted keys only for local tests; artifacts labelled generated | Ephemeral storage, restrictive file mode, automated cleanup, never import into production stores |
| Fictional catalogue presented as enterprise truth | False assurance and wrong migration plan | Catalogue and report are `simulated`; high-assurance claims rejected | Authorised reconciliation against authenticated asset sources |
| Dependency graph poisoning or cycle | Unsafe ordering or planning deadlock | Unknown/self/duplicate dependencies and cycles fail closed | Authenticated sources, conflict lineage, graph-owner review |
| Conflicting ownership | Work routed to the wrong authority | Conflicting asset ownership fails closed | Authoritative ownership source and dispute workflow |
| Functionally wrong target | KEM used as signature target or signature scheme used for key establishment | Function-specific target allowlists; unsupported target blocks work | Versioned organisation policy and protocol-specific profiles |
| Self-approval or stale approval | Unauthorised or outdated migration decision | Requester cannot approve; decision binds exact object version | Identity provider, RBAC, dual control, signed audit event |
| Permanent, expired, or weakly authorised exception | Risk remains unmanaged | Separate exception contract, expiry, named risk-owner approval, compensating controls | Explicit delegated-authority contract, scheduled expiry enforcement and escalation |
| Weak verification represented as completion | False migration completion | Independent verifier, exact target match, all criteria pass, pre/post evidence required | Authenticated evidence sources and independent assurance sampling |
| Coverage conflated with completion | Misleading programme reporting | Separate report sections and percentages; no overall score | Portfolio governance review and metric definitions |

## Security invariants

1. Invalid events or policy fail closed and produce no alert output.
2. Explanations cannot create alerts or change rule results, severity, or score.
3. DNS suffix matching occurs only at label boundaries.
4. Alert identifiers are stable for the same event and rule.
5. The pipeline performs no network or cryptographic lifecycle side effects.
6. The same collector/source identity cannot be accepted with a different raw
   payload digest.
7. Checkpoints advance only after all entries on a validated page are recorded.
8. Missing algorithm evidence is `unknown`, never quantum-resistant by default.
9. PQC and hybrid observations require deployment verification and are not
   labelled compliant or safe solely from algorithm names.
10. Certificate evidence does not prove negotiated key establishment or complete
    enterprise cryptographic coverage.
11. Observation, inventory record, and PQC assessment are committed atomically.
12. Simulation and generated evidence cannot claim authenticated-production or
    independently-verified status; both high-assurance levels are runtime-
    disabled until an authenticated collector trust registry exists.
13. The lab TLS probe cannot connect to a non-loopback target.
14. Cipher-suite and certificate observations do not invent negotiated
    key-establishment evidence.
15. Catalogue evidence cannot claim a higher maturity than its source boundary.
16. Dependency cycles, unknown dependencies, duplicate identities, and
    conflicting asset ownership fail closed.
17. A requester cannot approve their own migration or exception.
18. Decisions, exceptions, and verification records bind to the exact current
    work-item version; stale records fail closed.
19. Exceptions are time bounded and require compensating controls.
20. `verified` requires independent pre/post evidence and every approved
    criterion to pass.
21. Discovery coverage and migration completion remain separate measures.
22. The migration workflow performs no production change.
23. A current PQC/hybrid family that matches its target requires verification,
    not a false urgent migration or an automatic completion claim.
24. Ed25519, Ed448, and DSA certificate evidence is classified as classical and
    quantum-vulnerable rather than left unknown.
25. Offline import recomputes the weakest enclosed evidence level and rejects a
    manifest mismatch, irrespective of a valid self-signature.
26. An exception approver must be the named risk owner until an explicit
    delegated-authority contract exists.

## Milestones 6 to 9 threat-model delta

### New assets

- reconciliation lineage and conflict state;
- offline bundle manifest, signature, public key, and sanitised artifacts;
- pilot authorisation, scope denominator, expiry, and stop conditions;
- tenant identifiers, workflow versions, audit events, and outbox records;
- integration proposals and evidence references.

### New threats and controls

| Threat | Required control |
|---|---|
| Conflict laundering | Retain every source record and label contradictory states; canonical selection is not truth resolution |
| Sanitisation interpreted as stronger evidence | Preserve the weakest enclosed evidence level and report sanitisation separately |
| Self-signed bundle treated as authenticated source | Verify integrity but report signer trust separately; no automatic evidence upgrade |
| Bundle artifact tampering | Verify exact manifest names, canonical sizes, SHA-256 digests, and Ed25519 signature |
| Re-signed evidence-claim inflation | Recompute weakest artifact evidence during import; reject manifest mismatch and enclosed high-assurance claims |
| Pilot scope creep or expired authority | Read-only authorisation, independent approver, explicit assets, validity window, and stop conditions |
| Cross-tenant object access | Tenant included in every workflow primary key and lookup |
| Lost update or replayed approval | Expected-version transition and audit/outbox event in one transaction |
| Self-approval or unauthorised role | Role gate plus requester/approver separation |
| Proposal mistaken for execution authority | Schema fixes status to approval-required and execution authority to none |
| Direct PKI/KMS/HSM mutation | Reject issue, revoke, rotate, delete, deploy, trust-change, and generic execute operations |

### Residual risk

The reference controls do not establish production identity assurance, database
row-level security, high availability, disaster recovery, secure key custody,
privacy compliance, connector credential safety, or external penetration-test
assurance. Those remain Gate G3-G5 evidence requirements.

## Out of scope

Production authentication/authorization, production multi-tenancy and service
availability, CA validation, CT wire parsing/proof verification, source
authentication, distributed event delivery, production SIEM authentication,
authoritative CMDB enrichment, Internet or enterprise-network scanning,
authenticated production discovery, non-certificate discovery, durable
multi-user operations, production approval identity, connector credentials,
and remediation/orchestration.
