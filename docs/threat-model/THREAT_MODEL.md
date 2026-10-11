# Threat model: Milestones 1 to 4

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
local JSONL/file sink ----> human SOC / migration review
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
| Missing coverage presented as safety | Unmanaged vulnerable cryptography remains hidden | Explicit `certificate-only` coverage and limitations; unknown stays unknown | Coverage metrics across network, code, cloud, PKI, KMS, and HSM collectors |
| Business-context poisoning | Incorrect migration order | Evidence fields remain separate from deterministic classification | Authoritative CMDB/owner sources, change approval, conflict handling |
| PQC or hybrid label treated as deployment proof | Premature completion claim | Status is `candidate-quantum-resistant` or `hybrid-unverified`, never safe/compliant | Protocol interoperability, chain, implementation, and relying-party verification |
| Sensitive inventory disclosure | Attacker gains infrastructure and dependency intelligence | Local-only reference storage | Encryption, tenant isolation, field-level authorization, audit, retention controls |
| Fixture promoted to production evidence | Test result presented as customer assurance | Known collectors have allowed evidence levels; fixture sources are simulation-only | Authenticated collector identity and signed evidence envelopes |
| Local TLS probe used for network scanning | Unauthorised access or SSRF-style reachability | IP literals only; loopback addresses only; bounded timeout; no redirect or credential support | Separate reviewed production collector with explicit scope and egress policy |
| Certificate parser resource abuse | Memory/CPU exhaustion or parser exploitation | One-megabyte input bound, pinned parser dependency, malformed input fails closed | Sandboxed parser service, quotas, dependency monitoring |
| TLS cipher label used as KEM proof | False conclusion about key establishment | Negotiated key establishment is explicitly `null` unless directly evidenced | Protocol-specific telemetry and independent handshake verification |
| Synthetic private key leakage | Lab key reused or mistaken for production material | Factory returns ephemeral, unencrypted keys only for local tests; artifacts labelled generated | Ephemeral storage, restrictive file mode, automated cleanup, never import into production stores |

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

## Out of scope

Production authentication/authorization, multi-tenancy, service availability,
live X.509 parsing, CA validation, CT wire parsing/proof verification, source
authentication, distributed event delivery, transactional SIEM outbox,
production SIEM authentication, authoritative CMDB enrichment, dependency-graph
resolution, Internet or enterprise-network scanning, authenticated production
discovery, non-certificate discovery, and remediation/orchestration.
