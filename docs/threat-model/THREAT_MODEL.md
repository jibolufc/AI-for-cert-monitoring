# Threat model: Milestone 1

## Assets

- Integrity and provenance of certificate observations
- Organization DNS policy and ownership context
- Alert integrity, severity, evidence, and audit trail
- Certificate metadata that may expose internal names or infrastructure
- Future credentials and cryptographic workflow authority (not present today)

## Trust boundaries

```text
untrusted event file
       |
       v
validation + normalization ---- trusted policy file
       |
       v
deterministic detection/scoring
       |
       +----> advisory explanation (no decision authority)
       |
       v
local JSONL sink ----> human SOC review
```

Both event and policy files can be modified by a local actor in this milestone.
The output is evidence for testing, not a tamper-evident audit record.

## Threats and current mitigations

| Threat | Impact | Current mitigation | Residual / future control |
|---|---|---|---|
| Forged event | False alert or concealed issuance | Strict shape/type/time validation; evidence fields retained | Authenticated collectors and signed provenance |
| Policy tampering | Suppressed or flooded alerts | Policy is explicit and fail-closed on invalid data | Signed/versioned policy, change approval, independent ownership source |
| DNS normalization bypass | Unknown name treated as trusted | Lowercase, trailing-dot removal, IDNA normalization, wildcard restrictions, label-boundary suffix matching | Differential tests with production parser and public-suffix awareness |
| Replay/duplicate event | Alert flooding | Deterministic alert identifier | Durable deduplication store and replay window |
| Prompt/model manipulation | Misleading response or unsafe action | No model call; explanation cannot change detection/severity; no executor | Structured output validation, evaluation, isolation, human review |
| Sensitive-name leakage | Infrastructure disclosure | Local-only sink and minimal fields | Classification, redaction, encryption, tenant isolation, retention policy |
| Malicious JSON volume | Resource exhaustion | Bounded local CLI use only | Payload/field limits, streaming parser, quotas, backpressure |
| JSONL injection | Corrupted downstream parsing | One encoded JSON object per line | Authenticated structured transport and schema enforcement |
| Privilege creep | Unauthorized issuance/revocation/key action | No credentials, network calls, or action interfaces | Separate executor, least privilege, approvals, audit, rollback |

## Security invariants

1. Invalid events or policy fail closed and produce no alert output.
2. Explanations cannot create alerts or change rule results, severity, or score.
3. DNS suffix matching occurs only at label boundaries.
4. Alert identifiers are stable for the same event and rule.
5. The pipeline performs no network or cryptographic lifecycle side effects.

## Out of scope

Production authentication/authorization, multi-tenancy, service availability,
live X.509 parsing, CA validation, CT proof verification, distributed event
delivery, production SIEM authentication, and remediation/orchestration.
