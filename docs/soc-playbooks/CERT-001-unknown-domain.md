# SOC playbook: CERT-001 — certificate for an unknown DNS namespace

## Purpose

Investigate a certificate issuance event containing at least one DNS name that
does not match the approved organization namespace policy. A detection is not
proof of malicious issuance or domain ownership.

## Initial triage

1. Confirm the alert evidence, event identifier, source, observation time,
   certificate fingerprint, issuer, subject, and unmatched DNS names.
2. Validate the source independently. For public certificates, inspect the
   relevant Certificate Transparency evidence and certificate chain; do not
   rely solely on the alert explanation.
3. Check authoritative domain/asset ownership records, recent acquisitions,
   approved third-party services, and pending DNS or certificate requests.
4. Search for related certificates, DNS changes, TLS endpoints, account
   activity, and issuance events using the fingerprint, serial number, issuer,
   subject, and DNS names.
5. Determine whether the policy is stale, the event is malformed, the name is a
   legitimate external dependency, or the issuance is unauthorized.

## Escalation

- Escalate immediately for confirmed organization names issued by an unexpected
  CA, active impersonation, exposed services, compromised accounts, or evidence
  of unauthorized control.
- Engage PKI, DNS, cloud, identity, legal/brand, and incident-response owners as
  applicable.

## Containment and recovery

Do not revoke, replace, block, or modify DNS solely because this rule fired.
Use established incident and change procedures. If unauthorized issuance is
confirmed, coordinate CA/account containment, revocation where applicable,
credential rotation, DNS/service remediation, monitoring, and evidence
preservation with the responsible owners.

## Closure evidence

Record the ownership decision, authoritative sources checked, policy correction
if any, related indicators, actions/approvals, residual risk, and monitoring or
follow-up requirements.
