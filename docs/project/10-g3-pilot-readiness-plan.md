# Gate G3 Pilot Readiness Plan

## Current decision

The project is approved to prepare for G3 using synthetic data only. Real-data
collection remains disabled. No customer, employer, CA, cloud-account, network,
certificate inventory, credential, or production endpoint is authorised by this
document or by the example readiness report.

## Required staging evidence

| ID | Control | Minimum evidence |
|---|---|---|
| G3-C01 | Workload identity | Identity design and test showing no long-lived embedded credential |
| G3-C02 | Least-privilege RBAC | Role matrix plus allowed/denied access test |
| G3-C03 | Private networking | Network diagram and egress/ingress policy test |
| G3-C04 | Encryption | Storage and transport configuration evidence |
| G3-C05 | Secret management | Secret lifecycle and access-log evidence using synthetic secrets |
| G3-C06 | Central logging | Tamper-resistant log destination and correlation test |
| G3-C07 | Deployment controls | Reviewed build/deploy evidence, pinned inputs, and rollback procedure |
| G3-C08 | Backup and restore | Successful synthetic restore with measured recovery time |

The included example leaves these controls at `planned` with no evidence. A
synthetic deployment must change each status only after attaching a hash, run
identifier, immutable log reference, or approved record.

## Real-pilot entry checklist

Before any real data is enabled, record all of the following:

1. Named data owner and written authorisation reference.
2. One named, authenticated, read-only source.
3. Explicit asset identifiers forming the coverage denominator.
4. Valid-from and expiry timestamps.
5. Data classification, purpose, minimisation, retention, and deletion method.
6. Approved privacy and security reviews.
7. Independent requester and approver identities.
8. Owned stop triggers and tested stop actions.
9. Confirmation that issuance, revocation, rotation, deletion, deployment,
   trust changes, and generic execution are prohibited.
10. A separate accountable G3 decision recorded outside the readiness tool.

## Stop procedure

Stop collection immediately on an out-of-scope record, unexpected personal or
secret data, failed source authentication, evidence-integrity failure, attempted
mutation, unapproved egress, scope change, or expired authority. Disable the
collector identity, preserve minimal audit evidence, notify the named owner, and
do not resume until a new or amended approval is recorded.

## Run the synthetic assessment

```bash
.venv/bin/python -m crypto_control_plane.g3_readiness_cli \
  --plan examples/g3/synthetic-readiness-plan.json \
  --output build/g3/readiness-report.json \
  --as-of 2026-10-18T12:00:00Z
```

Current expected status: `blocked`, with eight controls remaining. After real
synthetic-environment evidence is attached for all eight controls, the status
may become `synthetic-staging-ready`. Every report must still show
`g3_gate_passed: false` and `collection_execution_authority: none`.

## Remaining external decisions

- cloud provider, account, region, budget owner, and teardown owner;
- production identity and logging destinations;
- the authorised source, asset denominator, and data owner;
- privacy, security, legal, and operational acceptance as applicable;
- independent validation and final accountable G3 decision.
