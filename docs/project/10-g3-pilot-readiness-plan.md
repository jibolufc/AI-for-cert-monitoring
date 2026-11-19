# Gate G3 Pilot Readiness Plan

## Current decision

The project is approved to prepare for G3 using synthetic data only. Real-data
collection remains disabled. No customer, employer, CA, cloud-account, network,
certificate inventory, credential, or production endpoint is authorised by this
document or by the example readiness report.

The AWS implementation baseline is defined in
`infra/aws/g3-synthetic/template.json`. It reuses the existing VPC, requires two
verified private subnets and their route tables as deployment inputs, creates no
NAT gateway or public workload, and preserves `collection_execution_authority:
none`.

### Latest controlled test: 19 November 2026

The approved synthetic write, restore, negative real-data, and shutdown sequence
completed in `us-east-1`. The written and restored object hashes matched, the
real-data-labelled event was rejected before another object was written, and the
reviewed close-window change set returned the Lambda reserved concurrency to
zero. The final CloudFormation output was `SyntheticInvocationState: disabled`;
`CollectionExecutionAuthority` remained `none`.

The sanitised evidence record is
[`evidence/g3/2026-11-19-controlled-synthetic-test.json`](../../evidence/g3/2026-11-19-controlled-synthetic-test.json).
It demonstrates G3-C07 and G3-C08 only. The other six controls remain planned
because their minimum tests were not completed. Gate G3 therefore remains
`blocked`, with `g3_gate_passed: false`; the test is not authority to use real
data or perform cryptographic lifecycle operations.

The follow-up read-only evidence pass demonstrated G3-C01 workload identity,
G3-C02 least-privilege RBAC, G3-C03 private networking, G3-C04 encryption, and
G3-C06 central logging. Together with the controlled test evidence for G3-C07
and G3-C08, seven of eight controls are now demonstrated. G3-C05 secret
management is recorded as not applicable to the current secretless synthetic
workload. The synthetic control set therefore has zero remaining controls, but
`g3_gate_passed` remains false and `collection_execution_authority` remains
`none`. An authoritative review confirmed live log retention of one month,
matching the reviewed 30-day template, and a credential-free HTTP probe
confirmed the bucket's insecure-transport denial.

The sanitised follow-up record is
[`evidence/g3/2026-11-19-closure-readonly-observations.json`](../../evidence/g3/2026-11-19-closure-readonly-observations.json).
The reviewed closure sequence for the remaining controls is recorded in
[`infra/aws/g3-synthetic/closure-evidence-plan.json`](../../infra/aws/g3-synthetic/closure-evidence-plan.json).
The scoped G3-C05 decision, its conditions and mandatory reactivation triggers
are recorded in
[`docs/project/12-g3-c05-secrets-management-disposition.md`](12-g3-c05-secrets-management-disposition.md)
and
[`evidence/g3/2026-11-19-c05-not-applicable-decision.json`](../../evidence/g3/2026-11-19-c05-not-applicable-decision.json).
G4 preparation may proceed alongside that sequence, but it cannot waive or
replace any G3 evidence requirement.

## Required staging evidence

| ID | Control | Minimum evidence |
|---|---|---|
| G3-C01 | Workload identity | Identity design and test showing no long-lived embedded credential |
| G3-C02 | Least-privilege RBAC | Role matrix plus allowed/denied access test |
| G3-C03 | Private networking | Network diagram and egress/ingress policy test |
| G3-C04 | Encryption | Storage and transport configuration evidence |
| G3-C05 | Secret management | Secret lifecycle evidence, or an accountable not-applicable decision for a demonstrably secretless synthetic scope |
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

## AWS deployment evidence sequence

1. Capture the VPC resource map, NAT count, private subnet IDs, public-IP
   assignment state, and private route-table destinations.
2. Create and review a CloudFormation change set from the repository template.
3. Deploy only after the selected subnet and route-table IDs match step 1.
4. Run the positive synthetic write, restore, and negative real-data tests.
5. Export stack events, outputs, Lambda logs, S3 object metadata/version, IAM
   role policy, security-group rules, and endpoint route evidence.
6. Hash the evidence manifest and update controls individually; never mark a
   control demonstrated merely because the stack exists.
