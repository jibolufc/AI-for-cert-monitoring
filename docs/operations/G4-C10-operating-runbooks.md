# G4-C10 Operating Runbooks and Support

## Control state

**Prepared, not demonstrated.** These runbooks preserve the current synthetic
boundary. They have not been exercised under an approved support model, and the
operations and security owners remain unassigned.

## Universal stop conditions

Stop the affected activity immediately if any of the following occurs:

- real, customer, employer, personal or secret data appears;
- an unapproved source, endpoint, credential, tenant or network path is used;
- evidence integrity, provenance or correlation fails;
- a requested operation could issue, revoke, rotate, delete, deploy or change trust;
- public or production traffic becomes enabled;
- the observed change set differs from the reviewed change set; or
- the operator cannot prove the current execution authority is `none`.

Stopping means disabling the bounded invocation or deployment path, preserving
minimal sanitised evidence, notifying the accountable owner when assigned and
not resuming without renewed approval.

## Deployment runbook

1. Confirm scope, branch, reviewed commit and test results.
2. Confirm synthetic data, private networking and authority flags remain unchanged.
3. Create a change set; do not execute a direct infrastructure mutation.
4. Review resource additions, replacements, IAM changes, cost and rollback impact.
5. Obtain execution approval separately from review approval.
6. Execute in the approved window and monitor stack events.
7. Verify outputs, concurrency lock, logs and evidence hashes.
8. Record the result without account-specific or secret values.

## Rollback runbook

1. Stop new invocations or traffic.
2. Capture the failing event, stack status and correlation identifiers.
3. Use the reviewed rollback or close-window change set.
4. Do not delete retained evidence to make rollback appear successful.
5. Verify the function is disabled and no unexpected resource remains active.
6. Record unresolved risk and require a new review before retry.

## Access runbook

1. Use the named operator identity with MFA; do not use root for routine work.
2. Use the dedicated CloudFormation service role and workload permissions boundary.
3. Review exact-resource permissions before deployment.
4. Test allowed and denied paths without exposing sensitive values.
5. Remove or expire temporary access after the approved window.
6. Escalate any unexpected allow decision as a security incident.

## Backup and recovery runbook

1. Identify the approved synthetic recovery point and expected hash.
2. Restore into the bounded synthetic location.
3. Verify content, version, provenance and hash independently.
4. Measure recovery time and recovery-point age.
5. Confirm expired or deleted data is not resurrected outside policy.
6. Keep G4-C06 open until failover and recovery are independently observed.

## Security incident runbook

1. Contain by disabling the narrowest affected path.
2. Preserve request IDs, timestamps, hashes and relevant immutable audit records.
3. Do not copy secret, personal or account-specific values into tickets or Git.
4. Notify the security, service and data owners when assigned.
5. Classify severity and decide whether external notification is required.
6. Record root cause, affected scope, corrective actions and residual risk.
7. Require independent confirmation before resuming.

## Support and escalation runbook

- Support hours: UNASSIGNED.
- Operations owner: UNASSIGNED.
- Security escalation contact: UNASSIGNED.
- Service owner: UNASSIGNED.
- External provider escalation: use only an approved account and preserve the case reference.
- No response-time promise exists until owners accept the operating model.

## Demonstration criteria

G4-C10 remains `planned` until deployment, rollback, access, recovery and incident
tabletop exercises have named participants, timestamps, expected and observed
results, unresolved risks, owner sign-off and independently reviewed evidence.

