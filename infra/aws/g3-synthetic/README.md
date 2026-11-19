# AWS G3 synthetic staging foundation

This CloudFormation template deploys a deliberately bounded synthetic evidence
runner into an **existing** VPC. It creates no VPC, public workload, NAT gateway,
interface endpoint, EC2 instance, Lightsail instance, public load balancer,
production collector, or cryptographic execution path.

## Preconditions

Before creating the stack, independently verify:

1. The target VPC and `us-east-1` region match the local deployment evidence
   record; do not commit account-specific resource IDs.
2. Two selected subnets are the named private subnets in different Availability
   Zones and have `Auto-assign public IPv4` disabled.
3. Neither private route table has `0.0.0.0/0` targeting an internet gateway.
4. Record whether an S3 gateway endpoint is already associated with either
   private route table; do not create a duplicate endpoint route.
5. Any NAT gateway and its recurring cost are explicitly accepted; this stack
   neither creates nor requires one. Security-group egress is limited to the
   S3 prefix list, so an existing NAT gateway does not give the workload
   internet access.
6. The account operator uses MFA-backed administrative access, not root access.
7. A budget owner and teardown owner are named for this temporary environment.
8. G3-C05 secret-management evidence is planned separately; this stack creates
   no secret and cannot by itself demonstrate the `secret_management` control.
9. The dedicated CloudFormation service role and
   `ccp-g3-workload-boundary` policy were created by the reviewed operator
   bootstrap; the human operator does not hold direct provisioning permissions.

10. The ID of the AWS-managed prefix list `com.amazonaws.us-east-1.s3` is
    recorded, using the same read-only identity that verifies facts 2 to 4
    (the bootstrap operator policy cannot describe prefix lists):
    `aws ec2 describe-managed-prefix-lists --region us-east-1 --filters
    Name=prefix-list-name,Values=com.amazonaws.us-east-1.s3
    --query 'PrefixLists[0].PrefixListId'`.

Do not deploy until all ten facts are recorded in the evidence directory.

## Resources

- private, versioned S3 bucket with SSE-S3 encryption, public-access blocking,
  TLS-only access policy, and 30-day synthetic-evidence lifecycle;
- S3 gateway VPC endpoint attached only to the verified private route tables;
- no-ingress security group whose only egress is HTTPS to the regional S3
  prefix list (no CIDR destinations);
- dedicated Lambda workload identity with evidence-prefix, logging, and required
  network-interface permissions only;
- Python 3.13 Lambda in the two private subnets with reserved concurrency set
  to zero, keeping invocation disabled until a separately approved update;
- explicit CloudWatch log group with 30-day retention.

The S3 object and its SHA-256 value are the authoritative durable test evidence.
CloudWatch logs are supplemental invocation evidence for this standard Lambda
function; this template does not use Lambda Managed Instances.

The function rejects any event not explicitly marked `synthetic` with
`real_data_enabled: false`. It supports only `write` and `restore` actions.

## One-time operator bootstrap

Deploy `operator-bootstrap.json` once from the root account only after reviewing
its change set and acknowledging `CAPABILITY_NAMED_IAM`. It does not create the
G3 workload. It creates:

- an encrypted, public-blocked template-staging bucket whose objects expire
  after seven days;
- AWS-style self-service MFA controls for the named existing IAM user;
- an MFA-gated operator policy limited to the `ccp-g3-synthetic` stack and
  change sets named `g3-reviewed-*`;
- a dedicated CloudFormation service role with template-derived provisioning
  permissions; and
- the `ccp-g3-workload-boundary` managed policy required by the Lambda role.

The bootstrap grants no CloudShell access, no administrator policy, no direct
service-provisioning permissions to the human user, and no normal evidence or
bucket-deletion authority. After bootstrap creation, sign out of root. The
operator must enrol MFA, sign out, sign back in with MFA, upload the reviewed
template only under `templates/`, and use the exact service-role and permissions-
boundary ARNs returned by the bootstrap outputs.

The bootstrap stack is a security dependency. Do not delete or update it while
the G3 workload stack exists. Its retained staging bucket and TLS-only policy
require a separate, approved teardown decision.

## Console deployment

1. Open CloudFormation in `us-east-1` and choose **Create stack** using new
   resources.
2. Choose **Upload a template file** and select `template.json`.
3. Use stack name `ccp-g3-synthetic`.
4. Select the verified VPC, two private subnet IDs, and their route-table IDs.
5. Set `WorkloadPermissionsBoundaryArn` to the output of the approved operator
   bootstrap and select its dedicated CloudFormation service role.
6. Set `S3PrefixListId` to the ID recorded for fact 10.
7. Leave `CreateS3GatewayEndpoint` as `false` if the route tables already have an
   S3 gateway endpoint. Set it to `true` only when read-only inspection proves
   there is no existing endpoint route.
8. Keep rollback enabled. Do not enable permissions that CloudFormation does not
   request.
9. Acknowledge that the stack creates IAM resources, review the change set,
   and create the stack.
10. Preserve the stack events, outputs, and resource inventory as deployment
   evidence.

## Updating an existing stack to S3-only egress

Stacks created before this change allow HTTPS egress to `0.0.0.0/0`. To apply
the restriction, create a change set named `g3-reviewed-*` on
`ccp-g3-synthetic` with the updated template and the new `S3PrefixListId`
parameter, keeping every other parameter's previous value. The change set
should show only `SyntheticWorkloadSecurityGroup` as Modify with Replacement
`False`. Reject it if it shows any other resource change or any replacement.
Record the change set and the security group's egress rules afterwards as
G3-C03 evidence.

## Test events

Write a synthetic evidence object:

```json
{
  "action": "write",
  "data_classification": "synthetic",
  "real_data_enabled": false,
  "payload": {"scenario": "g3-connectivity-test", "result": "synthetic-only"}
}
```

Then use the returned `runs/...json` key to test restore:

```json
{
  "action": "restore",
  "data_classification": "synthetic",
  "real_data_enabled": false,
  "key": "runs/REPLACE-WITH-WRITE-KEY.json"
}
```

Expected negative test: setting `real_data_enabled` to `true` must fail without
writing an object.

## Evidence and gate status

A successful stack creation does not pass G3. Only update a readiness control
from `planned` to `demonstrated` after attaching immutable or hashed evidence of
the corresponding test. `collection_execution_authority` remains `none`.
G3-C05 remains `planned` until a separate synthetic-secret lifecycle and access
test is approved and evidenced; the absence of stored secrets in this stack is
not evidence that the control has been demonstrated.

## Cost and teardown

The baseline avoids NAT gateways, interface endpoints, customer-managed KMS
keys, Secrets Manager secrets, and continuously running compute. Normal Lambda,
S3, and CloudWatch usage charges may still apply.

Before deleting the stack, export the required synthetic evidence. The bucket is
retained deliberately together with its TLS-only bucket policy; empty and delete
them separately only after confirming the evidence is no longer required.
Verify that no stack-created log group, Lambda, role, security group, endpoint,
or retained bucket remains billable or active.
