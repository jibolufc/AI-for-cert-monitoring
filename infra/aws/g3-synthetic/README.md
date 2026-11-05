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
   neither creates nor requires one.
6. The account operator uses MFA-backed administrative access, not root access.

Do not deploy until all six facts are recorded in the evidence directory.

## Resources

- private, versioned S3 bucket with SSE-S3 encryption, public-access blocking,
  TLS-only access policy, and 30-day synthetic-evidence lifecycle;
- S3 gateway VPC endpoint attached only to the verified private route tables;
- no-ingress security group with HTTPS-only egress;
- dedicated Lambda workload identity with evidence-prefix, logging, and required
  network-interface permissions only;
- Python 3.13 Lambda in the two private subnets with concurrency capped at one;
- explicit CloudWatch log group with 30-day retention.

The function rejects any event not explicitly marked `synthetic` with
`real_data_enabled: false`. It supports only `write` and `restore` actions.

## Console deployment

1. Open CloudFormation in `us-east-1` and choose **Create stack** using new
   resources.
2. Choose **Upload a template file** and select `template.json`.
3. Use stack name `ccp-g3-synthetic`.
4. Select the verified VPC, two private subnet IDs, and their route-table IDs.
5. Leave `CreateS3GatewayEndpoint` as `false` if the route tables already have an
   S3 gateway endpoint. Set it to `true` only when read-only inspection proves
   there is no existing endpoint route.
6. Keep rollback enabled. Do not enable permissions that CloudFormation does not
   request.
7. Acknowledge that the stack creates IAM resources, review the change set,
   and create the stack.
8. Preserve the stack events, outputs, and resource inventory as deployment
   evidence.

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

## Cost and teardown

The baseline avoids NAT gateways, interface endpoints, customer-managed KMS
keys, Secrets Manager secrets, and continuously running compute. Normal Lambda,
S3, and CloudWatch usage charges may still apply.

Before deleting the stack, export the required synthetic evidence. The bucket is
retained deliberately; empty and delete it separately only after confirming the
evidence is no longer required. Verify that no stack-created log group, Lambda,
role, security group, endpoint, or retained bucket remains billable or active.
