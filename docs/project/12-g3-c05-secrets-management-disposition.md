# G3-C05 Secrets-Management Disposition

## Decision

G3-C05 `secret_management` is **not applicable to the current synthetic staging
scope**.

The current workload:

- uses an AWS Lambda execution role and temporary AWS credentials supplied by
  the platform;
- contains no application password, API token, private key, client secret,
  database credential, or other stored secret;
- has no authenticated production integration;
- accepts synthetic input only;
- keeps real-data collection disabled; and
- has `collection_execution_authority: none`.

Creating a synthetic managed secret solely to demonstrate a lifecycle that the
current workload does not use would add cost, permissions, network resources and
cleanup risk without reducing a present secret-handling risk. The proposed
Secrets Manager secret and interface endpoint therefore will not be created.

## Scope and conditions

This disposition applies only to `environment: synthetic-staging` and only while
the workload remains secretless. It is not a statement that secrets management
is unimportant to the product or to a future authorised pilot.

The disposition must be withdrawn and G3-C05 reassessed before any of the
following:

1. adding a password, token, private key, client secret or credential;
2. adding an authenticated collector, production data source or third-party API;
3. introducing a database or service requiring stored credentials;
4. enabling real data;
5. changing the environment from `synthetic-staging`; or
6. granting collection, migration or cryptographic execution authority.

At that point, the project must select an approved secret store, define private
network access where required, apply exact-resource IAM controls, demonstrate
retrieval and rotation without disclosure, capture access logs, and test
revocation and teardown.

## Evidence and gate treatment

The readiness assessor may treat `secret_management` as satisfied by a
`not-applicable` disposition only when all of the following are true:

- the environment is `synthetic-staging`;
- the control is `secret_management`;
- the control status is `not-applicable`; and
- `evidence_refs` contains this decision record or another accountable decision
  reference.

No other G3 control may use this exception. An authorised real-data pilot cannot
use this synthetic-scope disposition.

With seven controls demonstrated and this one control accepted as not
applicable, the automated assessment may report `synthetic-staging-ready` with
zero remaining controls. It must still report:

- `g3_gate_passed: false`;
- `collection_execution_authority: none`; and
- that an external accountable G3 decision is required before a real-data pilot.

## Cost and security consequence

No Secrets Manager secret, interface endpoint, rotation function or additional
secret-access policy will be deployed. The previously estimated interface
endpoint and secret charges are therefore avoided, and the synthetic workload's
AWS attack surface remains unchanged.
