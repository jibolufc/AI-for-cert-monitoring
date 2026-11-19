# G4-C09 Data Protection and Retention Baseline

## Control state

**Prepared, not demonstrated.** The current scope is synthetic-only and can be
documented locally. A real-data classification, lawful-purpose decision, source
authority and privacy/security approvals do not yet exist.

## Current permitted data

| Data class | Permitted now | Handling |
|---|---|---|
| Synthetic certificate and migration records | Yes | Validate, minimise and label `synthetic` |
| Sanitised project evidence | Yes | Remove account, asset and identity-bearing values before version control |
| Temporary AWS role credentials | Platform-managed only | Never export, log or store in the repository |
| Real certificate inventory or enterprise hostnames | No | Requires written source and data-owner authority |
| Personal data, customer data or employer data | No | Requires classification, purpose, privacy and retention approval |
| Passwords, tokens, private keys or client secrets | No | Prohibited in source, evidence, logs and synthetic payloads |

## Protection requirements

- Minimise every record to the fields required for discovery, provenance,
  verification or migration governance.
- Reject real-data flags in synthetic environments.
- Encrypt transport and storage using approved platform controls.
- Use workload identity and temporary credentials; do not embed credentials.
- Keep raw identifiers out of public briefs and repository evidence.
- Preserve provenance and evidence level when sanitising; never relabel simulated
  evidence as authenticated or production evidence.
- Do not collect from a source merely because it is technically reachable.

## Current retention schedule

| Record | Retention | Disposal |
|---|---|---|
| Synthetic S3 evidence | 30 days | Lifecycle expiry; noncurrent versions permanently expire after 30 days |
| Synthetic Lambda logs | 30 days | CloudWatch log-group retention |
| Reviewed staging templates | 7 days | Staging-bucket lifecycle expiry |
| Sanitised gate decisions and hashes | Project assurance lifetime | Repository history; never include data requiring routine erasure |
| Local temporary test output | Test duration | Remove after validation unless intentionally promoted to sanitised evidence |
| Real or production data | Not authorised | No retention schedule exists; intake is prohibited |

Git history is not an appropriate store for erasable, secret or personal data.
If such material is committed accidentally, stop processing, restrict access,
preserve minimal incident evidence and follow a separately approved history-
rewrite and notification process.

## Reactivation and approval triggers

Before accepting real data, the data owner and security owner must approve:

1. source authority and purpose;
2. field-level classification and minimisation;
3. residency and cross-border constraints;
4. encryption and key ownership;
5. subject or customer rights where applicable;
6. retention, legal hold and deletion verification;
7. incident notification and evidence preservation; and
8. the boundary between public, internal, confidential and secret evidence.

## Demonstration criteria

G4-C09 remains `planned` until the approved classification and retention schedule
are enforced, expiry/deletion tests are observed, restore paths do not resurrect
expired data, and an independent reviewer confirms that repository and public
artefacts contain no prohibited data.

