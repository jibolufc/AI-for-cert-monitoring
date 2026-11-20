# Agent handoff

Read this before working in this repository. It records where work stands so
the next agent (Codex, Claude or a person) does not repeat or contradict it.
Update the "Last handoff" section when you stop.

## Rules that apply to every change

- Status claims come from tool output, not prose. For G3 run
  `python -m crypto_control_plane.g3_readiness_cli --plan evidence/g3/2026-11-19-readiness-plan.json --output evidence/g3/2026-11-19-readiness-report.json --as-of <now>`
  and quote the report. Same for G4 with `g4_readiness_cli`.
- Do not edit a hashed evidence record (`evidence/**/*.json` with a `.sha256`).
  Add a new dated record that supersedes it, and hash that.
- Do not change a control's minimum-evidence wording in the same change that
  marks the control demonstrated or not applicable.
- A control is `demonstrated` only when its evidence meets every part of its
  minimum evidence. Partial evidence keeps it `planned`.
- Requester and approver must be different identities, including for
  not-applicable decisions and plan approval.
- AWS changes go through a reviewed `g3-reviewed-*` change set. Record the
  change-set ID in `evidence/g3/`. The bootstrap stack may only change under a
  recorded exception (see `infra/aws/g3-synthetic/README.md`).
- No real data, public endpoints or cryptographic execution. All authority
  fields stay `none` / `false`.
- Run the full suite on Python 3.11 and 3.13 before committing:
  `python -m unittest discover -s tests`.

## Last handoff: 20 November 2026, 13:55 UTC (Codex)

Branch `codex/g3-readiness`. Main has PR #2 (kex-probe), #3 (D1/D4), #4 (S3-only
egress) and #5 merged; this branch has main merged in.

**Done in this handoff**

1. Rejected and deleted two unsafe S3-only egress previews. V1 proposed five
   changes and three replacements. V2 still proposed replacement of
   `SyntheticEvidenceBucketPolicy`.
2. Updated the workload template to preserve the live evidence-bucket name,
   bucket-policy target and immutable security-group description during an
   existing-stack update. Added regression coverage and update instructions.
3. Executed `g3-reviewed-s3-only-egress-v3-20261120` only after it showed one
   resource change: `SyntheticWorkloadSecurityGroup`, Modify, Replacement
   `False`. Change-set ID suffix:
   `a362ba14-dc18-4319-9acc-f22c55fe7633`.
4. CloudFormation reported `UPDATE_COMPLETE` at `2026-11-20T13:26:55Z` with no
   failure or rollback. The bounded operator then observed zero inbound and one
   outbound security-group rule; exact expansion remains denied by
   `ec2:DescribeSecurityGroupRules` and no permission was broadened.
5. Added and hashed
   `evidence/g3/2026-11-20-s3-only-egress-update.json`, closing review R5 while
   retaining the read-permission limitation explicitly.
6. Reran the assessor into the new hashed
   `evidence/g3/2026-11-20-readiness-report.json`. Authoritative result remains
   **`blocked`, 6 demonstrated, 0 accepted not applicable, 2 remaining**.
7. Fixed the `test_kex_probe` stand-in launcher so Python interpreter paths
   containing spaces are shell-quoted without changing production probe code.
   The full suite now passes on temporary Python 3.11.18 and installed Python
   3.13: 165 tests, zero failures and one expected loopback sandbox skip on each.

**Open, in order**

1. Attach the bootstrap change-set ID from 19 November to a new corrections
   supplement (do not edit the hashed 19 November record) to close R4.
2. G3-C06: add tamper resistance (deny log deletion and retention changes to all
   but a break-glass role, then record one denied call; or export to S3 with
   Object Lock). Then set `central_logging` to `demonstrated` in a new dated plan.
3. G3-C05: either a second person approves the not-applicable decision (set
   `approved_by` in a new dated plan) or run a synthetic Secrets Manager test.
4. Plan approval: the recorded plan has `requested_by` = `approved_by`. An
   independent approver is required before `synthetic-staging-ready`.
5. Generate `dashboard/dist/data.json` from the assessor report and stack
   outputs; it still shows 12 November figures.
6. Only after G3 reports `synthetic-staging-ready`: continue G4.

Untracked `public-site-release/` in the Codex worktree is unrelated; leave it.
