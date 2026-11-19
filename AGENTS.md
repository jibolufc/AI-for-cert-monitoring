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

## Last handoff: 19 November 2026, 17:00 UTC (Claude)

Branch `codex/g3-readiness`. Main has PR #2 (kex-probe), #3 (D1/D4), #4 (S3-only
egress) and #5 merged; this branch has main merged in.

**Done in this handoff**

1. Committed Codex's uncommitted G4 foundation drafts (G4-C01, C02, C09, C10)
   as `f46855d`. All four remain `planned`; G4 is `blocked`, 0 of 10.
2. Merged PR #4 into main and main into this branch. The template's security
   group now allows HTTPS only to the S3 prefix list (`S3PrefixListId`). The
   live stack still has the old `0.0.0.0/0` rule.
3. Reviewed `64c9cba` and corrected the G3 position. Findings R1 to R5 are in
   `docs/project/09-external-review-findings-register.md` section 2a and
   `evidence/g3/2026-11-19-review-corrections.json`.
4. G3 assessor now requires an independent `approved_by` for not-applicable
   controls.
5. Recorded G3 plan and report added. Result: **`blocked`, 6 of 8
   demonstrated** (C01, C02, C03, C04, C07, C08).

**Open, in order**

1. Apply the S3-only egress template to `ccp-g3-synthetic` with a
   `g3-reviewed-*` change set. It must show only
   `SyntheticWorkloadSecurityGroup` as Modify, Replacement `False`. Record the
   change-set ID and the new egress rule (closes R5).
2. Attach the bootstrap change-set ID from 19 November to the corrections record
   (closes R4).
3. G3-C06: add tamper resistance (deny log deletion and retention changes to all
   but a break-glass role, then record one denied call; or export to S3 with
   Object Lock). Then set `central_logging` to `demonstrated` in a new dated plan.
4. G3-C05: either a second person approves the not-applicable decision (set
   `approved_by` in a new dated plan) or run a synthetic Secrets Manager test.
5. Plan approval: the recorded plan has `requested_by` = `approved_by`. An
   independent approver is required before `synthetic-staging-ready`.
6. Generate `dashboard/dist/data.json` from the assessor report and stack
   outputs; it still shows 12 November figures.
7. Only after G3 reports `synthetic-staging-ready`: continue G4.

Untracked `public-site-release/` in the Codex worktree is unrelated; leave it.
