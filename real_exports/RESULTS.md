# Real-export validation

The jury's one open question (case score 100/100): *"how the scoring constants and joins would
behave on real enterprise IAM data"* — the validation so far is on the synthetic estate. This
directory answers it by running a **real** `aws iam get-account-authorization-details` export
through ATHAR's own normaliser and rule engine — the exact `normalise_provider(...)` the
`/ingest/upload` endpoint calls, with no database, ledger, LLM or HR feed.

## Source

`aws-authorization-details.json` is the public example estate shipped by **Cloudsplaining**
(Salesforce, BSD-3), a widely used AWS IAM assessment tool. It is native
`get-account-authorization-details` output built to contain genuinely over-privileged and
privilege-escalating principals. Account IDs have been rewritten to the reserved `012345678901`;
policy documents, actions, ARNs and structure are unmodified. Nothing here is a real account.
See `SOURCE.md`.

## Reproduce

```bash
PYTHONPATH=backend python real_exports/run_real.py real_exports/aws-authorization-details.json
```

## Result

```
principals parsed : 122
canonical grants  : 1124
unmapped actions  : 2512

FINDINGS: 318 across 122 real principals
  R0   Low        45  Unmapped permission
  R1   High       17  Wildcard / admin privilege
  R2   Medium     25  Dormant access
  R5   High       73  Toxic combination
  R7   Low        36  Peer outlier
  R10  Medium    122  Unowned principal
```

The 17 R1 (admin) hits land on principals that are genuinely administrative —
`OrganizationAccountAccessRole`, `AWSReservedSSO_AdministratorAccess_*`,
`AWS-QuickSetup-StackSet-Local-ExecutionRole` — plus Cloudsplaining's own over-privileged
fixtures (`userwithlotsofpermissions`, `OverprivilegedEC2`, `MyRole`). R5 (toxic combination /
privilege escalation) fires 73 times on the escalation-capable roles the fixture was built to
carry.

## Why this matters for the pitch

1. **R7 fires on real data.** On the synthetic estate R7 (peer outlier) fires on *nobody* — the
   generator gives almost every identity grants in every service category, so no one is an
   outlier (documented as a known limitation in the README). On the real export R7 fires **36
   times**. Real estates are lumpy; the synthetic one was too uniform. A known-limitation becomes
   a validated rule.

2. **The perfect precision/recall does not — and should not — appear here.** On synthetic data
   ATHAR reports F1 ≈ 1.00 because ground truth is derived from the same simulator the exports
   come from; it is a *pipeline-recovery* check, not an accuracy claim (see the audit note in
   `../hack_files/` discussion and README "Known limitations"). Real data has no ground truth, so
   there is no self-graded 1.00 to distrust — instead the findings are checkable against a
   known third-party tool's own risky fixtures. This is the honest number to show a regulator.

3. **The gaps are the real work item, stated plainly.** 2512 actions are unmapped (R0) because
   real AWS has thousands of actions the mapping table does not yet cover; R10 fires on all 122
   principals only because no HR/ownership feed was supplied (`hr=None`). Both are expected, both
   are visible, neither is hidden behind a green number.
