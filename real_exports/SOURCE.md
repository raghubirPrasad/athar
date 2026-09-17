# Provenance and licence

`aws-authorization-details.json` is derived from the example estate published by the
**Cloudsplaining** project:

- Project: Cloudsplaining — AWS IAM Security Assessment tool
- Publisher: Salesforce
- Licence: BSD-3-Clause
- Origin file: `examples/files/example.json` (native `aws iam get-account-authorization-details`
  output, purpose-built with over-privileged and privilege-escalation principals for testing)

## Modifications

- The two account IDs that were not already the reserved dummy value have been rewritten to
  `012345678901`. No other bytes changed: policy documents, actions, ARNs (minus account number)
  and the file structure are the original.

## Why this file, not a live cloud

Option A from the improvement plan: a public, deliberately-vulnerable IAM estate, so the
validation is reproducible offline (no network on the demo stage) and carries no risk of leaking
a real account, ARN or identity. It is real *native format* and real *risky policy content* — the
part the jury asked us to test — without a real *estate*.

To extend to a live estate later, run `aws iam get-account-authorization-details` against a
throwaway account (e.g. BishopFox `iam-vulnerable` or Rhino `CloudGoat` deployed via Terraform)
and drop the JSON in beside this one.
