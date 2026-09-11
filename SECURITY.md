# Security policy

ATHAR is a hackathon prototype. It ships with hardening that a real deployment would keep
(RBAC with separation of duties, validated uploads, RFC 7807 errors without traces,
security headers, rate limits, prompt-injection guardrails, a tamper-evident ledger) and
with dev defaults that a real deployment must replace (see `docs/THREAT_MODEL.md`,
"Residual risks").

## Reporting

Open a private security advisory on the GitHub repository, or email the maintainers at the
address in the repository profile. Please include the commit hash, reproduction steps and
the impact you believe it has. We aim to acknowledge within 72 hours.

## Scope notes

- The Anvil private key in `.env.example` is Anvil's publicly known dev account #0. It is
  not a secret and holds nothing of value; reporting it is not a finding.
- All IAM data in this repository is synthetic (`nda.example`). Nothing references a real
  cloud account, entity or person.
