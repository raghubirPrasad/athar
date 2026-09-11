# Control and technique mappings

Every MITRE ATT&CK, ISO/IEC 27001:2022, UAE IA and DESC ISR identifier that ATHAR quotes in
the UI, the CSV or the PDF is listed here with the primary source it was checked against.

**How the mark works in the code.** `detection/common.py::verify()` appends ` (verify)` to
every identifier a rule declares, unconditionally — there is no allowlist, so a verified
identifier carries the mark just as an unverified one does. That is deliberately conservative:
it can never under-mark, which is what the CLAUDE.md "Never" list guards against. The cost is
that the mark alone does not tell a reader which identifiers have been checked. **This table
does.** If the mark is ever made conditional, the allowlist is this file's "verified" rows.

The "Used by" column is exactly what `athar.detection.registry.all_rules()` declares; to check
it, print `rule.id`, `rule.attack_techniques` and `rule.control_refs` for every rule.

## MITRE ATT&CK (verified 2026-09-10 against attack.mitre.org)

| ID | Name | Tactic(s) | Source | Used by |
|---|---|---|---|---|
| T1078.004 | Valid Accounts: Cloud Accounts | Persistence, Privilege Escalation, Initial Access, Defense Evasion | https://attack.mitre.org/techniques/T1078/004/ | R1, R2, R3, R4, R9 |
| T1098 | Account Manipulation | Persistence, Privilege Escalation | https://attack.mitre.org/techniques/T1098/ | R5 |
| T1098.001 | Account Manipulation: Additional Cloud Credentials | Persistence, Privilege Escalation | https://attack.mitre.org/techniques/T1098/001/ | R6 |
| T1548 | Abuse Elevation Control Mechanism | Privilege Escalation, Defense Evasion | https://attack.mitre.org/techniques/T1548/ | R5 |
| T1556 | Modify Authentication Process | Credential Access, Defense Evasion, Persistence | https://attack.mitre.org/techniques/T1556/ | R9 |

Notes: the ATT&CK site labels the tactic set slightly differently per release (the page fetched
for T1078.004 listed "Persistence, Privilege Escalation, Initial Access" plus the evasion
tactic); the IDs and names above are exact. R0, R7, R8 and R10 declare no technique by design:
they are governance heuristics, not adversary behaviours.

Three sub-techniques that earlier drafts of this table credited to rules — T1098.003
(Additional Cloud Roles), T1548.005 (Temporary Elevated Cloud Access) and T1556.006
(Multi-Factor Authentication) — are **not** emitted by any rule and have been removed. Each is
a defensible secondary mapping for R5, R1 and R9 respectively, but a table of identifiers the
product does not actually quote is a table a judge can falsify in one query. If a rule starts
declaring one, it comes back here with its source.

## ISO/IEC 27001:2022 Annex A (titles verified against a public Annex A listing; the standard text itself is paywalled)

| Control | Title | Used by |
|---|---|---|
| A.5.14 | Information transfer | R8 |
| A.5.15 | Access control | R1, R4, R5 |
| A.5.16 | Identity management | R10 |
| A.5.17 | Authentication information | R6, R9 |
| A.5.18 | Access rights | R1, R2, R3, R7 |
| A.6.5 | Responsibilities after termination or change of employment | R3 |
| A.8.2 | Privileged access rights | R5 |
| A.8.5 | Secure authentication | R9 |

Source used for titles: https://www.isms.online/iso-27001/annex-a-2022/ (secondary; matches
the ISO/IEC 27001:2022 Annex A table of contents). Treat as verified for titles, *unverified*
for clause wording. Rules quote these as `ISO 27001:2022 A.5.15 (verify)` and so on.

## UAE Information Assurance Regulation and DESC ISR — *unverified*

| Reference | Emitted as | Intended meaning | Status |
|---|---|---|---|
| UAE IA T5 | `UAE IA T5 (verify)` (R1) | Access-control family of the TDRA (formerly NESA) UAE Information Assurance Regulation | **(verify)** — the control family numbering has not been checked against the published regulation |
| UAE IA data residency | `UAE IA data residency (verify)` (R8) | The regulation's requirements on where data may be held | **(verify)** — no clause number is quoted, deliberately |
| DESC ISR data residency | `DESC ISR data residency (verify)` (R8) | Dubai Electronic Security Center Information Security Regulation clauses on data location | **(verify)** — no clause number is quoted, deliberately |

R1 is the only rule that quotes a UAE IA *family number*. The two residency references name a
subject, not a clause, so there is nothing to mis-cite; the family number `T5` is the one
identifier here that could be wrong, and it carries the mark until someone reads the published
regulation.
