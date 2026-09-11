# Demo click path

Recorded against seed 42, month 12, on the database `make demo` seeds and the chain it anchors to.
Every number here was read back out of that run — the API, the CLI or the database — and not typed
from memory. The three identities in the top-three beat are chosen by the ranking, never placed by
hand (PRD §9).

The estate is deterministic, so the same seed gives the same numbers — but a change to the
generator or the rules moves them, and then this file is stale until someone re-measures. "How to
re-measure" at the bottom gives the command behind every figure. `make verify SCAN=12` is the
one-line check: if it passes, the roots and counts below still describe the running system.

## Before you start

```bash
make demo
```

Then log in as `approver@athar.local` (the video uses the approver so the Apply button is live).
Keep a shell open for the ledger beat.

Without Docker, run `make demo-local` instead (README, "Running without Docker") and replace every
`docker compose exec api athar X` below with `cd backend && uv run athar X`; each `make <target>`
has a `-local` twin.

Run `make eval` once after a re-seed. The Evaluation page reads `data/eval/results-7.json` from
disk rather than recomputing it, so after the estate changes that page keeps showing the previous
run's precision and recall until the harness is run again.

| Account | Role | Used for |
|---|---|---|
| `analyst@athar.local` | analyst | run scans, advance the month, run agents, upload exports |
| `approver@athar.local` | approver | everything above, plus approve / reject / apply and exceptions |
| `judge@athar.local` | viewer | read-only; this is the account judges receive |

## Beats

### 0:00 — Set the scene (Overview)

Month 12 (August 2026), 507 identities (382 people, 125 service accounts), 99 open findings: 21
critical, 47 high, 27 medium, 4 low. Median risk score 2. The ledger badge reads **anchored** with
the month-12 root `0xc1559c8d30ae…`.

> "Three clouds, five hundred identities, twelve months of history. Nobody at this authority has
> ever had one view of who can do what."

### 0:30 — Watch it drift (Timeline → Play)

Month 1 opens with 47 findings and month 12 ends with 99:
47 · 56 · 56 · 67 · 68 · 70 · 75 · 81 · 87 · 92 · 98 · 99. It is not a straight line — month 3 adds
nothing at all, and the steps between months vary from one finding to eleven — which is worth
pointing at, because a hand-drawn curve would be smoother than this one. The identity count goes
386 → 507 over the same window. Nothing here was authored:
the estate was simulated month by month from hires, role changes, departures, project retirements
and incident response, and it rotted on its own.

### 1:15 — The organisational finding (Overview → a department card's half-life → Timeline)

Every department card carries "Offboarding half-life"; the value links to the Timeline page, where
the half-life table shows the grants and revocations behind it per trigger. Platform Engineering
granted **500** permissions over the year and revoked **27** on departure — around one in twenty,
under the tenth the metric needs, so the half-life reads **Never (Broken)**. Cyber Security is
worse: 360 granted, 12 revoked. **Smart Services is the only department that revokes on departure
often enough to have a half-life at all** — 373 granted, 43 revoked — and it still takes **5
months**. Estate-wide the departure row is 2,105 granted against 107 revoked.

The counts are provider grants — one role assignment, one attached policy — not the canonical rows
they expand into.

> "That is not twelve risky people. That is one broken offboarding process, and the number says so."

### 1:45 — Top three by risk (Identities → sort by score, descending)

| # | Identity | Department | Score | Blast radius | Rules |
|---|---|---|---|---|---|
| 1 | Hamad Al Ketbi (`emp-0093`) | Platform Engineering | 100 | 69.9% | R4 |
| 2 | Rohan Al Suwaidi (`emp-0098`) | Platform Engineering | 100 | 69.9% | R4 |
| 3 | Nadia Khan (`emp-0172`) | Platform Engineering | 100 | 69.9% | R1, R4, R5, R9 |

Ties at 100 break on blast radius, so the top of the table is the widest reach, not an arbitrary id.

All three are Platform Engineering, all three are at 100, and all three fired R4, the cross-cloud
superuser rule. Say that on camera rather than hiding it: it is itself the finding, a whole platform
team holding the same power in AWS, Azure and GCP, and it is why the tie at 100 breaks on blast
radius rather than on anything interesting. Walk **Nadia Khan**, because four rules fired on her at
once — R1, R4, R5 and R9 — which makes hers the densest drill-down in the estate.

Each drill-down has the altitude toggle:

- **Headline**: one business sentence, no identifiers.
- **Explanation**: since when, the blast-radius sentence, and the causal history.
- **Evidence**: raw provider JSON → canonical rows → rules fired → score line items → escalation
  chain → the Merkle leaf and its proof.

If there is time for a fourth, **Karim Al Mehairi** (`emp-0299`, Platform Engineering, score 100,
69.9%) sits just below the top three on the same rule.

Then use the rule filter for two different failure modes: filter to **R3** (21 findings) for a
departed employee who kept access, and to **R5** (19 findings) for a self-escalation path rendered
as a chain.

### 3:00 — Close the loop (drill-down → Plan remediation → Remediation → Approve → Apply)

For an R3 orphan the plan is `disable_identity` and it drops everything. For the other rules the
plan is built from ninety days of actual usage plus the grants the rule cited, then widened to
provider granularity — a cloud cannot revoke half a role assignment, so anything sharing one with a
dropped grant goes too, and the plan says so.

Use a departed employee: the one measured for this script is **Aisha Al Ameri** (`emp-0191`),
Platform Engineering, R3, score **100**, blast radius **69.3%** — the widest reach of any orphan on
the estate. The plan is `disable_identity`; it drops all **49** of her grants and keeps none, so
privilege reduction is 100% and the expected blast radius after is 0%. Approve as the approver
(the analyst who proposed it cannot: separation of duties returns 403), then Apply. The simulated
cloud changes — every grant revoked, every credential deactivated, the identity disabled — the
month is re-ingested and re-scanned, and the before/after score is measured rather than asserted:
**100 → 0**, blast radius **69.3% → 0.0%**, and the month's open findings go from 99 to 96, because
three of them were hers. A new scan row appears on the Ledger page, anchored, alongside the two
decisions the approval and the apply each wrote to the chain.

> "The agent proposed the change. An approver signed it. The simulated cloud changed. The new score
> is the one the engine measured afterwards."

### 3:40 — Prove it (Ledger → Verify, then tamper)

Verify scan 12 in the UI: PASS, with the recomputed root and the on-chain root side by side —
`0xc1559c8d30ae2457bd085f348f84d89ca3c07bad3affe2ddd01538e1520fe838` against on-chain commit 11,
99 findings, transaction `0xa22adc8fb802…`. Then, in the shell:

```bash
docker compose exec api athar tamper --finding <key> --scan 12
```

```bash
make verify SCAN=12
```

It now reports FAIL and prints both roots. The badge turns red on the next page load without
anyone pressing Verify: the badge recomputes the root from the finding rows as they stand, so an
edited severity is visible immediately; the explicit Verify action is the one that also reads the
chain, which is what tells an edited database from an edited commit.

`tamper` alters one scan and prints which one, plus the command that puts it back — for scan 12
that is `athar scan --month 12`, i.e. `make scan SCAN=12`. Run it, verify again, and the badge goes
green. (A finding key is stable across months, so a finding usually sits in several scans; `tamper`
deliberately touches only the one you name, because `scan` restores only the month it re-runs.)

### 4:20 — Accuracy, two registers (Evaluation)

Precision and recall on the held-out seed, per-rule confusion, and the decoy table. Measured on
seed 7 with `make eval`: **precision 1.00, recall 1.00, F1 1.00 at High+ — 48 flagged, 48 true
positives, no false positives, no false negatives** across 491 identities, and **all eleven decoys
correctly left alone**. On the tuning seed (42, the demo estate) the same harness reports precision
0.96, recall 1.00, F1 0.98 — 48 flagged, 46 true positives, two false positives — and eleven of
eleven decoys left alone. Constants are tuned on 42 and reported on 7, and the file each run writes
says which of the two it was, so a reader never has to take the label on trust.

Say plainly what the numbers mean: ground truth restates each rule's predicate over the simulator's
own state, so this is a pipeline-recovery check — does the engine recover, from the written exports,
what the simulator recorded doing? — and not a claim about a real estate. The decoys are the part
that tests judgement: eleven identities built to trip a naïve detector, seven of them legitimate
only through an entry in the governance register and four through an HR `contract_end` in the
future. Never through a cloud-side tag.

R7 is the honest gap on this page: it fires on nothing, on either seed, in any month. Say so rather
than let a judge find it (README, "Known limitations").

### 4:45 — Export and close (Findings → Export)

The CSV carries `recommended_action` for a ticket queue; the PDF footer carries the Merkle root and
the transaction. Both can be checked without the dashboard. `make export` writes all three files
into `data/exports/` — and `athar export --format csv` writes the `findings.json` sidecar beside the
CSV on its own, so a CSV handed to someone is always verifiable:

```bash
docker compose exec api athar verify --csv data/exports/findings.csv --json data/exports/findings.json
```

```
99/99 rows verify against the on-chain root 0xc1559c8d30ae…
```

The root is read from the chain, not from the report, so a report with findings deleted and its
Merkle tree recomputed is rejected.

## Rehearsal checklist

- [ ] `make demo` twice on a clean machine; the second run prints twelve lines, one per month, each
      ending `already anchored`. The last reads
      `month 12: 99 findings · root 0xc1559c8d30ae… · already anchored`.
- [ ] `make eval` after the re-seed, so the Evaluation page is not showing the previous estate.
- [ ] Log in as the judge account: every page renders, no mutating control is enabled.
- [ ] Approve and apply one plan; the score moves and the decision appears on the Ledger page.
- [ ] Tamper one scan, verify (FAIL), re-scan that month, verify (PASS).
- [ ] Network off except the local chain: every beat still works, because agent output is cached
      and falls back to templates.

## How to re-measure

Every figure above came from one of these. Re-run them after any change to the generator, the
rules or the scoring constants, and update this file in the same commit.

| Beat | Where the number comes from |
|---|---|
| Identity and finding counts, severity split, median score, ledger badge | `GET /api/v1/estate/summary` |
| The month-by-month series | `GET /api/v1/timeline` |
| Half-life: grants, revocations, months, label | `GET /api/v1/departments/halflife` |
| Top three, scores, blast radius | `GET /api/v1/identities?sort=-score&limit=10` |
| Rules fired on one identity | `GET /api/v1/identities/<id>` |
| Findings per rule | `GET /api/v1/findings?limit=500`, grouped by `rule_id` |
| Plan action, grants dropped, expected blast radius | `GET /api/v1/remediation` after `make agent` |
| Score before / after | the `ApplyResult` the Apply call returns — never computed by hand |
| Root, transaction, chain index, finding count | `athar verify --scan 12` |
| Export row count | `athar verify --csv … --json …` |
| Precision, recall, decoys | `make eval` |

The read-only ones take a viewer cookie:

```bash
curl -s -c /tmp/athar.jar -H 'Content-Type: application/json' -H 'X-Requested-With: athar' \
  -X POST http://localhost:8000/api/v1/auth/login \
  -d '{"email":"judge@athar.local","password":"'"$DEMO_JUDGE_PASSWORD"'"}'
```

```bash
curl -s -b /tmp/athar.jar http://localhost:8000/api/v1/estate/summary
```
