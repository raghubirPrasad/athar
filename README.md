# ATHAR

ATHAR (Arabic أثر, "trace") is a multi-cloud access-governance dashboard for a government
shared-services estate. It ingests AWS, Azure and GCP IAM exports plus an HR feed, normalises
them into one permission model, shows how the estate became over-privileged over twelve
months, scores identities by measured blast radius, explains every finding at three
altitudes, proposes fenced agent-driven remediation with human approval, and anchors every
scan and decision to a Merkle-committed ledger that a judge can verify without trusting us.

Everything in this repository is synthetic. The customer, Nahar Digital Authority, is
fictional; every email uses the reserved `nda.example` domain; no real account, entity or
person is referenced.

## Quickstart

Requires Docker (Compose v2) and `make`. No images are published yet, so the first run builds
the API and web images locally and takes a few minutes; later runs reuse them.

From the root of this repository (the directory holding this README):

```bash
cp .env.example .env
```

```bash
make demo
```

`make demo` starts Postgres, a local Anvil chain, the API and the web app; generates the
500-identity estate for seed 42; ingests and scans all twelve months, anchoring each scan on
the ledger; then prints the URL and the demo accounts. Run it a second time: nothing is
duplicated, no contract is redeployed, and each month reports `already anchored`.

Dashboard: http://localhost:8080 · API docs: http://localhost:8000/api/docs

The repository is not public yet, so there is nothing to clone and the CI badge that normally
sits at the top of this file would 404; it goes back once the repository is published. The public
URL is in the submission PDF. Until then, work from the copy you were given: CI runs the same
checks locally through `make ci`.

### Running without Docker

If Docker is unavailable, the same pipeline runs directly on the host. It needs `uv`,
Foundry (`anvil`), Node 22 and a Postgres reachable at `DATABASE_URL`.

```bash
make anvil-local    # in its own shell: a local chain with persistent state
```

```bash
make demo-local     # migrate, seed users, generate, ingest and scan every month
```

```bash
make api-local      # in its own shell: http://localhost:8000/api/docs
```

```bash
make web-local      # in its own shell: http://localhost:5173
```

The rest of the demo has host equivalents too, each a `-local` twin of the Docker target:
`make scan-local`, `make advance-local`, `make agent-local`, `make export-local`,
`make verify-local [SCAN=n]` and `make reset-local`. Anywhere the docs say
`docker compose exec api athar X`, the host equivalent is `cd backend && uv run athar X`.

## Demo accounts

| Account | Role | Can |
|---|---|---|
| `analyst@athar.local` | analyst | run scans, advance the month, run agents, upload exports |
| `approver@athar.local` | approver | everything above plus approve / reject / apply remediation and grant exceptions |
| `judge@athar.local` | viewer | read everything, change nothing |

Passwords are in `.env` (`DEMO_*_PASSWORD`).

## What to click

1. **Overview** opens on the organisational finding: one card per department, each carrying its
   offboarding half-life. A department whose half-life reads *Never* has a broken process, not
   twelve risky people — every card but one reads *Never* here. Click the value for the Permission
   Half-Life table on **Timeline**, which shows the grants and revocations behind it per trigger.
2. **Identities** → sort by *Score* descending. Open the top three. Each drill-down has the
   altitude toggle: *Headline* (one sentence for a director), *Explanation* (why it fired,
   since when, blast radius, what changes if remediated), *Evidence* (raw provider JSON →
   canonical rows → rules → score line items → escalation chain → policy diff → Merkle leaf
   and proof).
3. **Timeline** → *Play* to watch month 1 → 12. Nothing was hand-authored: the estate drifted
   under simulated hires, role changes, departures, project launches and incident response.
4. **Plan remediation** on a finding (analyst), then **Remediation** → *Approve* → *Apply*
   (approver). The simulated cloud changes, the month is re-scanned, and the score drops.
5. **Ledger** → *Verify* on any scan. Then, from a shell, `docker compose exec api athar
   tamper --finding <key> --scan 12` and verify again: it fails, and the badge turns red.
   `tamper` alters that one scan and prints the command that restores it.
6. **Evaluation** shows precision and recall against ground truth on a held-out seed the
   scoring constants never saw, including the decoys designed to fool a naïve scanner.
7. **Findings** → *Export CSV* / *Export PDF*. The CSV carries `recommended_action` for a
   ticket queue; the PDF footer carries the Merkle root and transaction for the board.

## Hosted instance

_URL and viewer account are in the submission PDF._ See `docs/DEPLOY.md` for how it is run.

## Architecture

```
seed ─► Generator (12 simulated months, native AWS/Azure/GCP exports + HR feed + ground truth)
          │
          ▼
        Normaliser + linker ─► Postgres (Canonical Permission Model, raw snippet on every row)
          │
          ▼
        Diff · Rules R0–R10 · Access graph · Blast-radius score · Half-life
          │                      │
          ▼                      ▼
        Findings store ─────► LedgerWriter ─► Anvil (GovernanceLedger.sol: Merkle roots, proof-bound decisions)
          │
          ├─► Agents (investigate · plan least-privilege · executive summary; cached, fenced)
          └─► FastAPI + exports ─► React dashboard
```

Full detail in `docs/SPEC.md`; the reasoning in `docs/PRD.md`; what it defends against and
what it does not in `docs/THREAT_MODEL.md`.

## Verifying a report

```bash
make verify SCAN=12
```

recomputes the Merkle root of scan 12 from the database and compares it with the root
committed on-chain. To verify an exported report without the dashboard, write the files with
`make export` (CSV, the `findings.json` sidecar and the PDF, all into `data/exports/`) and then:

```bash
docker compose exec api athar verify --csv data/exports/findings.csv --json data/exports/findings.json
```

Each row's committed instance is re-hashed and its inclusion proof checked against the
on-chain root.

## Tests and evaluation

```bash
make test
```

```bash
make test-contracts
```

```bash
make eval
```

`make eval` reports precision / recall / F1 at High+ on the tuning seed (42) and the held-out
seed (7). Constants are tuned only on 42 and reported on 7. The current run:

```
seed 42: precision 0.96 recall 1.00 F1 0.98 (tp 46 fp 2 fn 0) at High+
seed 7: precision 1.00 recall 1.00 F1 1.00 (tp 48 fp 0 fn 0) at High+
  precision 1.00 / recall 1.00 at High+ on held-out seed 7
  Of 48 accounts flagged, 48 are verified genuine risks.
```

Eleven of eleven decoys are left alone on both seeds. The Evaluation page reads the held-out
result from `data/eval/results-7.json` rather than recomputing it, so run `make eval` again after
any re-seed or the page will keep showing the previous estate's numbers.

Both seeds come from `.env` (`ATHAR_SEED`, `ATHAR_EVAL_SEED`). To evaluate on a different
held-out seed, change `ATHAR_EVAL_SEED`, recreate the API container so it reads the new value,
then run the harness:

```bash
docker compose up -d api
```

```bash
make eval
```

The Evaluation page then shows that seed. Seed 7 happens to score perfectly; most others carry one
or two false positives, and the per-rule table on the page shows where.

```bash
make ci
```

`make ci` runs every job the GitHub Actions workflow runs: lint, the Python and frontend tests,
the production bundle, the contracts and their committed ABI, the evaluation gates on both sample
seeds, the security audits (`pip-audit`, `npm audit`, `gitleaks`) and `docker compose config`. It
is stricter than CI in one place — it runs the whole pytest suite where CI skips the `slow`
markers. Two steps announce themselves as skipped rather than passing quietly if the tool is
absent: `docker compose config` without the Docker CLI, and `gitleaks` when it is not installed.
Only `publish-images` has no local equivalent; it needs a registry token and runs on `main`.

## What a run produces

Seed 42, twelve months, 500 identities, on a laptop:

| | |
|---|---|
| Estate generated | 426 files across three providers, in about two seconds |
| Identities at month 12 | 507 (382 people, 125 service accounts) |
| Findings | 47 in month 1, rising to 99 in month 12 (21 critical, 47 high, 27 medium, 4 low) |
| Scans anchored | 12, one per month; month 12 commits root `0xc1559c8d30ae…` at chain index 11 |
| `make demo` end to end | about ninety seconds once the images have been built |
| Held-out evaluation (seed 7) | precision 1.00, recall 1.00 at High+; all eleven decoys correctly left alone |

## Known limitations

- The ledger proves a finding existed at a point in time and was not edited afterwards. It
  does not prove the finding is correct, and it does not protect against a compromised API
  host holding the writer key (production path: HSM key, per-approver wallets, permissioned
  chain). See `docs/THREAT_MODEL.md`.
- GCP has no UAE region; the GCP footprint is framed as a non-sovereign analytics workload
  under a documented exception, which is itself a governance talking point (`me-central1`
  is listed pending verification).
- Agents explain; the rule engine decides. With `LLM_PROVIDER=none` every agent falls back
  to deterministic templates, so the demo never depends on a network call.
- **R7 (peer outlier) fires on nothing in this estate, on either seed.** It is implemented,
  registered, tested and offered in the filters, but the generator gives almost every identity
  grants in all seven service categories, so the department median category count is already the
  maximum and R7's second term — "at least two categories more than peers" (`SPEC §7`) — can
  never be satisfied. Reading "more than peers" the other way, as categories fewer than half the
  department holds, does not rescue it either: measured on seed 42, that fires on nobody at all, in
  any of the twelve months. The statistical term on its own
  (grant count above the department median + 2·MAD) does select 25–47 identities a month, so
  dropping the category term would make R7 fire — but that is a change of rule semantics and a
  new tuning decision, not a bug fix, so it has not been made under the clock. The honest state
  is: nine of the eleven rules carry the demo; R7 is a rule whose second term this estate cannot
  satisfy.
- Every ATT&CK and control identifier ATHAR quotes carries a `(verify)` mark, including the ones
  that have been checked: the code marks unconditionally rather than consulting an allowlist, so
  it can never under-mark. `docs/MAPPINGS.md` is where you find out which are actually verified
  and against what source.
- Read the precision and recall numbers for what they are. Ground truth is written by the
  simulator from its own bookkeeping, in the same canonical vocabulary the rules use, so the two
  sides agree on definitions by construction and disagree only where the pipeline loses or
  distorts something. The evaluation is therefore a pipeline-recovery check — does the rule engine
  recover, from the written exports, what the simulator recorded doing? — on an estate whose seed
  the scoring constants never saw. It is not a claim about a real cloud estate. The part that does
  test judgement is the decoy set: eleven identities built to trip a naïve detector — seven
  legitimate only through an entry in the governance register, four through an HR `contract_end`
  in the future, never through a cloud-side tag — and the harness reports how many were correctly
  left alone. On both seeds it is currently eleven of eleven.

## Licence

Apache-2.0. See `LICENSE`.
