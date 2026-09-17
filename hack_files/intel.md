# INTEL — School of Cyber Defence @ GISEC Global 2026

Compiled 16 September 2026. Sources are public web pages listed in §10, each with a confidence
mark. Anything marked `(unconfirmed)` came from one source only or from a page that contradicts
another source — treat it as a question for the organisers, not a fact to build on.

**Our topic:** Multi-Cloud Access Governance Dashboard · Difficulty: Intermediate · 6 of 6 teams
selected it. Our build is ATHAR (`docs/SPEC.md`, `docs/PRD.md`).

**Time remaining:** final is **18 September 2026**. Two days.

---

## 1. Bottom line, for the person with thirty seconds

1. Every one of the six teams picked our topic. Nothing in the minimum deliverable list
   differentiates us — all six will have a normaliser, five rules, a risk-sorted table and a CSV.
   The grade separates on **"prototype works" (25%)** and **"technical depth & correctness" (25%)**,
   which is where most hackathon builds are weakest and where a second `make demo` run, measured
   precision/recall and verifiable evidence actually show up. See §5.
2. The final is a **live stage pitch with jury Q&A**, not a code review. Judges are practitioners.
   Rehearse the walk-through in the brief's own words ("open the dashboard on a 500-identity
   estate, sort by risk, walk through the top three findings and the evidence behind each"), and
   rehearse being interrupted mid-demo. See §6, §7.
3. The organiser is **DESC** (Dubai Electronic Security Center) — a government regulator. The
   framing that lands is a government shared-services estate, UAE data residency, and an audit
   trail. That framing is already in `docs/PRD.md §3–§4`; keep the language consistent on stage.
4. Two live risks with hard deadlines: venue ambiguity (§2.2) and demo fragility (§8). Resolve both
   before rehearsal, not on the morning.

---

## 2. The event

### 2.1 GISEC Global 2026

| | |
|---|---|
| What | Gulf Information Security Expo & Conference — largest cybersecurity event in MEA |
| Dates | **16–18 September 2026** (Tue–Thu) |
| Scale | 25,000+ attendees claimed, 180+ countries, CISOs / InfoSec leaders / ethical hackers |
| Theme 2026 | AI, emerging tech, "Cyber First" launched this edition |
| Contact | `gisec@dwtc.com` · +971 4 308 6469 (organiser is Dubai World Trade Centre) |

### 2.2 Venue — unresolved conflict, act on this

Two venues appear across official sources and they are **not the same place**:

- `gisec.ae` front page: **Dubai World Trade Centre (DWTC)** — Sheikh Zayed Road, the traditional
  GISEC home.
- `gisec.ae/student-ctf-school-of-cyber-defense`, techfirm.ae and all 2026 press releases:
  **Dubai Exhibition Centre (DEC), Expo City Dubai** — Jebel Ali / Expo site, ~30 km further out,
  different metro line (Route 2020), different parking.

For the student competition specifically, **three independent sources say DEC Expo City**, so that
is the working assumption. But the difference is an hour of Dubai traffic and a missed slot.

> **Action:** confirm the exact hall, stage and arrival time by email/WhatsApp with the organiser
> before the evening of 17 September. Plan transport for DEC Expo City; keep DWTC as fallback.

### 2.3 Organisers and who is in the room

| Role | Who |
|---|---|
| Competition operator | Tech Firm Technology LLC (`techfirm.ae`, `scd.techfirm.ae`) |
| Government collaborator | **Dubai Electronic Security Center (DESC)** — Dubai's cyber regulator |
| Strategic technology partner | AMD |
| Partners providing mentors / exposure | Kaspersky, HPE, Huawei, others (industrial / gold / silver tiers) |
| Jury | "Industry experts", practitioners — described as "people who do this every day" |

DESC's presence matters for content: DESC authors the **Information Security Regulation (ISR)** that
Dubai government entities must comply with. Our control mapping (`docs/MAPPINGS.md`, PRD F17) points
at UAE IA / DESC ISR / ISO 27001. Any identifier shown on stage must be verified against the primary
source or carry the `(verify)` mark — CLAUDE.md rule, and in this room it is also a credibility
risk: someone in the audience wrote the regulation.

### 2.4 Format and timeline

Second edition of the competition. Eligibility: UAE university students, 17+, CS / engineering /
infosec and related. Teams of **up to 5**; universities may enter multiple teams.

| Stage | Dates | What |
|---|---|---|
| Registration & verification | until 1–3 Sep 2026 *(sources differ: 1 Sep vs 3 Sep)* | manual review, student ID verification |
| Stage 1 — online qualification | until 6 Sep | five themed technical blocks; server-side timers, autosave, forward-only answers |
| Stage 2 — case study & jury review | 7–11 Sep | **PDF, max 5 pages**, team picks a topic for deeper analysis |
| Finalists announced | 10 Sep *or* 14 Sep `(unconfirmed — sources conflict)` | top 5 teams |
| Mentorship | 11–17 Sep | mentors from DESC / industry partners |
| **Stage 3 — offline final** | **18 Sep** | live pitch on stage + jury Q&A, live scoreboard, award ceremony |

Stage 1 themes were: network defence (segmentation, access control), threat management
(identification, prioritisation), system security (hardening, vulnerability management), incident
response (containment, investigation, communication).

The stage is reported as the **"Dark Stage"** at GISEC, with a live scoreboard and the award ceremony
immediately after `(unconfirmed on stage name)`.

### 2.5 Prizes

- **AED 20,000** total, split across the top three teams (all 2026 press releases agree).
- `gisec.ae` also advertises "prize pool worth more than AED 50,000" on the Student CTF page —
  that figure most likely covers the **separate attack/defence CTF track**, not this competition
  (see §2.6). Do not quote AED 50,000 as ours.

### 2.6 Do not confuse the two tracks

`gisec.ae` lists a **School of Cyber Defense (CTF)** running 16–18 Sep, 10:00–17:00, described as
**attack/defence**, 10 teams × 5 members, difficulty **Intermediate**, prize pool AED 50,000+. That
is a live-fire CTF format.

Our track is the **build / case-study competition**: pick a topic, build a solution, defend it in
front of a jury. Same programme name, same difficulty label, different game. Some press coverage
blurs them. When reading any source about "the competition", check whether it says *attack/defence*
or *case study and presentation* — only the latter describes what we are graded on.

---

## 3. The brief, verbatim

> **Multi-Cloud Access Governance Dashboard** — Difficulty: Intermediate
>
> **Why this matters.** Government bodies run hybrid estates across several clouds. Permissions
> drift: people keep access after changing roles, service accounts outlive their projects, and
> nobody has one view of who can do what.
>
> **What to build.** A dashboard that ingests permission data from several simulated cloud accounts
> (AWS/Azure/GCP-style) into one model and flags over-privileged users, orphaned accounts, and risky
> combinations.
>
> **Minimum deliverable (what we grade).**
> 1. Synthetic but realistic IAM data for at least three providers, with different native formats.
> 2. A normaliser mapping provider-specific roles into one common permission model.
> 3. Detection rules: admin/wildcard privileges, unused access (no activity in N days), accounts of
>    departed staff, users with the same power across all three clouds, toxic combinations
>    (e.g. create-role + assign-role).
> 4. A dashboard: identity list with risk scores, drill-down into why an identity was flagged,
>    filters by cloud/department.
> 5. An exportable findings report (CSV or PDF).
>
> **What the demo should show.** Open the dashboard on a 500-identity estate, sort by risk, and walk
> through the top three findings and the evidence behind each.

Six of six teams selected it.

### 3.1 Reading the brief closely

Things the wording commits us to, that are easy to miss:

- **"with different native formats"** — not three files with a `provider` column. AWS must look like
  an IAM policy document with `Statement`/`Action`/`Resource` and wildcards; Azure like a role
  assignment with `roleDefinitionId`, `principalId`, `scope`; GCP like an IAM policy `bindings`
  array with `role` + `members` (`user:`, `serviceAccount:`). A judge will open the raw JSON.
  Covered: `SPEC §4.6`, and each mapping has a test parsing the raw snippet (CLAUDE.md conventions).
- **"unused access (no activity in N days)"** — **N is a parameter**, so it must be configurable,
  not a literal. Ours: `DORMANT_DAYS=90`, `STALE_KEY_DAYS=180`, env-declared in `config.py`.
  Expect the question "what if I set it to 30?" — be able to change it live.
- **"accounts of departed staff"** — implies an **HR feed** as a second source of truth, not a cloud
  signal. This is the deliverable most teams under-build; it is also the one that produces the best
  narrative ("the estate does not know this person left in March").
- **"the same power across all three clouds"** — requires the canonical model to make powers
  *comparable* across providers. This bullet is the actual justification for the normaliser
  existing, and the cleanest thing to show on stage: one person, three providers, one sentence.
- **"toxic combinations (e.g. create-role + assign-role)"** — "e.g." means the example is a floor.
  Privilege-escalation reasoning is expected; showing the escalation *chain* exceeds it.
- **"drill-down into why an identity was flagged"** — "why", not "what". Evidence and causation,
  not a rule name. Our three-altitude rendering and causal history answer exactly this bullet.
- **"exportable findings report (CSV or PDF)"** — "or". Doing both is cheap and reads as thorough;
  the column that matters to a practitioner is `recommended_action`.
- **"500-identity estate"** — the demo must be fast at 500 identities, with a risk sort that is
  meaningful, not a table that takes eight seconds to paint.

---

## 4. Since all six teams chose this topic

Assume every competitor delivers the five minimum bullets. Assume also — from how hackathon builds
usually go — that most will have:

- point-value risk scores invented by hand (`admin = 40`, `dormant = 20`) with no defence of the
  numbers;
- a single snapshot, no notion of time;
- no measurement of whether the rules are right;
- a demo run from a dev server and a database that was hand-fixed an hour earlier;
- an LLM somewhere in the scoring path, usually unexamined.

That predicts the questions the jury will have been forced to ask five times before us, and where a
different answer registers:

| Likely jury probe | Weak answer | Our answer | Where |
|---|---|---|---|
| "Why is this a 78?" | "That's our weighting" | line-item drill-down; blast radius measured as reachable resources / estate | `SPEC §8`, F8 |
| "How do you know the rules are right?" | "We tested it manually" | precision/recall vs ground truth, 11 decoys, tuned on seed 42, **reported on held-out seed 7** | `SPEC §17`, F11 |
| "Does the AI decide this?" | "It helps score" | rule engine decides; LLM only explains; injection test in CI | CLAUDE.md #5, F14 |
| "Can I run this?" | a laptop with a warm dev server | `make demo`, three commands, clean second run | `SPEC §18`, F6 |
| "Would I trust this report in an audit?" | "It's exported" | `make verify` recomputes the Merkle root and checks it against the chain | `SPEC §12`, F13 |
| "What does this tell me to do Monday?" | "review these users" | Permission Half-Life per department — a process finding, not a list | F10 |

The differentiator to lead with is **time**: drift is a rate, not a state (PRD §2). Five other teams
will show a snapshot. That is the single strongest framing we have, and it is already built.

---

## 5. Grading — the rubric we are working to

Recorded in `docs/SPEC.md §20`; reproduced here so this doc stands alone.

| Criterion | Weight | What the judge actually sees |
|---|---|---|
| Fit to the brief | 20% | every bullet of the minimum deliverable, a named buyer, what it replaces, a demo following the brief's own script |
| Relevance | 15% | rules + graph analysis over a canonical model, agents fenced to explanation/remediation, on-chain attestation for audit, UAE residency and control mapping |
| **Prototype works** | **25%** | `make demo` in three commands; clean second run; malformed uploads rejected; CI badge; hosted URL; demo accounts |
| **Technical depth & correctness** | **25%** | native-format fidelity, wildcard expansion tests, blast radius from reachability, measured precision/recall with decoys, OZ-compatible Merkle, single-writer nonce, proof-bound decisions, injection-defended agent |
| Innovation | 15% | time as primary axis, Permission Half-Life, findings with a birth certificate, three altitudes, remediation you can approve and see take effect, reports verifiable without trusting us |

**Half the grade (50%) is "it works" + "it is correct."** Neither is a feature you can add on the
last morning. Both decay if anyone lands a change without running `make ci`. This is the reason
CLAUDE.md's non-negotiables are written as bugs rather than style issues.

Corollary for the last 48 hours: **a P2 feature that risks the demo path is negative expected
value.** Cutting is cheap (PRD lists what to cut); a broken `make demo` in front of the jury is not
recoverable.

---

## 6. The final — stage format and what to prepare

Known: live presentation, on stage, jury Q&A, live scoreboard, award ceremony same day. Not
published: slot length, whether we present from our own laptop, whether internet is available, screen
resolution/aspect, whether slides are pre-submitted.

> **Action — confirm with organisers before 17 Sep evening:** pitch duration · Q&A duration · own
> laptop or house machine · HDMI/USB-C and adapter · internet access on stage (and whether it is
> filtered) · display aspect ratio · slide deck submission deadline and format.

Prepare for the worst case of each:

| Unknown | Prepare for |
|---|---|
| Slot might be 5 minutes | a 5-minute version that still hits sort → top 3 → evidence → export |
| No internet | fully local `make demo`; agent outputs cached; no live LLM call on the demo path (CLAUDE.md) |
| House laptop only | recorded screen capture of the full walk-through as fallback, plus hosted URL |
| Projector at 1024×768 / 16:9 crop | UI legible at low resolution; severity never colour-only (already a convention) |
| Q&A hostile / interrupting | every claim traceable to a screen we can reach in two clicks |

Two people on stage is usually right: one drives, one narrates. Decide who answers a question none of
us expected, and decide that now rather than in front of the jury.

---

## 7. Demo script for the final

The brief prescribes it. Follow its wording — judges recognise their own script and score fit
against it.

1. **One sentence of problem.** Government estate, three clouds, nobody has one view. (PRD §2.)
2. **Open the dashboard on the 500-identity estate. Sort by risk.** Do not explain the architecture
   first; show the artefact.
3. **Top finding — drill down.** Why flagged → evidence rows (`grant_id`, the raw provider snippet)
   → score line items. This is the "why" bullet of the brief, and the moment technical depth is
   visible.
4. **Second finding — cross-cloud.** Same identity, administrative power in all three providers,
   one sentence. This is the bullet that only exists because the normaliser exists.
5. **Third finding — departed staff or toxic combination.** Show the HR feed as the second source of
   truth, or the escalation chain.
6. **Filters.** By cloud, by department — brief bullet 4, ten seconds.
7. **Export.** CSV / PDF, point at `recommended_action`. Brief bullet 5.
8. **Then, and only then, the differentiators** — as much as the clock allows, in this order:
   drift over time / Permission Half-Life · measured precision/recall on the held-out seed ·
   `make verify` against the chain · propose → approve → apply → re-scan and risk drops.

Rule for the stage: **minimum deliverable first, differentiators second.** Fit is 20% and it is
scored on the brief's bullets. A judge who does not see bullet 5 will not award it because we showed
something cleverer instead.

Keep `docs/DEMO.md` as the authoritative runbook; this section is the narrative over it.

---

## 8. Risks, next 48 hours

| Risk | Impact | Mitigation |
|---|---|---|
| Venue confusion (DWTC vs DEC Expo City) | miss the slot | §2.2 — confirm in writing; plan for DEC; leave early |
| Unknown slot length | over-run, cut off before export | rehearse 5-minute and 10-minute cuts |
| Live LLM call on demo path | rate limit or timeout on stage | already forbidden (CLAUDE.md); verify cache is warm and regenerate is explicit |
| Second `make demo` not clean | direct hit on 25% criterion | run it twice on a clean machine before travelling; not on the machine that has been building all week |
| Late feature breaks demo path | unrecoverable on stage | feature freeze; after freeze, only fixes on the demo path; `make ci` before every commit |
| Quoting an unverified ISR / IA / ATT&CK identifier in front of DESC | credibility | `(verify)` mark rule; check `docs/MAPPINGS.md` before the deck is final |
| Quoting AED 50,000 prize or the wrong track's format | minor credibility | §2.5, §2.6 |
| Judge opens raw JSON and it does not look native | direct hit on technical depth | `SPEC §4.6` fidelity; re-read one export of each provider with fresh eyes |
| Any real domain / ARN / entity name in the data | disqualifying-level embarrassment | `nda.example` only; Nahar Digital Authority is fictional; `gitleaks` in CI |

---

## 9. Open questions for organisers / mentors

Ask by the evening of 17 September:

1. Exact venue, hall and stage; arrival and setup time.
2. Pitch length, Q&A length, order of teams.
3. Own laptop or house machine? Adapters? Aspect ratio?
4. Internet on stage — available, filtered?
5. Deck: pre-submission required? Format? Deadline?
6. Do judges get repository access, or is it presentation only?
7. Is the Stage 2 PDF in front of the jury, or does the pitch stand alone?
8. Scoring: is the live scoreboard the jury score, or is Stage 1/2 carried forward?

Question 8 changes strategy: if earlier stages carry weight, the pitch defends an existing position;
if not, everything rides on the 18th.

---

## 10. Sources

Retrieved 16 September 2026.

- [GISEC Global 2026 — official site](https://gisec.ae/) — dates 16–18 Sep, DWTC, scale claims. High confidence on dates; venue conflicts with student-track pages.
- [GISEC — Student CTF / School of Cyber Defense](https://gisec.ae/student-ctf-school-of-cyber-defense) — DEC Expo City, 10:00–17:00, attack/defence, 10×5 teams, Intermediate, AED 50,000+. **This page describes the CTF track (§2.6).**
- [Tech Firm Technology — School of Cyber Defence CTF 2026](https://techfirm.ae/ctf/2026/) — full stage timeline, team size, 5-page PDF, mentorship, venue DEC. Highest-detail source for our track.
- [ZAWYA press release — School of Cyber Defense returns for 2026](https://www.zawya.com/en/press-release/companies-news/from-campus-to-gisec-global-school-of-cyber-defense-returns-for-2026-in-collaboration-with-dubai-electronic-security-center-469534) — DESC collaboration, AMD, partners, AED 20,000, eligibility.
- [Security MEA — School of Cyber Defense Competition Returns](https://securitymea.com/2026/08/27/school-of-cyber-defense-competition-returns-to-gisec-global-2026/) — top 5 to final, top 3 prizes, mentorship window, AI/emerging-tech focus.
- [WAM — DESC launches School of Cyber Defence at GISEC Global 2026](https://www.wam.ae/en/article/c1w8zou-dubai-electronic-security-centre-launches-school) — official DESC announcement. Page body did not render on fetch; details taken from search summary, so treat specifics as secondary.
- [Intelligent CISO — GISEC Global 2026 opens](https://www.intelligentciso.com/2026/09/15/gisec-global-2026-opens-tomorrow-in-dubai-as-global-cyber-leaders-converge-to-shape-the-next-digital-era/) — event scale and 2026 themes.
- [Dubai Exhibition Centre — GISEC 2026](https://www.dubaiexhibitioncentre.com/en/whats-on/gisec-2026) — venue listing supporting DEC Expo City.
- [CXO Insight ME — GISEC Global 2026 launches Cyber First](https://www.cxoinsightme.com/future/tech/gisec-global-2026-launches-cyber-first/) — context on this edition's framing.

Internal, authoritative over anything above for what we build:
`docs/SPEC.md` (contract, §20 rubric traceability) · `docs/PRD.md` (why, priorities, cut list) ·
`docs/DEMO.md` (runbook) · `CLAUDE.md` (non-negotiables).

---

## 11. Conflicts to resolve, in one place

| Item | Source A | Source B | Working assumption |
|---|---|---|---|
| Venue | DWTC (`gisec.ae` home) | DEC Expo City (student pages, techfirm, all press) | **DEC Expo City** — confirm |
| Registration close | 1 Sep (press) | 3 Sep (techfirm) | moot, passed |
| Finalists announced | 10 Sep (Security MEA) | 14 Sep (techfirm) | moot, we are in |
| Prize pool | AED 20,000 (press, our track) | AED 50,000+ (`gisec.ae` CTF page) | AED 20,000 for our track |
| Format | case study + pitch (techfirm, press) | attack/defence (`gisec.ae` CTF page) | **case study + pitch** — two distinct tracks (§2.6) |
