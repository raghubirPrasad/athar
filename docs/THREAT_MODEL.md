# ATHAR threat model

One page, STRIDE-lite, written for the engineer who will run `make demo` twice and then
try to break it. Companion to `docs/SPEC.md §12.1` (ledger limits) and `§15` (hardening).

## Assets

| Asset | Why it matters |
|---|---|
| Findings and identity scores | What a director acts on; must be the same thing an auditor sees a year later |
| Decisions (approve / reject / apply / exception) | Who authorised a change to a production estate, and when |
| Ledger writer key | Signs every on-chain commit; whoever holds it can write (never rewrite) history |
| LLM outputs (hypotheses, plans, summaries) | Prose that people trust; must never carry instructions smuggled in through IAM metadata |
| Demo accounts and JWT secret | Access to the dashboard and to the approver workflow |
| Synthetic estate on disk | The reproducible evidence base; forward-only by design |

## Trust boundaries

```
browser ──(cookie JWT, SameSite=Strict, X-Requested-With)──► API ──► Postgres
                                                              │
                                                              ├──► Anvil (JSON-RPC, local network only)
                                                              └──► LLM provider (aggregate/structured facts only)
```

- **Browser ↔ API.** Authenticated by an `httpOnly; SameSite=Strict` cookie; every mutating
  request also needs `X-Requested-With: athar`, so a cross-site form post cannot act.
- **API ↔ Postgres.** Single trusted service account; the DB is not exposed outside compose
  (host port is for local development only).
- **API ↔ Anvil.** Only `LedgerWriter` signs. One nonce owner per process.
- **API ↔ LLM.** Only structured canonical facts leave the host; provider free text is
  wrapped by `sanitize_untrusted()`; no identities reach the executive-summary agent.

## Threats and mitigations

| STRIDE | Threat | Mitigation | Where |
|---|---|---|---|
| Tampering | Someone edits a severity or deletes a finding in the scanner's own database after the report went to the board | Every scan is Merkle-committed on-chain; `athar verify` recomputes the root from the DB and compares; the tamper demo shows the badge turn red | `ledger/`, SPEC §12 |
| Tampering | A decision is recorded against a finding that was never in the scan | `recordDecision` reverts unless an OpenZeppelin `MerkleProof.verify` passes against the committed root | `GovernanceLedger.sol` |
| Tampering | Second-preimage games on the Merkle tree | Double-hashed leaves (domain separation from 64-byte internal nodes), sorted pairs, OZ-compatible construction with property tests | `ledger/merkle.py` |
| Spoofing | Prompt injection through IAM metadata (tags, display names, policy names) makes the agent mark an account safe | Agents receive structured facts; free text is truncated, stripped and wrapped as `untrusted_text`; output is schema-validated, action must be in `allowed_actions`, identifiers not in the input are redacted; severity and score never touch the model. Test: `tests/agents/test_injection.py` | `agents/guard.py`, SPEC §11.3 |
| Elevation | The model "decides" something is safe | Structurally impossible: no LLM output can create a finding, change a severity or score, or choose an action outside the rule's set | SPEC §11.1, CLAUDE.md non-negotiable 5 |
| Elevation | An engineer with cloud tagging rights hides their own finding | Exceptions come only from the governance register (approver, review date); cloud tags are displayed as evidence, never read as exceptions | SPEC §4.3, rules R1/R2 |
| Elevation | An analyst approves their own remediation plan | Separation of duties enforced server-side: proposer ≠ approver; `apply` requires `approved`; the auto-remediation flag needs an approver | `api/routers/remediation.py`, SPEC §15.1 |
| Elevation | Viewer account (given to judges) mutates state | RBAC on every route; viewer is read-only; mutating routes require analyst or approver | `security/rbac.py` |
| Denial | Oversized or malformed uploads crash the ingest | 10 MiB limit, JSON depth limit, UTF-8 check, provider-specific pydantic schemas, unknown roles → `R0` finding; robustness fixtures in CI | `normaliser/schemas.py`, `tests/robustness/` |
| Denial | Credential stuffing on `/auth/login`, or burning the LLM quota through the agent endpoints | Rate limits 5/min/IP on login, 20/min/IP on agents; LLM cache by content hash so the demo runs warm | `security/limits.py` |
| Information disclosure | Stack traces or internal paths leak to clients | RFC 7807 problem+json with stable codes; catch-all handler logs and returns `internal.error` | `api/problem.py` |
| Information disclosure | Tokens in localStorage read by injected script | Token lives only in an `httpOnly` cookie; CSP `default-src 'self'` on the web tier | `frontend/nginx.conf`, SPEC §13 |
| Information disclosure | IAM data on a public chain | Only hashes, counts and timestamps are ever written on-chain | SPEC §12.1 |
| Repudiation | "I never approved that" | Decision carries `actorHash = keccak256(user_id)` and an evidence hash binding plan, action, model id and prompt version; audit log row per transition | `ledger/writer.py`, `audit_log` |
| Supply chain | Malicious dependency or leaked secret in the repo | Pinned dependencies, `pip-audit`, `npm audit --audit-level=high`, `gitleaks` in CI; `.env` never committed | `.github/workflows/ci.yml` |

## What the ledger does not protect against

Stated on the Ledger page and repeated here because judges will ask.

- **A compromised API host holding the writer key.** Whoever holds the key can append true or
  false commits. It cannot rewrite history, and every commit is attributable to the key, but
  the prototype has one key on one host. Production path: HSM-backed key, per-approver
  wallets so a decision is signed by the person, and a permissioned chain shared with the
  audit function.
- **Wrong findings.** The ledger proves a finding existed at a point in time and was not
  edited afterwards. It does not prove the finding was correct; the evaluation harness does that.
- **Availability.** If Anvil is down the scan still completes and is marked `unanchored`;
  a background retry drains the queue. The ledger never blocks the pipeline.

## Residual risks (accepted for the prototype)

1. Writer key on the API host (above).
2. The LLM provider sees aggregate statistics and structured, sanitised facts. It never sees
   raw IAM exports, ARNs or email addresses. With `LLM_PROVIDER=none` nothing leaves the host.
3. Demo passwords in `.env.example` are placeholders; the hosted instance uses real ones and
   `ATHAR_DEV=false`, which refuses the example JWT secret.
4. No refresh-token flow; sessions are 12 hours. Acceptable for a demo, not for production.
5. Anvil is a single local node with `--state`; it is a tamper-evidence device, not a
   consensus network.
6. Two moderate `react-router` advisories stand, both fixed only in `react-router-dom@7`, a major
   upgrade that rewrites every route in the app. They sit below the `--audit-level=high` gate
   `make security` and CI enforce, and they are recorded here rather than passed over silently.
   *Constructor injection in `deserializeErrors()`* is server-side-rendering hydration; ATHAR
   ships a static bundle and renders nothing on the server, so the code path does not exist here.
   *Open redirect via a backslash in `<Link>` / `useNavigate`* did reach us: the one place a
   destination is not a route constant is the post-login redirect, and its guard checked for a
   leading `/` and a leading `//` only. A browser normalises `/\evil.example` to `//evil.example`
   while parsing, and strips tabs and newlines before parsing, so both forms walked through it.
   `frontend/src/auth/redirect.ts` now rejects any control character and any leading separator of
   either kind, which holds whatever router version is installed. Upgrade the router anyway
   before this is anything but a prototype.
