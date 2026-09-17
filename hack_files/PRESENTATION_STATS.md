# ATHAR — presentation stat sheet

Every number for the deck, with its source so you can defend it on stage. Numbers are the
current run; regenerate with the command shown if you re-seed.

## Jury (Stage 2)

| Stat | Value | Source |
|---|---|---|
| Case score | **100 / 100** | `hack_files/remarks.md` |
| Fit to brief | 20/20 | remarks.md |
| Relevance | 15/15 | remarks.md |
| Prototype works | 25/25 | remarks.md |
| Technical depth | 25/25 | remarks.md |
| Innovation | 15/15 | remarks.md |
| The one gap they named | "validate on real-world cloud exports" | remarks.md (jury comment) |

## Synthetic estate — scale (the demo)

| Stat | Value | Source |
|---|---|---|
| Identities at month 12 | **507** (382 people, 125 service accounts) | `README.md` "What a run produces" |
| Native files generated | 426 across 3 providers, ~2 s | README.md |
| Findings, month 1 → 12 | 47 → **99** (21 critical, 47 high, 27 medium, 4 low) | README.md |
| Scans anchored on-chain | 12 (one per month) | README.md |
| Month-12 Merkle root | `0xc1559c8d30ae…` at chain index 11 | README.md |
| `make demo` end-to-end | ~90 s (after image build) | README.md |

## Detection quality — measured (the "is it correct" story)

| Stat | Value | Source |
|---|---|---|
| Held-out seed 7: precision / recall / F1 | **1.00 / 1.00 / 1.00** (tp 48, fp 0, fn 0) | `data/eval/results-7.json` |
| Tuning seed 42: precision / recall / F1 | 0.958 / 1.00 / 0.979 (tp 46, fp 2, fn 0) | `data/eval/results-42.json` |
| Decoys correctly left alone | **11 / 11** on both seeds | results-{7,42}.json |
| Regenerate | `make eval` | — |

> **Say this out loud on stage:** the synthetic 1.00 is a *pipeline-recovery* check — ground truth
> is written by the same simulator, so it measures whether the engine recovers what the simulator
> recorded, not real-world accuracy. Leading with that honesty defuses the "too good to be true"
> reaction. Full reasoning: `README.md` "Known limitations" and `real_exports/RESULTS.md`.

## Real AWS export — the new evidence (closes the jury's gap)

Run: `python real_exports/build_panel_json.py` · Live: dashboard → **Real export** tab.

| Stat | Value | Source |
|---|---|---|
| Real principals parsed | **122** | `real_exports/RESULTS.md`, `frontend/public/real-export.json` |
| Canonical grants | 1124 | real-export.json |
| Findings | **318** across 122 principals | real-export.json |
| High / Critical | 90 | real-export.json |
| R1 admin/wildcard | 17 (incl. `OrganizationAccountAccessRole`, `AWSReservedSSO_AdministratorAccess`) | real-export.json |
| R5 toxic combination (privesc) | 73 (incl. `privesc-sre-role`, `privesc-AssumeRole-ending-role`) | real-export.json |
| **R7 peer outlier** | **36 on real vs 0 synthetic** | real-export.json |
| Unmapped actions (mapping-coverage work item) | 2512 → surfaced as R0 | real-export.json |
| Source estate | Cloudsplaining fixture (Salesforce, BSD-3), sanitised | `real_exports/SOURCE.md` |

## Three numbers to put on the title slide

1. **100/100** jury score, through to the final.
2. **507 identities, 3 clouds, one model** — over 12 simulated months of drift.
3. **318 findings on a real AWS export** — R7 fires on real data where the synthetic estate can't.
