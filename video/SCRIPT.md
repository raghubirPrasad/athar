# ATHAR demo video — voiceover script

Runtime **≈1:29** (1920×1080, 30 fps, 2670 frames). Eighteen short beats, cut fast.
Leaves ~5½ minutes of the 7-minute budget for the deck and live Q&A.

Delivery: brisk but unhurried. The app carries the story; the words point at things.
Each block below maps to one beat on screen.

---

| # | Time | On screen | Say |
|---|---|---|---|
| 1 | 0:00 | Logo draws in | *ATHAR — multi-cloud access governance.* |
| 2 | 0:03 | Overview, wide | *One government estate, across AWS, Azure and GCP.* |
| 3 | 0:08 | Punch to stat tiles | *Five hundred and seven identities — in a single model.* |
| 4 | 0:13 | Punch to department cards | *And the offboarding half-life reads Never. Access is granted, and almost never taken away.* |
| 5 | 0:18 | Identities table, cursor clicks | *Every identity, ranked by risk.* |
| 6 | 0:23 | Punch to score column | *The score is measured blast radius — the share of the estate each one can actually reach. Not a number we invented.* |
| 7 | 0:28 | Punch to cloud chips | *The top rows hold admin in all three clouds at once — the finding no single console can show you.* |
| 8 | 0:32 | Drill-down opens | *Open one, and the score is completely in the open.* |
| 9 | 0:37 | Punch to the formula + callout | *You can read the formula, term by term: reach, exploitability, controls — capped at a hundred.* |
| 10 | 0:43 | Punch to causal history | *And the exact grants, month by month, that caused it. Not just what — why, and since when.* |
| 11 | 0:48 | Timeline | *Time is the primary axis. A year of drift replayed — findings climbing from forty-seven to ninety-nine.* |
| 12 | 0:54 | Punch to half-life | *Permission half-life per department: a broken process, not twelve risky people.* |
| 13 | 0:58 | Real export | *Then we point the same engine at a real AWS export. No changes.* |
| 14 | 1:02 | Punch to real stats | *A hundred and twenty-two real principals. Three hundred and eighteen findings. And the peer-outlier rule, which fires on nothing synthetic, fires thirty-six times on real data.* |
| 15 | 1:08 | Punch to rule table | *Landing on genuinely administrative and privilege-escalation roles.* |
| 16 | 1:12 | Ledger | *Every scan anchored to a Merkle ledger — a regulator verifies it without trusting us.* |
| 17 | 1:17 | MCP terminal types out | *And over MCP, any AI can query it. An analyst can propose a plan; a viewer is blocked — four-oh-three. The model can look and suggest. It can never decide, or act.* |
| 18 | 1:25 | Close | *ATHAR. Every permission leaves a trace. Give us the exports — we'll give you the record.* |

---

## Notes

- **No baked-in audio.** Narrate live over it, or record and mux:
  `ffmpeg -i athar.mp4 -i vo.mp3 -c:v copy -c:a aac -shortest athar_vo.mp4`
- **If you must cut**, drop beats 15 and 16 (rule table, ledger) — both re-appear in the deck.
  Never cut 9, 10 or 14: the formula, the causal history and the real-data result are the
  differentiators.
- Numbers match the current seed-42 run and the real-export panel. Re-check them if you re-seed.
- Re-render after any change: `cd video && npm run render`. Timing lives in the `D` map at the
  bottom of `src/Video.tsx` — every value is frames at 30 fps.
