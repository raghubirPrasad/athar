"""Smoke test: exercise the MCP tools against the live API and prove the fence.

Reads passwords from the environment (never hardcoded):
    ATHAR_ANALYST_PASSWORD=... ATHAR_JUDGE_PASSWORD=... python smoke_test.py
"""
import json
import os
from client import AtharClient, AtharError

ANALYST_PW = os.environ["ATHAR_ANALYST_PASSWORD"]
JUDGE_PW = os.environ["ATHAR_JUDGE_PASSWORD"]

an = AtharClient(email="analyst@athar.local", password=ANALYST_PW)

print("== estate_summary ==")
s = an.get("/estate/summary")
print(json.dumps({k: s.get(k) for k in list(s)[:8]}, default=str)[:300])

print("\n== list_identities (-score, top 3) ==")
ids = an.get("/identities", {"sort": "-score", "limit": 3})
items = ids.get("items", ids if isinstance(ids, list) else [])
for it in items[:3]:
    print(" ", it.get("identity_id"), "score", it.get("score"), it.get("department"))

print("\n== list_findings High, top 3 ==")
fs = an.get("/findings", {"severity": "High", "limit": 3})
fitems = fs.get("items", [])
top_key = fitems[0]["finding_key"] if fitems else None
for f in fitems[:3]:
    print(" ", f.get("finding_key"), f.get("rule_id"), f.get("identity_id"))

if top_key:
    print(f"\n== explain_finding {top_key} (altitudes present?) ==")
    ef = an.get(f"/findings/{top_key}")
    print("  keys:", [k for k in ef if k in ("altitudes", "score", "evidence", "merkle_leaf", "rule_id")])

    print("\n== propose_remediation (analyst, propose only) ==")
    try:
        plan = an.post(f"/agent/plan/{top_key}")
        print("  plan action:", plan.get("action"), "reduction%:", plan.get("privilege_reduction_pct"))
    except AtharError as e:
        print("  (plan error)", str(e)[:160])

print("\n== FENCE: judge (viewer) must NOT be able to propose ==")
judge = AtharClient(email="judge@athar.local", password=JUDGE_PW)
print("  judge can read identities:", bool(judge.get("/identities", {"limit": 1})))
try:
    judge.post(f"/agent/plan/{top_key or 'x'*32}")
    print("  !! FENCE BREACH: judge proposed a plan")
except AtharError as e:
    print("  fence holds — judge blocked:", str(e)[:120])
