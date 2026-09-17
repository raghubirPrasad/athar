"""Run the real AWS export through ATHAR's pipeline and emit the JSON the dashboard's
Real-export panel reads (frontend/public/real-export.json). Read-only: no DB, no ledger."""

from __future__ import annotations

import collections
import datetime as dt
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "backend"))

from athar.detection.registry import get_rule, run_all  # noqa: E402
from athar.domain import Thresholds  # noqa: E402
from athar.normaliser.pipeline import (  # noqa: E402
    normalise_provider,
    provider_rows_to_month,
    to_estate_view,
)

SRC = REPO / "real_exports/aws-authorization-details.json"
OUT = REPO / "frontend/public/real-export.json"

data = SRC.read_bytes()
rows = normalise_provider("aws", 1, {"authorization-details.json": data}, hr=None)
estate = to_estate_view(provider_rows_to_month(rows))
drafts = run_all(estate, Thresholds())

by_rule = collections.Counter(d.rule_id for d in drafts)
sev_of = {rid: get_rule(rid).severity for rid in by_rule}
by_sev = collections.Counter(sev_of[d.rule_id] for d in drafts)
idents_flagged = {d.identity_id for d in drafts}


def rule_row(rid: str) -> dict:
    spec = get_rule(rid)
    return {"rule_id": rid, "name": spec.name, "severity": spec.severity, "count": by_rule[rid]}


rule_rows = sorted(
    (rule_row(r) for r in by_rule),
    key=lambda r: (int(r["rule_id"][1:]) if r["rule_id"][1:].isdigit() else 99),
)

# sample High/Critical principals, de-duplicated by leaf name, order preserved
samples: list[dict] = []
seen: set[str] = set()
for d in drafts:
    if get_rule(d.rule_id).severity not in ("High", "Critical"):
        continue
    leaf = d.identity_id.split("/")[-1].split(":")[-1]
    if leaf in seen:
        continue
    seen.add(leaf)
    samples.append({"rule_id": d.rule_id, "name": leaf})
    if len(samples) >= 14:
        break

payload = {
    "source": "Cloudsplaining example estate (Salesforce, BSD-3) — native aws "
    "get-account-authorization-details; account IDs sanitised to 012345678901",
    "generated_at": dt.datetime.now(dt.UTC).isoformat(timespec="seconds"),
    "file_bytes": len(data),
    "principals": len(rows.principals),
    "grants": len(rows.grants),
    "unmapped_actions": len(rows.unmapped),
    "findings_total": len(drafts),
    "identities_flagged": len(idents_flagged),
    "by_severity": {k: by_sev.get(k, 0) for k in ("Critical", "High", "Medium", "Low")},
    "rules": rule_rows,
    "samples": samples,
    # R7 counts on real data vs zero on the synthetic estate — the headline of this panel.
    "r7_real": by_rule.get("R7", 0),
    "r7_synthetic": 0,
}

OUT.parent.mkdir(parents=True, exist_ok=True)
OUT.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
print(f"wrote {OUT} ({OUT.stat().st_size} bytes)")
print(json.dumps({k: payload[k] for k in ("findings_total", "identities_flagged", "r7_real", "by_severity")}, indent=2))
