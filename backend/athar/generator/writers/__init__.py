"""Native export writers (SPEC §4.6). Pure: state in, file text out.

Each provider module turns a `MonthSnapshot` (plus the `EstateState` for the HR registers and
the account/subscription/organisation constants) into the exact export shapes a real
`aws iam get-account-authorization-details`, `az role assignment list --all` or
`gcloud projects get-iam-policy` produces. Nothing here touches the filesystem — `estate.py`
owns every side effect — and nothing calls `random`, `uuid4()` or `datetime.now()`:

  * ids come from the seeded RNG values already stored on the state objects,
  * every date comes from `athar.clock`,
  * a timestamp's time-of-day comes from `business_ts()`, a sha256 of a stable key mapped into
    the Asia/Dubai working day, so the same estate always renders the same bytes.

Serialisation rules (byte-identical output across runs and machines):
  * JSON   `json.dumps(obj, indent=2, sort_keys=True)` + a trailing newline
  * JSONL  `json.dumps(obj, sort_keys=True)`, one object per line
  * CSV    the `csv` module with `lineterminator="\\n"`
  * every list is sorted by a stable id before it is written
"""

from __future__ import annotations

import csv
import io
import json
from collections.abc import Iterable, Sequence
from datetime import date
from typing import Any

from athar.clock import iso_ts
from athar.generator.state import EstateState, MonthSnapshot
from athar.hashing import sha256_hex

NOT_AVAILABLE = "N/A"
NOT_SUPPORTED = "not_supported"
NO_INFORMATION = "no_information"

# Asia/Dubai working day (SPEC §4.1) expressed in UTC, as `rng.business_ts` does.
_WORK_HOUR_START = 3
_WORK_HOURS = 12


def dumps(obj: Any) -> str:
    """Canonical pretty JSON for a native export file."""
    return json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def dump_lines(objects: Iterable[Any]) -> str:
    """Canonical JSON Lines (`events.jsonl`, `remediations.jsonl`)."""
    return "".join(json.dumps(obj, sort_keys=True, ensure_ascii=False) + "\n" for obj in objects)


def csv_text(header: Sequence[str], rows: Iterable[Sequence[Any]], comment: str | None = None) -> str:
    """CSV with `\\n` line endings; an optional leading `#` comment line (the SYNTHETIC marker)."""
    buffer = io.StringIO(newline="")
    if comment:
        buffer.write(f"# {comment}\n")
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(list(header))
    for row in rows:
        writer.writerow(["" if value is None else str(value) for value in row])
    return buffer.getvalue()


def business_ts(day: date, key: str) -> str:
    """ISO-8601 UTC timestamp on `day`, at a time of day derived from `key` (never from a clock)."""
    digest = sha256_hex(key.encode())
    hour = _WORK_HOUR_START + int(digest[:2], 16) % _WORK_HOURS
    minute = int(digest[2:4], 16) % 60
    return iso_ts(day, hour, minute)


def opt_ts(day: date | None, key: str) -> str | None:
    return business_ts(day, key) if day is not None else None


def iso_day(day: date | None) -> str:
    return day.isoformat() if day is not None else ""


def etag(*parts: Any) -> str:
    """A stable, opaque, base64-looking etag for a GCP IAM policy document."""
    digest = sha256_hex("|".join(str(p) for p in parts).encode())
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    body = "".join(alphabet[int(digest[i : i + 2], 16) % 64] for i in range(0, 20, 2))
    return f"Bw{body}="


def month_files(state: EstateState, snapshot: MonthSnapshot) -> dict[str, str]:
    """Every native file for one month, keyed by its path relative to the month directory."""
    from athar.generator.writers import aws, azure, gcp, hr

    files: dict[str, str] = {}
    files.update(hr.hr_files(state, snapshot))
    files.update(aws.aws_files(state, snapshot))
    files.update(azure.azure_files(state, snapshot))
    files.update(gcp.gcp_files(state, snapshot))
    return files


__all__ = [
    "NOT_AVAILABLE",
    "NOT_SUPPORTED",
    "NO_INFORMATION",
    "business_ts",
    "csv_text",
    "dump_lines",
    "dumps",
    "etag",
    "iso_day",
    "month_files",
    "opt_ts",
]
