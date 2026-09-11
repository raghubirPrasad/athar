"""Seeded randomness helpers (SPEC §4.5).

Every function takes the one `random.Random(seed)` owned by the simulator. Nothing in
this package calls the module-level `random`, `uuid4()` or `datetime.now()`.
"""

from __future__ import annotations

import math
import random
import uuid
from collections.abc import Sequence
from datetime import date, timedelta

from athar.clock import EPOCH, date_in_month, iso_ts

_ALNUM_UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"  # AWS-style identifiers avoid 0/1
_HEX = "0123456789abcdef"


def guid(rng: random.Random) -> str:
    """RFC 4122 text form of 128 seeded bits (SPEC §4.1: never `uuid4()`)."""
    return str(uuid.UUID(int=rng.getrandbits(128)))


def poisson(rng: random.Random, mean: float) -> int:
    """Knuth's Poisson sampler; adequate for the small means in SPEC §4.2."""
    if mean <= 0:
        return 0
    limit = math.exp(-mean)
    k = 0
    p = 1.0
    while True:
        p *= rng.random()
        if p < limit:
            return k
        k += 1


def upper_id(rng: random.Random, prefix: str, length: int = 17) -> str:
    """AWS unique id: `AIDA…` (user), `AGPA…` (group), `AROA…` (role), `ANPA…` (policy)."""
    return prefix + "".join(rng.choice(_ALNUM_UPPER) for _ in range(length))


def access_key_id(rng: random.Random) -> str:
    return upper_id(rng, "AKIA", 16)


def hex_id(rng: random.Random, length: int) -> str:
    return "".join(rng.choice(_HEX) for _ in range(length))


def digits(rng: random.Random, length: int) -> str:
    """A numeric id of fixed length with a non-zero first digit (AWS account, GCP project number)."""
    first = str(rng.randint(1, 9))
    return first + "".join(str(rng.randint(0, 9)) for _ in range(length - 1))


def weighted[T](rng: random.Random, options: Sequence[tuple[T, float]]) -> T:
    total = sum(w for _, w in options)
    roll = rng.random() * total
    acc = 0.0
    for value, weight in options:
        acc += weight
        if roll < acc:
            return value
    return options[-1][0]


def pick[T](rng: random.Random, items: Sequence[T]) -> T:
    if not items:
        raise ValueError("cannot pick from an empty sequence")
    return items[rng.randrange(len(items))]


def sample[T](rng: random.Random, items: Sequence[T], k: int) -> list[T]:
    k = min(k, len(items))
    return rng.sample(list(items), k) if k > 0 else []


def day_in(rng: random.Random, month: int) -> date:
    return date_in_month(month, rng.random())


def days_before_epoch(rng: random.Random, lo: int, hi: int) -> date:
    """A date `lo..hi` days before month 1 — for state that pre-dates the simulation window."""
    return EPOCH - timedelta(days=rng.randint(lo, hi))


def business_ts(rng: random.Random, d: date) -> str:
    """ISO timestamp inside the Asia/Dubai working day (03:00–14:59 UTC)."""
    return iso_ts(d, hour=rng.randint(3, 14), minute=rng.randint(0, 59))
