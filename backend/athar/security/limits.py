"""In-memory token-bucket rate limiting keyed by client IP (SPEC §15.3).

`/auth/login` 5/min/IP and `/agent/*` 20/min/IP. `X-Forwarded-For` is honoured only when the
direct peer is inside `TRUSTED_PROXY_CIDRS`, which is empty by default: on the documented local
path (`athar serve`, the Vite dev proxy) every request arrives from loopback, so believing the
header there would let one client rotate it and spend a fresh bucket on each guess. One process,
one bucket table; good enough for a single API container.
"""

from __future__ import annotations

import math
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network, ip_address

from starlette.types import ASGIApp, Receive, Scope, Send

from athar.api.problem import problem_response

TrustedProxies = Sequence[IPv4Network | IPv6Network]
UNKNOWN_CLIENT = "unknown"


@dataclass
class _Bucket:
    tokens: float
    updated: float


@dataclass
class TokenBucket:
    """`rate_per_minute` sustained, bursting up to `capacity` (defaults to the rate)."""

    rate_per_minute: float
    capacity: float | None = None
    clock: Callable[[], float] = time.monotonic
    _buckets: dict[str, _Bucket] = field(default_factory=dict, repr=False)

    def __post_init__(self) -> None:
        if self.capacity is None:
            self.capacity = self.rate_per_minute

    def check(self, key: str) -> tuple[bool, int]:
        """Consume one token for `key`. Returns (allowed, retry_after_seconds)."""
        assert self.capacity is not None
        now = self.clock()
        bucket = self._buckets.get(key)
        if bucket is None:
            bucket = _Bucket(tokens=self.capacity, updated=now)
            self._buckets[key] = bucket
        refill = (now - bucket.updated) * self.rate_per_minute / 60.0
        bucket.tokens = min(self.capacity, bucket.tokens + refill)
        bucket.updated = now
        if bucket.tokens >= 1.0:
            bucket.tokens -= 1.0
            return True, 0
        retry = math.ceil((1.0 - bucket.tokens) * 60.0 / self.rate_per_minute)
        return False, max(1, retry)

    def reset(self) -> None:
        self._buckets.clear()


def _parse(host: str) -> IPv4Address | IPv6Address | None:
    try:
        return ip_address(host)
    except ValueError:
        return None


def _is_trusted(host: str, trusted: TrustedProxies) -> bool:
    address = _parse(host)
    return address is not None and any(address in network for network in trusted)


def _forwarded_for(scope: Scope) -> str:
    values = [
        value.decode("latin-1")
        for key, value in scope.get("headers", [])
        if key.decode("latin-1").lower() == "x-forwarded-for"
    ]
    return ", ".join(values)


def client_ip(scope: Scope, trusted: TrustedProxies = ()) -> str:
    """The address a bucket is keyed on (SPEC §15.3).

    `X-Forwarded-For` is believed only when the direct peer is inside `trusted`
    (`TRUSTED_PROXY_CIDRS`); the client is then the right-most hop that is not itself a trusted
    proxy, because each proxy appends and everything to its left is client-supplied. With no
    trusted proxies — the default — the header is ignored and the peer address is used, so a
    loopback client cannot mint a new bucket per request. Hops that are not parsable addresses
    are skipped rather than trusted as keys.
    """
    client = scope.get("client")
    host = str(client[0]) if client else UNKNOWN_CLIENT
    if not trusted or not _is_trusted(host, trusted):
        return host
    for hop in reversed(_forwarded_for(scope).split(",")):
        address = _parse(hop.strip())
        if address is None or any(address in network for network in trusted):
            continue
        return str(address)  # normalised, so one client cannot spell itself two ways
    return host  # header absent, empty, or every hop is a trusted proxy


@dataclass
class RateLimitRule:
    prefix: str
    bucket: TokenBucket
    exact: bool = False

    def matches(self, path: str) -> bool:
        return path == self.prefix if self.exact else path.startswith(self.prefix)


class RateLimitMiddleware:
    """Pure ASGI: 429 problem+json with Retry-After when a rule's bucket is empty."""

    def __init__(
        self, app: ASGIApp, rules: list[RateLimitRule], trusted_proxies: TrustedProxies = ()
    ) -> None:
        self.app = app
        self.rules = rules
        self.trusted_proxies = tuple(trusted_proxies)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        path = scope.get("path", "")
        for rule in self.rules:
            if rule.matches(path):
                allowed, retry_after = rule.bucket.check(client_ip(scope, self.trusted_proxies))
                if not allowed:
                    response = problem_response(
                        429,
                        "rate.limited",
                        detail="Too many requests; slow down",
                        headers={"Retry-After": str(retry_after)},
                    )
                    await response(scope, receive, send)
                    return
                break
        await self.app(scope, receive, send)


def default_rules(prefix: str = "/api/v1") -> list[RateLimitRule]:
    return [
        RateLimitRule(f"{prefix}/auth/login", TokenBucket(5), exact=True),
        RateLimitRule(f"{prefix}/agent/", TokenBucket(20)),
    ]
