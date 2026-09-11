"""Token-bucket rate limiting and client-IP resolution (SPEC §15.3)."""

from __future__ import annotations

from ipaddress import ip_network

import pytest
from athar.config import Settings
from athar.security.limits import RateLimitRule, TokenBucket, client_ip, default_rules
from pydantic import ValidationError

COMPOSE_PROXY = (ip_network("172.20.0.0/16"),)  # the reverse proxy, and only it


class FakeClock:
    def __init__(self) -> None:
        self.t = 1000.0

    def __call__(self) -> float:
        return self.t


def test_bucket_allows_capacity_then_denies() -> None:
    clock = FakeClock()
    bucket = TokenBucket(rate_per_minute=5, clock=clock)
    results = [bucket.check("ip")[0] for _ in range(6)]
    assert results == [True] * 5 + [False]


def test_bucket_retry_after_is_positive_seconds() -> None:
    clock = FakeClock()
    bucket = TokenBucket(rate_per_minute=5, clock=clock)
    for _ in range(5):
        bucket.check("ip")
    allowed, retry = bucket.check("ip")
    assert not allowed
    assert 1 <= retry <= 12  # one token refills every 12 s at 5/min


def test_bucket_refills_over_time() -> None:
    clock = FakeClock()
    bucket = TokenBucket(rate_per_minute=5, clock=clock)
    for _ in range(5):
        bucket.check("ip")
    assert bucket.check("ip")[0] is False
    clock.t += 12.0
    assert bucket.check("ip")[0] is True
    assert bucket.check("ip")[0] is False
    clock.t += 60.0
    assert [bucket.check("ip")[0] for _ in range(5)] == [True] * 5  # never bursts above capacity


def test_bucket_keys_are_independent() -> None:
    bucket = TokenBucket(rate_per_minute=1, clock=FakeClock())
    assert bucket.check("a")[0] and not bucket.check("a")[0]
    assert bucket.check("b")[0]


def test_bucket_reset_clears_state() -> None:
    bucket = TokenBucket(rate_per_minute=1, clock=FakeClock())
    bucket.check("a")
    bucket.reset()
    assert bucket.check("a")[0]


def _scope(host: str, forwarded: str | None = None) -> dict:
    headers = [(b"x-forwarded-for", forwarded.encode())] if forwarded else []
    return {"type": "http", "client": (host, 12345), "headers": headers}


def test_client_ip_ignores_forwarded_for_from_an_untrusted_peer() -> None:
    assert client_ip(_scope("203.0.113.9", "198.51.100.1"), COMPOSE_PROXY) == "203.0.113.9"


# --- default: no trusted proxy (`athar serve`, the Vite dev proxy, tests) ---------------


def test_client_ip_default_ignores_forwarded_for_even_from_loopback() -> None:
    """The documented local path always has a loopback peer, so believing the header there
    would hand an attacker a fresh login bucket per request (SPEC §15.3)."""
    assert client_ip(_scope("127.0.0.1", "198.51.100.1")) == "127.0.0.1"
    assert client_ip(_scope("::1", "10.0.0.1, 198.51.100.2")) == "::1"
    assert client_ip(_scope("127.0.0.1", "198.51.100.3"), trusted=()) == "127.0.0.1"


def test_client_ip_rotating_the_header_cannot_mint_buckets_by_default() -> None:
    bucket = TokenBucket(rate_per_minute=5, clock=FakeClock())
    results = [bucket.check(client_ip(_scope("127.0.0.1", f"198.51.100.{i}"))) for i in range(8)]
    assert [allowed for allowed, _ in results] == [True] * 5 + [False] * 3


# --- compose: one declared proxy ---------------------------------------------------------


def test_client_ip_uses_the_rightmost_untrusted_hop_from_a_trusted_proxy() -> None:
    assert client_ip(_scope("172.20.0.5", "10.1.1.1, 198.51.100.1"), COMPOSE_PROXY) == "198.51.100.1"
    assert client_ip(_scope("172.20.0.5", "198.51.100.2"), COMPOSE_PROXY) == "198.51.100.2"


def test_client_ip_skips_hops_that_are_themselves_trusted_proxies() -> None:
    scope = _scope("172.20.0.5", "198.51.100.4, 172.20.0.9, 172.20.0.5")
    assert client_ip(scope, COMPOSE_PROXY) == "198.51.100.4"


def test_client_ip_falls_back_to_the_peer_when_every_hop_is_trusted_or_unparsable() -> None:
    assert client_ip(_scope("172.20.0.5", "172.20.0.9"), COMPOSE_PROXY) == "172.20.0.5"
    assert client_ip(_scope("172.20.0.5", "not-an-ip, also bad"), COMPOSE_PROXY) == "172.20.0.5"
    assert client_ip(_scope("172.20.0.5", " , "), COMPOSE_PROXY) == "172.20.0.5"


def test_client_ip_normalises_the_hop_so_one_client_is_one_bucket() -> None:
    long_form = client_ip(_scope("172.20.0.5", "2001:0db8:0000:0000:0000:0000:0000:0001"), COMPOSE_PROXY)
    short_form = client_ip(_scope("172.20.0.5", " 2001:db8::1 "), COMPOSE_PROXY)
    assert long_form == short_form == "2001:db8::1"


def test_client_ip_ipv6_proxy_network_is_honoured() -> None:
    trusted = (ip_network("::1/128"),)
    assert client_ip(_scope("::1", "198.51.100.7"), trusted) == "198.51.100.7"


def test_client_ip_without_client_or_header() -> None:
    assert client_ip({"type": "http", "headers": []}) == "unknown"
    assert client_ip({"type": "http", "headers": []}, COMPOSE_PROXY) == "unknown"
    assert client_ip(_scope("127.0.0.1")) == "127.0.0.1"
    assert client_ip(_scope("172.20.0.5"), COMPOSE_PROXY) == "172.20.0.5"


def test_settings_parse_trusted_proxy_cidrs_and_refuse_malformed_ones() -> None:
    settings = Settings(_env_file=None, TRUSTED_PROXY_CIDRS="172.20.0.0/16, 127.0.0.1")
    assert settings.trusted_proxy_networks == (ip_network("172.20.0.0/16"), ip_network("127.0.0.1/32"))
    assert Settings(_env_file=None).trusted_proxy_cidrs == []
    assert Settings(_env_file=None).trusted_proxy_networks == ()
    with pytest.raises(ValidationError):
        Settings(_env_file=None, TRUSTED_PROXY_CIDRS="192.168.0.0/99")


def test_default_rules_login_exact_and_agent_prefix() -> None:
    rules = default_rules("/api/v1")
    by_prefix = {r.prefix: r for r in rules}
    login = by_prefix["/api/v1/auth/login"]
    agent = by_prefix["/api/v1/agent/"]
    assert login.exact and login.bucket.rate_per_minute == 5
    assert not agent.exact and agent.bucket.rate_per_minute == 20
    assert login.matches("/api/v1/auth/login") and not login.matches("/api/v1/auth/login/x")
    assert agent.matches("/api/v1/agent/summary") and not agent.matches("/api/v1/agents")
    assert not RateLimitRule("/x", TokenBucket(1)).matches("/api/v1/health")
