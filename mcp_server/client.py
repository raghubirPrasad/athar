"""Thin authenticated HTTP client for the ATHAR API.

The MCP server never talks to the database or the engine directly: it calls the same
`/api/v1` surface the dashboard uses, so it inherits ATHAR's RBAC, evidence and ledger
logic unchanged. Login sets an httpOnly `athar_session` cookie; httpx's cookie jar carries
it. Mutating requests send `X-Requested-With: athar`, the CSRF header the API requires.
"""

from __future__ import annotations

import os
from typing import Any

import httpx

DEFAULT_BASE = os.environ.get("ATHAR_API", "http://localhost:8000/api/v1")
DEFAULT_EMAIL = os.environ.get("ATHAR_MCP_EMAIL", "analyst@athar.local")
DEFAULT_PASSWORD = os.environ.get("ATHAR_MCP_PASSWORD", "")


class AtharError(RuntimeError):
    """The API returned an error, surfaced to the caller instead of a raw stack trace."""


class AtharClient:
    def __init__(
        self,
        base_url: str = DEFAULT_BASE,
        email: str = DEFAULT_EMAIL,
        password: str = DEFAULT_PASSWORD,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self._email = email
        self._password = password
        self._http = httpx.Client(base_url=self.base_url, timeout=30.0)
        self._logged_in = False

    def _login(self) -> None:
        if self._logged_in:
            return
        if not self._password:
            raise AtharError(
                "no ATHAR_MCP_PASSWORD set — export the demo account password before starting the server"
            )
        r = self._http.post(
            "/auth/login",
            json={"email": self._email, "password": self._password},
            headers={"X-Requested-With": "athar"},
        )
        if r.status_code != 200:
            raise AtharError(f"login failed ({r.status_code}) for {self._email}")
        self._logged_in = True

    def get(self, path: str, params: dict[str, Any] | None = None) -> Any:
        self._login()
        r = self._http.get(path, params={k: v for k, v in (params or {}).items() if v is not None})
        return self._unwrap(r)

    def post(self, path: str, params: dict[str, Any] | None = None) -> Any:
        self._login()
        r = self._http.post(
            path,
            params={k: v for k, v in (params or {}).items() if v is not None},
            headers={"X-Requested-With": "athar"},
        )
        return self._unwrap(r)

    @staticmethod
    def _unwrap(r: httpx.Response) -> Any:
        if r.status_code >= 400:
            detail = ""
            try:
                detail = r.json().get("detail") or r.json().get("title") or ""
            except Exception:  # noqa: BLE001 — best-effort error text
                detail = r.text[:200]
            raise AtharError(f"{r.request.method} {r.request.url.path} → {r.status_code}: {detail}")
        return r.json()
