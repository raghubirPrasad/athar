"""All configuration in one place (SPEC §18.2).

Every environment variable ATHAR reads is declared here and documented in
`.env.example`. Nothing else in the codebase reads `os.environ`.
"""

from __future__ import annotations

from functools import lru_cache
from ipaddress import IPv4Network, IPv6Network, ip_network
from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

APP_NAME = "ATHAR"
ORG_NAME = "Nahar Digital Authority"  # fictional, SPEC §4.1
EMAIL_DOMAIN = "nda.example"  # RFC 2606 reserved; never a real domain

# Anvil dev account #0 — DEV ONLY, PUBLICLY KNOWN KEY. Never holds value.
ANVIL_DEV_KEY_0 = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
EXAMPLE_JWT_SECRET = "change-me-athar-dev-secret"  # noqa: S105 — sentinel, refused unless ATHAR_DEV
MIN_JWT_SECRET_CHARS = 32  # HS256 key shorter than the digest is refused outside dev (SPEC §15.1)

# Demo account passwords. `seed_users` writes these on every start, so outside dev each one is a
# live credential published in `.env.example`, not a placeholder — `assert_startable` refuses them.
EXAMPLE_ANALYST_PASSWORD = "analyst-demo-pass"  # noqa: S105 — sentinel, refused unless ATHAR_DEV
EXAMPLE_APPROVER_PASSWORD = "approver-demo-pass"  # noqa: S105 — sentinel, refused unless ATHAR_DEV
EXAMPLE_JUDGE_PASSWORD = "judge-demo-pass"  # noqa: S105 — sentinel, refused unless ATHAR_DEV


REPO_ROOT = Path(__file__).resolve().parents[2]  # backend/athar/config.py -> repo root


class Settings(BaseSettings):
    # The repo-root .env is read first so `uv run` from backend/ and pytest see the same values;
    # a ./.env in the working directory (later entry) wins; missing files are ignored.
    model_config = SettingsConfigDict(
        env_file=(str(REPO_ROOT / ".env"), ".env"), env_file_encoding="utf-8", extra="ignore"
    )

    # --- estate / simulation -------------------------------------------------
    athar_seed: int = Field(42, alias="ATHAR_SEED")
    athar_eval_seed: int = Field(7, alias="ATHAR_EVAL_SEED")
    athar_months: int = Field(12, alias="ATHAR_MONTHS")
    athar_identities: int = Field(500, alias="ATHAR_IDENTITIES")
    athar_dev: bool = Field(True, alias="ATHAR_DEV")
    # Relative paths resolve against the repository root, so `uv run athar …` writes to the same
    # place whichever directory it is invoked from; compose passes an absolute /app/data.
    data_dir: str = Field("data", alias="ATHAR_DATA_DIR")

    # --- storage -------------------------------------------------------------
    database_url: str = Field("postgresql+psycopg://athar:athar@localhost:5432/athar", alias="DATABASE_URL")

    # --- auth ----------------------------------------------------------------
    jwt_secret: str = Field(EXAMPLE_JWT_SECRET, alias="JWT_SECRET")
    jwt_ttl_hours: int = Field(12, alias="JWT_TTL_HOURS")
    demo_analyst_password: str = Field(EXAMPLE_ANALYST_PASSWORD, alias="DEMO_ANALYST_PASSWORD")
    demo_approver_password: str = Field(EXAMPLE_APPROVER_PASSWORD, alias="DEMO_APPROVER_PASSWORD")
    demo_judge_password: str = Field(EXAMPLE_JUDGE_PASSWORD, alias="DEMO_JUDGE_PASSWORD")
    cookie_secure: bool = Field(False, alias="COOKIE_SECURE")
    # Proxies whose `X-Forwarded-For` the rate limiter believes (SPEC §15.3). Comma-separated
    # addresses or CIDRs; empty (the default) means trust nothing and key on the direct peer.
    trusted_proxy_cidrs: Annotated[list[str], NoDecode] = Field(
        default_factory=list, alias="TRUSTED_PROXY_CIDRS"
    )

    # --- LLM -----------------------------------------------------------------
    llm_provider: Literal["gemini", "ollama", "none"] = Field("gemini", alias="LLM_PROVIDER")
    llm_model: str = Field("gemini-2.5-flash", alias="LLM_MODEL")
    gemini_api_key: str = Field("", alias="GEMINI_API_KEY")
    google_api_key: str = Field("", alias="GOOGLE_API_KEY")  # accepted as an alias for GEMINI_API_KEY
    ollama_url: str = Field("http://ollama:11434", alias="OLLAMA_URL")
    ollama_model: str = Field("qwen3:8b", alias="OLLAMA_MODEL")
    llm_timeout_seconds: int = Field(20, alias="LLM_TIMEOUT_SECONDS")
    llm_max_concurrency: int = Field(3, alias="LLM_MAX_CONCURRENCY")

    # --- ledger --------------------------------------------------------------
    ledger_rpc_url: str = Field("http://anvil:8545", alias="LEDGER_RPC_URL")
    ledger_private_key: str = Field(ANVIL_DEV_KEY_0, alias="LEDGER_PRIVATE_KEY")
    ledger_contract_address: str = Field("", alias="LEDGER_CONTRACT_ADDRESS")
    ledger_enabled: bool = Field(True, alias="LEDGER_ENABLED")
    ledger_receipt_timeout_seconds: float = Field(60.0, alias="LEDGER_RECEIPT_TIMEOUT_SECONDS")

    # --- detection thresholds (defaults; runtime values live in `settings` table) ---
    dormant_days: int = Field(90, alias="DORMANT_DAYS")
    stale_key_days: int = Field(180, alias="STALE_KEY_DAYS")
    # NoDecode: the env value is a comma-separated list, not JSON; the validator below splits it.
    approved_regions: Annotated[list[str], NoDecode] = Field(
        default_factory=lambda: ["me-central-1", "uaenorth", "uaecentral", "me-central1"],
        alias="APPROVED_REGIONS",
    )
    auto_remediate_departed: bool = Field(False, alias="AUTO_REMEDIATE_DEPARTED")

    # --- scheduler / serving -------------------------------------------------
    scan_interval_minutes: int = Field(0, alias="SCAN_INTERVAL_MINUTES")
    public_url: str = Field("http://localhost:8080", alias="PUBLIC_URL")
    api_host: str = Field("0.0.0.0", alias="API_HOST")  # noqa: S104 — container bind
    api_port: int = Field(8000, alias="API_PORT")
    log_level: str = Field("INFO", alias="LOG_LEVEL")
    max_upload_bytes: int = Field(10 * 1024 * 1024, alias="MAX_UPLOAD_BYTES")
    api_mock: bool = Field(False, alias="ATHAR_API_MOCK")  # serve deterministic mock data (frontend dev only)

    @property
    def effective_gemini_key(self) -> str:
        return self.gemini_api_key or self.google_api_key

    @property
    def trusted_proxy_networks(self) -> tuple[IPv4Network | IPv6Network, ...]:
        """`TRUSTED_PROXY_CIDRS` parsed; empty means no proxy header is believed (SPEC §15.3)."""
        return tuple(ip_network(entry, strict=False) for entry in self.trusted_proxy_cidrs)

    @field_validator("data_dir", mode="after")
    @classmethod
    def _absolute_data_dir(cls, v: str) -> str:
        path = Path(v)
        return str(path if path.is_absolute() else (REPO_ROOT / path))

    @field_validator("approved_regions", "trusted_proxy_cidrs", mode="before")
    @classmethod
    def _split_csv(cls, v: object) -> object:
        if isinstance(v, str):
            return [s.strip() for s in v.split(",") if s.strip()]
        return v

    @field_validator("trusted_proxy_cidrs", mode="after")
    @classmethod
    def _parsable_cidrs(cls, v: list[str]) -> list[str]:
        for entry in v:
            ip_network(entry, strict=False)  # ValueError → ValidationError at startup, never at request time
        return v

    def assert_startable(self) -> None:
        """Refuse to start with example credentials outside dev (SPEC §15.1).

        `ATHAR_DEV=true` (the `make demo` default) allows every example value. With
        `ATHAR_DEV=false` the process is treated as hosted: the demo passwords are published in
        `.env.example` and `seed_users` writes them on every start, a short `JWT_SECRET` weakens
        HS256, and a non-Secure cookie sends the session over plain HTTP.
        """
        if self.athar_dev:
            return
        problems: list[str] = []
        if self.jwt_secret == EXAMPLE_JWT_SECRET:
            problems.append("JWT_SECRET is the .env.example value")
        elif len(self.jwt_secret) < MIN_JWT_SECRET_CHARS:
            problems.append(f"JWT_SECRET is shorter than {MIN_JWT_SECRET_CHARS} characters")
        for alias, value, example in (
            ("DEMO_ANALYST_PASSWORD", self.demo_analyst_password, EXAMPLE_ANALYST_PASSWORD),
            ("DEMO_APPROVER_PASSWORD", self.demo_approver_password, EXAMPLE_APPROVER_PASSWORD),
            ("DEMO_JUDGE_PASSWORD", self.demo_judge_password, EXAMPLE_JUDGE_PASSWORD),
        ):
            if value == example:
                problems.append(f"{alias} is the .env.example value")
        if not self.cookie_secure:
            problems.append("COOKIE_SECURE is false, so the session cookie is not marked Secure")
        if problems:
            raise RuntimeError(
                "refusing to start with ATHAR_DEV=false: "
                + "; ".join(problems)
                + ". Set real values, or ATHAR_DEV=true for a local demo."
            )


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
