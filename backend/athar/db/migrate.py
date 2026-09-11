"""Run Alembic programmatically (used by the API on startup and by the CLI)."""

from __future__ import annotations

from pathlib import Path

from alembic import command
from alembic.config import Config

from athar.config import get_settings


def alembic_config() -> Config:
    here = Path(__file__).parent
    cfg = Config()
    cfg.set_main_option("script_location", str(here / "migrations"))
    cfg.set_main_option("sqlalchemy.url", get_settings().database_url)
    return cfg


def upgrade_head() -> None:
    command.upgrade(alembic_config(), "head")
