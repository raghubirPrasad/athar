"""001 — Canonical Permission Model + operational tables (SPEC §5.1).

Revision ID: 001_cpm
Revises: None
"""

from __future__ import annotations

from alembic import op

from athar.db.models import Base

revision = "001_cpm"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Initial schema is created from the frozen models; later revisions must be hand-written.
    Base.metadata.create_all(bind=op.get_bind())


def downgrade() -> None:
    Base.metadata.drop_all(bind=op.get_bind())
