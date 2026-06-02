"""api key metadata

Revision ID: 0002
Revises: 0001
Create Date: 2026-06-01 21:05:00.000000

"""
from alembic import op


revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS name TEXT NOT NULL DEFAULT 'Workspace session'")
    op.execute("ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS key_prefix TEXT NOT NULL DEFAULT 'as_live_'")
    op.execute("ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS key_type TEXT NOT NULL DEFAULT 'session'")


def downgrade() -> None:
    op.execute("ALTER TABLE api_keys DROP COLUMN IF EXISTS key_type")
    op.execute("ALTER TABLE api_keys DROP COLUMN IF EXISTS key_prefix")
    op.execute("ALTER TABLE api_keys DROP COLUMN IF EXISTS name")
