"""browser sessions

Revision ID: 0003
Revises: 0002
Create Date: 2026-06-02 16:20:00.000000

"""
from alembic import op


revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS browser_sessions (
          session_id TEXT PRIMARY KEY,
          api_key_hash TEXT NOT NULL REFERENCES api_keys(token_hash) ON DELETE CASCADE,
          csrf_token TEXT NOT NULL,
          created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
          expires_at TIMESTAMPTZ NOT NULL
        )
        """
    )
    op.execute("CREATE INDEX IF NOT EXISTS idx_browser_sessions_expires_at ON browser_sessions(expires_at)")


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS browser_sessions")
