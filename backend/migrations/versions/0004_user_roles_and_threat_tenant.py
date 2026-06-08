"""user roles and threat tenant

Revision ID: 0004
Revises: 0003
Create Date: 2026-06-08 16:00:00.000000

"""
from alembic import op


revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TABLE workspace_users ADD COLUMN IF NOT EXISTS role TEXT NOT NULL DEFAULT 'owner'")
    op.execute("ALTER TABLE threat_events ADD COLUMN IF NOT EXISTS tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE")
    op.execute("CREATE INDEX IF NOT EXISTS idx_threat_events_tenant_id ON threat_events(tenant_id)")


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS idx_threat_events_tenant_id")
    op.execute("ALTER TABLE threat_events DROP COLUMN IF EXISTS tenant_id")
    op.execute("ALTER TABLE workspace_users DROP COLUMN IF EXISTS role")
