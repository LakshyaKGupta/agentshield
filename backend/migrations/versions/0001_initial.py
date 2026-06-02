"""initial schema

Revision ID: 0001
Revises: 
Create Date: 2026-06-01 12:00:00.000000

"""
from alembic import op
import sqlalchemy as sa
import os

# revision identifiers, used by Alembic.
revision = '0001'
down_revision = None
branch_labels = None
depends_on = None

def upgrade() -> None:
    migrations_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    sql_path = os.path.join(migrations_dir, "001_initial_schema.sql")
    
    with open(sql_path, "r", encoding="utf-8") as f:
        sql_content = f.read()
        
    # Execute the entire initial SQL schema
    op.execute(sql_content)

def downgrade() -> None:
    op.execute("""
        DROP TABLE IF EXISTS invitations CASCADE;
        DROP TABLE IF EXISTS cryptographic_keys CASCADE;
        DROP TABLE IF EXISTS event_outbox CASCADE;
        DROP TABLE IF EXISTS trust_history CASCADE;
        DROP TABLE IF EXISTS threat_events CASCADE;
        DROP TABLE IF EXISTS audit_ledger CASCADE;
        DROP TABLE IF EXISTS agent_tokens CASCADE;
        DROP TABLE IF EXISTS agents CASCADE;
        DROP TABLE IF EXISTS workspace_users CASCADE;
        DROP TABLE IF EXISTS api_keys CASCADE;
        DROP TABLE IF EXISTS tenants CASCADE;
        DROP FUNCTION IF EXISTS reject_audit_ledger_mutation() CASCADE;
        DROP FUNCTION IF EXISTS reject_audit_ledger_truncate() CASCADE;
    """)
