from __future__ import annotations

import uuid
from datetime import datetime, timezone
from sqlalchemy import BigInteger, Boolean, Column, DateTime, ForeignKey, Numeric, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()

class TenantModel(Base):
    __tablename__ = "tenants"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(Text, nullable=False)
    status = Column(Text, nullable=False, default="active")
    preferences = Column(JSONB, nullable=False, default=dict)
    created_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))


class ApiKeyModel(Base):
    __tablename__ = "api_keys"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id = Column(UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    token_hash = Column(Text, nullable=False, unique=True)
    scopes = Column(JSONB, nullable=False)
    status = Column(Text, nullable=False, default="active")
    created_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    last_used_at = Column(DateTime(timezone=True))


class WorkspaceUserModel(Base):
    __tablename__ = "workspace_users"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id = Column(UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    email = Column(Text, nullable=False, unique=True)
    password_hash = Column(Text, nullable=False)
    role = Column(String, nullable=False, default="owner")
    created_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))


class AgentModel(Base):
    __tablename__ = "agents"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id = Column(UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    name = Column(Text, nullable=False)
    type = Column(Text, nullable=False)
    permissions = Column(JSONB, nullable=False, default=dict)
    trust_score = Column(Numeric, nullable=False, default=1.0)
    status = Column(Text, nullable=False, default="active")
    metadata = Column(JSONB, nullable=False, default=dict)
    created_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))


class AgentTokenModel(Base):
    __tablename__ = "agent_tokens"

    jti = Column(String, primary_key=True)
    tenant_id = Column(UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    agent_id = Column(UUID(as_uuid=True), ForeignKey("agents.id", ondelete="CASCADE"), nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    revoked_at = Column(DateTime(timezone=True))


class AuditLedgerModel(Base):
    __tablename__ = "audit_ledger"

    id = Column(BigInteger, primary_key=True, autoincrement=True)
    tenant_id = Column(UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    agent_id = Column(UUID(as_uuid=True), ForeignKey("agents.id", ondelete="SET NULL"))
    event_type = Column(Text, nullable=False)
    severity = Column(Text, nullable=False)
    verdict = Column(Text, nullable=False)
    event_data = Column(JSONB, nullable=False)
    prev_hash = Column(Text, nullable=False)
    curr_hash = Column(Text, nullable=False, unique=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))


class ThreatEventModel(Base):
    __tablename__ = "threat_events"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    ledger_id = Column(BigInteger, ForeignKey("audit_ledger.id", ondelete="CASCADE"), nullable=False)
    agent_id = Column(UUID(as_uuid=True), ForeignKey("agents.id", ondelete="CASCADE"), nullable=False)
    tenant_id = Column(UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"))
    attack_type = Column(Text, nullable=False)
    confidence = Column(Numeric, nullable=False)
    evidence = Column(Text, nullable=False)
    resolved = Column(Boolean, nullable=False, default=False)
    created_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))


class TrustHistoryModel(Base):
    __tablename__ = "trust_history"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    agent_id = Column(UUID(as_uuid=True), ForeignKey("agents.id", ondelete="CASCADE"), nullable=False)
    ledger_id = Column(BigInteger, ForeignKey("audit_ledger.id", ondelete="SET NULL"))
    delta = Column(Numeric, nullable=False)
    reason = Column(Text, nullable=False)
    score_after = Column(Numeric, nullable=False)
    created_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))


class EventOutboxModel(Base):
    __tablename__ = "event_outbox"

    id = Column(BigInteger, primary_key=True, autoincrement=True)
    event_name = Column(Text, nullable=False)
    payload = Column(JSONB, nullable=False)
    processed_at = Column(DateTime(timezone=True))
    retry_count = Column(BigInteger, nullable=False, default=0)
    created_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))


class CryptographicKeyModel(Base):
    __tablename__ = "cryptographic_keys"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id = Column(UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    private_key_pem = Column(Text, nullable=False)
    public_key_pem = Column(Text, nullable=False)
    created_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    rotated_at = Column(DateTime(timezone=True))
    status = Column(Text, nullable=False, default="active")


class InvitationModel(Base):
    __tablename__ = "invitations"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id = Column(UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    email = Column(Text, nullable=False)
    role = Column(Text, nullable=False)
    status = Column(Text, nullable=False, default="pending")
    created_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
