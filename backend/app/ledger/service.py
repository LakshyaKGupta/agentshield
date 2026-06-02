from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from uuid import UUID

from ..contracts import LedgerEntry, LedgerVerification, Severity, Verdict
from ..store import InMemoryStore


GENESIS_HASH = "0" * 64


def canonical_timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat()


def canonical_hash(payload: dict, prev_hash: str) -> str:
    canonical = json.dumps({"prev_hash": prev_hash, "payload": payload}, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode()).hexdigest()


def append_ledger_entry(
    store: InMemoryStore,
    tenant_id: UUID,
    agent_id: UUID | None,
    event_type: str,
    severity: Severity,
    verdict: Verdict,
    event_data: dict,
) -> LedgerEntry:
    prev_hash = store.ledger[-1].curr_hash if store.ledger else GENESIS_HASH
    created_at = datetime.now(timezone.utc)
    payload = {
        "tenant_id": str(tenant_id),
        "agent_id": str(agent_id) if agent_id else None,
        "event_type": event_type,
        "severity": severity.value,
        "verdict": verdict.value,
        "event_data": event_data,
        "created_at": canonical_timestamp(created_at),
    }
    curr_hash = canonical_hash(payload, prev_hash)
    entry = LedgerEntry(
        id=len(store.ledger) + 1,
        tenant_id=tenant_id,
        agent_id=agent_id,
        event_type=event_type,  # type: ignore[arg-type]
        severity=severity,
        verdict=verdict,
        event_data=event_data,
        prev_hash=prev_hash,
        curr_hash=curr_hash,
        created_at=created_at,
    )
    store.ledger.append(entry)
    store.persist_ledger_entry(entry)
    event = {"event": "security.event.created", "ledger_id": entry.id, "agent_id": str(agent_id), "verdict": verdict.value}
    store.events.append(event)
    store.persist_event(event)
    return entry


def verify_ledger(store: InMemoryStore) -> LedgerVerification:
    prev_hash = GENESIS_HASH
    for entry in store.ledger:
        payload = {
            "tenant_id": str(entry.tenant_id),
            "agent_id": str(entry.agent_id) if entry.agent_id else None,
            "event_type": entry.event_type,
            "severity": entry.severity.value,
            "verdict": entry.verdict.value,
            "event_data": entry.event_data,
            "created_at": canonical_timestamp(entry.created_at),
        }
        expected = canonical_hash(payload, prev_hash)
        if expected != entry.curr_hash or entry.prev_hash != prev_hash:
            return LedgerVerification(
                valid=False,
                entries_checked=entry.id,
                broken_at=entry.id,
                expected_hash=expected,
                actual_hash=entry.curr_hash,
                checked_at=datetime.now(timezone.utc),
            )
        prev_hash = entry.curr_hash
    return LedgerVerification(valid=True, entries_checked=len(store.ledger), checked_at=datetime.now(timezone.utc))
