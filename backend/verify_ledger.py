#!/usr/bin/env python3
"""
AgentShield — Audit Ledger SHA-256 Chain Verification Tool
=========================================================
This script queries the active database audit ledger and performs a strict,
independent cryptographic validation of the SHA-256 hash chains.

Usage:
  python3 verify_ledger.py
"""

from __future__ import annotations

import os
import sys
from dotenv import load_dotenv

# Load env variables
load_dotenv()

# Set path relative to project root
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.app.store import create_store
from backend.app.ledger.service import verify_ledger


def print_banner() -> None:
    print("\033[94m┌────────────────────────────────────────────────────────┐\033[0m")
    print("\033[94m│      🛡️  AgentShield — Independent Ledger Verifier     │\033[0m")
    print("\033[94m└────────────────────────────────────────────────────────┘\033[0m")


def main() -> None:
    print_banner()

    database_url = os.getenv("DATABASE_URL")
    if not database_url:
        print("\033[93m[!] DATABASE_URL not set in .env. Defaulting to in-memory store.\033[0m")
    else:
        print(f"\033[92m[✓] Connected to Database: postgres://...@{database_url.split('@')[-1]}\033[0m")

    # Load store and retrieve entries
    try:
        store = create_store(database_url)
        print("\033[90m[*] Loading audit ledger entries from store...\033[0m")
    except Exception as exc:
        print(f"\033[91m[✗] Database connection failed: {exc}\033[0m")
        sys.exit(1)

    total_entries = len(store.ledger)
    if total_entries == 0:
        print("\033[93m[!] Ledger is empty. No blocks to verify. Spawn an agent or run an attack to start.\033[0m")
        sys.exit(0)

    print(f"\033[90m[*] Loaded {total_entries} block entries. Starting cryptographic verification...\033[0m\n")

    # Perform Independent Verification
    verification = verify_ledger(store)

    if verification.valid:
        print(f"\033[92m🟢 [SUCCESS] Cryptographic verification complete!\033[0m")
        print(f"  • Status:          \033[92mValid & Untampered\033[0m")
        print(f"  • Blocks Checked:  \033[97m{verification.entries_checked}\033[0m")
        print(f"  • Verified At:     \033[90m{verification.checked_at.isoformat()}\033[0m")
        print("\n\033[92m✓ All SHA-256 hash chains from genesis block to current head are validated.\033[0m")
    else:
        print(f"\033[91m🔴 [FAILURE] Cryptographic mismatch detected! Tampering suspected.\033[0m")
        print(f"  • Broken Block ID: \033[91m#{verification.broken_at}\033[0m")
        print(f"  • Expected Hash:   \033[92m{verification.expected_hash}\033[0m")
        print(f"  • Found Hash:      \033[91m{verification.actual_hash}\033[0m")
        print(f"  • Verified At:     \033[90m{verification.checked_at.isoformat()}\033[0m")
        print("\n\033[91m[!] WARNING: The audit ledger has been altered. Integrity checks failed.\033[0m")
        sys.exit(2)


if __name__ == "__main__":
    main()
