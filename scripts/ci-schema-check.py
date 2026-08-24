#!/usr/bin/env python3
"""Validate the reporter's fresh schema and its production privacy migration."""

from __future__ import annotations

import sqlite3
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCHEMA = (ROOT / "schema.sql").read_text(encoding="utf-8")
MIGRATION = (ROOT / "migrations/2026-08-24-privacy-hardening.sql").read_text(encoding="utf-8")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


db = sqlite3.connect(":memory:")
try:
    db.executescript(SCHEMA)
    bug_columns = {row[1] for row in db.execute("PRAGMA table_info(bugs)")}
    require({"contact", "ip_hash", "user_agent"}.issubset(bug_columns),
            "legacy compatibility columns are missing from bugs")
    require(db.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='bug_rate_limits'"
    ).fetchone() is not None, "fresh schema lacks bug_rate_limits")

    db.execute(
        "INSERT INTO bugs(summary,contact,ip_hash,user_agent) VALUES(?,?,?,?)",
        ("legacy", "person@example.com", "deadbeef", "LegacyBrowser/1.0"),
    )
    db.execute("CREATE INDEX IF NOT EXISTS idx_bugs_iphash ON bugs(ip_hash,created_at)")
    db.executescript(MIGRATION)
    db.executescript(MIGRATION)

    row = db.execute("SELECT contact,ip_hash,user_agent FROM bugs WHERE summary='legacy'").fetchone()
    require(row == ("", "", ""), "privacy migration did not scrub legacy report metadata")
    require(db.execute(
        "SELECT 1 FROM sqlite_master WHERE type='index' AND name='idx_bugs_iphash'"
    ).fetchone() is None, "privacy migration left the legacy IP index in place")
    require(db.execute("PRAGMA quick_check").fetchone() == ("ok",), "reporter schema failed quick_check")
finally:
    db.close()

print("PASS fresh reporter schema and idempotent privacy migration")
