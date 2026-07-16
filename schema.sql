CREATE TABLE IF NOT EXISTS bugs (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  summary    TEXT NOT NULL,
  steps      TEXT,
  expected   TEXT,
  actual     TEXT,
  version    TEXT,
  platform   TEXT,
  severity   TEXT,
  media_url  TEXT,
  contact    TEXT,
  ip_hash    TEXT,
  user_agent TEXT,
  status     TEXT NOT NULL DEFAULT 'new'
);
CREATE INDEX IF NOT EXISTS idx_bugs_created ON bugs (created_at);
CREATE INDEX IF NOT EXISTS idx_bugs_iphash  ON bugs (ip_hash, created_at);
