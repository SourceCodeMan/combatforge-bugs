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
  contact    TEXT, -- legacy compatibility; new writes leave this blank
  ip_hash    TEXT, -- legacy compatibility; rate-limit hashes live only in bug_rate_limits
  user_agent TEXT, -- legacy compatibility; new writes leave this blank
  status     TEXT NOT NULL DEFAULT 'new'
);
CREATE INDEX IF NOT EXISTS idx_bugs_created ON bugs (created_at);

-- Five submissions per salted IP hash per rolling five-minute bucket. The hash is kept here only
-- for short-lived abuse control and is never attached to the bug report row.
CREATE TABLE IF NOT EXISTS bug_rate_limits (
  ip_hash     TEXT NOT NULL,
  window_start INTEGER NOT NULL,
  count       INTEGER NOT NULL DEFAULT 0,
  last_nonce  TEXT NOT NULL,
  PRIMARY KEY (ip_hash, window_start)
);
