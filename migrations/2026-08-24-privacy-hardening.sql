-- Idempotent release migration: move abuse control out of report records and scrub legacy metadata.
CREATE TABLE IF NOT EXISTS bug_rate_limits (
  ip_hash      TEXT NOT NULL,
  window_start INTEGER NOT NULL,
  count        INTEGER NOT NULL DEFAULT 0,
  last_nonce   TEXT NOT NULL,
  PRIMARY KEY (ip_hash, window_start)
);

UPDATE bugs SET contact = '', ip_hash = '', user_agent = ''
WHERE COALESCE(contact, '') <> '' OR COALESCE(ip_hash, '') <> '' OR COALESCE(user_agent, '') <> '';

DROP INDEX IF EXISTS idx_bugs_iphash;
