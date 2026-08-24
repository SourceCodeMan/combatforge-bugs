# CombatForge Bugs — bug-report service

A single Cloudflare Worker that serves a bug-report form, stores each submission
in **D1** (SQLite), and posts it to the **#bug-reports** Discord channel via webhook.
No third-party tools; owned end to end.

- **Form (public):** https://report.playcombatforge.com
- **Inbox (private):** https://report.playcombatforge.com/admin
- **Submit endpoint:** `POST /submit` (same origin, urlencoded form)
- **Health:** `GET /health`

## Pieces (already set up)
- **D1 database** `combatforge_bugs` — created; id is in `wrangler.toml`. Schema in `schema.sql` (table `bugs`).
- **Discord webhook** — "CombatForge Bugs", posting to **#bug-reports** (already created in the server).
- **Secrets** (set at deploy time, never stored in the repo): `DISCORD_WEBHOOK_URL`, `ADMIN_KEY`
  (at least 32 random characters), and `IP_SALT` (at least 16 random characters).

## Deploy (first time, ~2 min)
```powershell
npx wrangler login      # click "Allow" in the browser
./deploy.ps1            # applies schema, deploys, prompts for the 3 secrets
```
Enter each secret when prompted (input is hidden). Never place them in chat, source control, or a URL.
Generate the two random values locally, for example with `openssl rand -hex 32`.

## Update later
For this privacy-hardening release, apply the idempotent schema and scrub before deploying:
```powershell
npm run schema
npm run migrate:privacy
npx wrangler deploy
```

## Wire-up on the marketing site
`playcombatforge.com` already has a **"Report a Bug"** button pointing at
`https://report.playcombatforge.com` (goes live once this worker is deployed).

## Security
Reviewed adversarially before first deploy (SQLi, XSS, spam/DoS, secrets, D1 correctness).
Guards in place: parameterized D1 queries, HTML-escaped admin view, a one-hour HMAC-signed HttpOnly
admin session, Discord-markdown-escaped embeds with mentions disabled, honeypot + atomic per-IP rate
limit (5 / 5 min), an allowlist for media-link hosts, a hard request-body cap, and fail-closed rate
limiting when `IP_SALT` is missing. Salted IP hashes live only in short-lived rate-limit buckets;
new bug rows do not retain IP hashes, raw User-Agent strings, or reporter contact information.
The privacy migration also blanks those three fields on existing rows and removes the obsolete
per-report IP-hash index.
