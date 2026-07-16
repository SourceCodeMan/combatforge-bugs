# CombatForge Bugs — bug-report service

A single Cloudflare Worker that serves a bug-report form, stores each submission
in **D1** (SQLite), and posts it to the **#bug-reports** Discord channel via webhook.
No third-party tools; owned end to end.

- **Form (public):** https://report.playcombatforge.com
- **Inbox (private):** https://report.playcombatforge.com/admin?key=<ADMIN_KEY>
- **Submit endpoint:** `POST /submit` (same origin, urlencoded form)
- **Health:** `GET /health`

## Pieces (already set up)
- **D1 database** `combatforge_bugs` — created; id is in `wrangler.toml`. Schema in `schema.sql` (table `bugs`).
- **Discord webhook** — "CombatForge Bugs", posting to **#bug-reports** (already created in the server).
- **Secrets** (set at deploy time, never stored in the repo): `DISCORD_WEBHOOK_URL`, `ADMIN_KEY`, `IP_SALT`.

## Deploy (first time, ~2 min)
```powershell
npx wrangler login      # click "Allow" in the browser
./deploy.ps1            # applies schema, deploys, prompts for the 3 secrets
```
The three secret values are in Claude's chat summary — paste each when prompted (input is hidden).

## Update later
Edit `src/index.js`, then:
```powershell
npx wrangler deploy
```

## Wire-up on the marketing site
`playcombatforge.com` already has a **"Report a Bug"** button pointing at
`https://report.playcombatforge.com` (goes live once this worker is deployed).

## Security
Reviewed adversarially before first deploy (SQLi, XSS, spam/DoS, secrets, D1 correctness).
Guards in place: parameterized D1 queries, HTML-escaped admin view, Discord-markdown-escaped
embeds with mentions disabled, honeypot + atomic per-IP rate limit (5 / 5 min), a hard request
body-size cap (not Content-Length-trusting), and fail-closed IP hashing (needs `IP_SALT`).
