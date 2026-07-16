# CombatForge Bugs - one-shot deploy.  (No secrets live in this file.)
#
# PREREQ (once):  npx wrangler login    then click "Allow" in the browser
# Then run:       ./deploy.ps1
# You'll be prompted to paste 3 secret values (Claude gave them to you in chat).

$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

Write-Host "[1/3] Applying D1 schema (creates the bugs table)..." -ForegroundColor Cyan
npx wrangler d1 execute combatforge_bugs --remote --file=./schema.sql

Write-Host "[2/3] Deploying the worker (plus report.playcombatforge.com custom domain)..." -ForegroundColor Cyan
npx wrangler deploy

Write-Host "[3/3] Setting secrets - paste each value when prompted (input is hidden):" -ForegroundColor Cyan
Write-Host "      order: DISCORD_WEBHOOK_URL, then ADMIN_KEY, then IP_SALT" -ForegroundColor DarkGray
npx wrangler secret put DISCORD_WEBHOOK_URL
npx wrangler secret put ADMIN_KEY
npx wrangler secret put IP_SALT

Write-Host ""
Write-Host "DONE." -ForegroundColor Green
Write-Host "  Form:  https://report.playcombatforge.com"
Write-Host "  Inbox: https://report.playcombatforge.com/admin?key=<ADMIN_KEY>"
Write-Host ""
Write-Host "Test: open the form, submit a bug, watch it appear in Discord #bug-reports." -ForegroundColor Yellow
