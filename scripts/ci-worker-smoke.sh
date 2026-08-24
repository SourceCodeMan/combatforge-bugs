#!/usr/bin/env bash
set -euo pipefail

port="${CI_WORKER_PORT:-8788}"
base_url="http://127.0.0.1:${port}"
admin_key="${CI_ADMIN_KEY:-combatforge-ci-admin-key-0000000000000000}"
ip_salt="${CI_IP_SALT:-combatforge-ci-rate-limit-salt-0000000000}"
log_root="${RUNNER_TEMP:-${TMPDIR:-/tmp}}"
log_file="${log_root%/}/combatforge-bugs-wrangler-${$}.log"
state_dir="$(mktemp -d "${TMPDIR:-/tmp}/combatforge-bugs-ci.XXXXXX")"
worker_pid=""
wrangler_bin="${WRANGLER_BIN:-./node_modules/.bin/wrangler}"

cleanup() {
  local status=$?
  if [[ -n "$worker_pid" ]]; then
    kill "$worker_pid" 2>/dev/null || true
    wait "$worker_pid" 2>/dev/null || true
  fi
  rm -rf -- "$state_dir"
  if [[ $status -ne 0 ]]; then
    echo "Wrangler log follows:" >&2
    tail -200 "$log_file" >&2 || true
  else
    rm -f "$log_file"
  fi
  exit "$status"
}
trap cleanup EXIT

"$wrangler_bin" d1 execute combatforge_bugs --local \
  --persist-to "$state_dir" --file=./schema.sql

"$wrangler_bin" dev --local --ip 127.0.0.1 --port "$port" --persist-to "$state_dir" \
  --var "ADMIN_KEY:${admin_key}" \
  --var "IP_SALT:${ip_salt}" \
  --var "DISCORD_WEBHOOK_URL:https://discord.invalid" >"$log_file" 2>&1 &
worker_pid=$!

ready=0
for _ in {1..60}; do
  if curl --fail --silent --show-error "${base_url}/health" >/dev/null 2>&1; then
    ready=1
    break
  fi
  if ! kill -0 "$worker_pid" 2>/dev/null; then
    break
  fi
  sleep 1
done
if [[ $ready -ne 1 ]]; then
  echo "Reporter Worker did not become healthy at ${base_url}" >&2
  exit 1
fi

SMOKE_BASE="$base_url" SMOKE_ADMIN_KEY="$admin_key" node scripts/smoke.mjs
