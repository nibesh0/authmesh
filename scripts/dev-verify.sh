#!/usr/bin/env bash
# One command to bring the local stack to a known state and verify it:
# refresh .env, rebuild images, recreate containers, clear abuse counters, then
# run the end-to-end smoke test.
#
#   ./scripts/dev-verify.sh            # rebuild + verify
#   SKIP_BUILD=1 ./scripts/dev-verify.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
mkdir -p .logs

if [[ ! -f .env ]]; then
  cp .env.example .env
  echo "created .env from .env.example"
fi

if [[ "${SKIP_BUILD:-0}" != "1" ]]; then
  echo "==> building images"
  bash scripts/build-images.sh > .logs/verify-build.log 2>&1 || {
    echo "build failed; last lines:" >&2
    tail -40 .logs/verify-build.log >&2
    exit 1
  }
fi

echo "==> recreating services"
docker compose up -d --no-build --force-recreate \
  user-service auth-service gateway > .logs/verify-up.log 2>&1

echo "==> waiting for health"
for _ in $(seq 1 90); do
  pending="$(docker compose ps --format '{{.Status}}' | grep -Ec 'starting|unhealthy' || true)"
  [[ "$pending" == "0" ]] && break
  sleep 2
done
docker compose ps --format 'table {{.Service}}\t{{.State}}\t{{.Status}}'

echo
echo "==> clearing rate-limit and lockout counters"
bash scripts/dev-reset-limits.sh || echo "(reset skipped)"

echo
echo "==> smoke test"
bash scripts/smoke-test.sh
