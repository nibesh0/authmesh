#!/usr/bin/env bash
# Rebuild the images and restart the Compose stack, then wait for health.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
mkdir -p .logs

echo "==> rebuilding images"
bash scripts/build-images.sh > .logs/rebuild.log 2>&1 || {
  echo "build failed; see .logs/rebuild.log" >&2
  tail -30 .logs/rebuild.log >&2
  exit 1
}

echo "==> recreating containers"
docker compose up -d --force-recreate --no-build gateway auth-service user-service \
  >> .logs/rebuild.log 2>&1

echo "==> waiting for health"
for _ in $(seq 1 60); do
  unhealthy="$(docker compose ps --format '{{.Service}} {{.Status}}' \
    | grep -Ec 'starting|unhealthy' || true)"
  if [[ "$unhealthy" == "0" ]]; then
    break
  fi
  sleep 2
done

docker compose ps --format 'table {{.Service}}\t{{.State}}\t{{.Status}}'
