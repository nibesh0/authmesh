#!/usr/bin/env bash
# Compact status of the Compose stack plus a short, width-limited log tail.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

LINES="${LINES_PER_SERVICE:-8}"
WIDTH="${WIDTH:-240}"

echo "=== containers ==="
docker compose ps -a --format 'table {{.Service}}\t{{.State}}\t{{.Status}}'

for service in user-service auth-service gateway; do
  echo
  echo "=== ${service} (last ${LINES}) ==="
  # Stack traces are multi-kilobyte JSON strings; truncate so this stays readable.
  docker compose logs --no-color --tail "$LINES" "$service" 2>&1 \
    | cut -c1-"$WIDTH" \
    | sed "s/^/  /"
done
