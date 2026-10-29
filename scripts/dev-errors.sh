#!/usr/bin/env bash
# Shows the most recent error entries per service, one per line, trimmed.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

TAIL="${TAIL:-600}"
WIDTH="${WIDTH:-3000}"

for service in gateway auth-service user-service; do
  echo "=== ${service} ==="
  docker compose logs --no-color --tail "$TAIL" "$service" 2>&1 \
    | grep -E '"level":"(ERROR|CRITICAL)"' \
    | tail -3 \
    | cut -c1-"$WIDTH"
  echo
done
