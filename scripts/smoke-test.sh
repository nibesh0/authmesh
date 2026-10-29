#!/usr/bin/env bash
# Runs the end-to-end smoke test against a running gateway.
#
#   ./scripts/smoke-test.sh                       # http://localhost:8080
#   GATEWAY_URL=http://host:8080 ./scripts/smoke-test.sh
#
# Output is also written to .logs/smoke.log. Uses the host python3 when available
# and falls back to a container, so it works on a machine with no Python.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
mkdir -p .logs

GATEWAY_URL="${GATEWAY_URL:-http://localhost:8080}"

run() {
  if command -v python3 >/dev/null 2>&1; then
    python3 "${ROOT}/scripts/smoke_test.py" --base-url "$GATEWAY_URL"
  else
    docker run --rm \
      --network host \
      -v "${ROOT}/scripts:/scripts:ro" \
      python:3.12-slim \
      python /scripts/smoke_test.py --base-url "$GATEWAY_URL"
  fi
}

run 2>&1 | tee .logs/smoke.log
exit "${PIPESTATUS[0]}"
