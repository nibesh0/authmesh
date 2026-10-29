#!/usr/bin/env bash
# Test runner.
#
#   ./scripts/run-tests.sh unit          # isolated, no infrastructure needed
#   ./scripts/run-tests.sh integration   # drives the Compose stack end to end
#   ./scripts/run-tests.sh all
#
# Unit tests run in a throwaway container on the Compose network so they can
# reach redis/mongo when a test asks for them.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

SUITE="${1:-unit}"
IMAGE="${TEST_IMAGE:-authmesh/test-runner:dev}"
COMPOSE_NETWORK="${COMPOSE_NETWORK:-authmesh_default}"
mkdir -p .logs

echo "==> building test runner image"
docker build -q -f tests/Dockerfile -t "$IMAGE" . >/dev/null

run_in_container() {
  local network_args=()
  if docker network inspect "$COMPOSE_NETWORK" >/dev/null 2>&1; then
    network_args=(--network "$COMPOSE_NETWORK")
  fi
  docker run --rm \
    "${network_args[@]}" \
    -e PYTHONPATH=/work \
    -e GATEWAY_URL="${GATEWAY_URL:-http://gateway:8080}" \
    -e REDIS_URL="${REDIS_URL:-redis://redis:6379/0}" \
    -e JWT_SECRET="${JWT_SECRET:-test-only-secret-0123456789abcdefghijklmnop}" \
    -e TOTP_ENCRYPTION_KEY="${TOTP_ENCRYPTION_KEY:-ZmRldi1vbmx5LWtleS1kby1ub3QtdXNlLWluLXByb2Q=}" \
    -e RECOVERY_CODE_PEPPER="${RECOVERY_CODE_PEPPER:-test-only-recovery-pepper-value}" \
    -v "${ROOT}:/work" \
    -w /work \
    "$IMAGE" "$@"
}

case "$SUITE" in
  unit)
    run_in_container python -m pytest tests/unit -m "not integration" -v \
      2>&1 | tee .logs/tests-unit.log
    ;;
  integration)
    echo "==> integration tests expect the stack to be up (make dev-up)"
    run_in_container python -m pytest tests/integration -v \
      2>&1 | tee .logs/tests-integration.log
    ;;
  all)
    run_in_container python -m pytest tests -v 2>&1 | tee .logs/tests-all.log
    ;;
  *)
    echo "usage: $0 [unit|integration|all]" >&2
    exit 64
    ;;
esac

exit "${PIPESTATUS[0]}"
