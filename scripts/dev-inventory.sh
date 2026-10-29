#!/usr/bin/env bash
# Prints a repository inventory: tracked file counts and line counts per area.
# Used to keep status reports factual rather than estimated.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
mkdir -p .logs
# Mirror to a file so the report can be read back without re-running.
exec > >(tee .logs/inventory.log) 2>&1

count() {
  local label="$1"
  shift
  local files lines
  files="$(find "$@" -type f 2>/dev/null | wc -l)"
  lines="$(find "$@" -type f -exec cat {} + 2>/dev/null | wc -l)"
  printf '%-28s %4s files %8s lines\n' "$label" "$files" "$lines"
}

echo "=== inventory ==="
count "proto contracts" proto
count "shared library" libs/common/src/authmesh_common
count "generated stubs" libs/common/src/authmesh
count "gateway" services/gateway/src
count "auth-service" services/auth/src
count "user-service" services/user/src
count "helm chart" deploy/helm
count "observability config" deploy/observability
count "tests" tests
count "scripts" scripts

echo
echo "=== helm templates ==="
ls -1 deploy/helm/authmesh/templates deploy/helm/authmesh/templates/tests 2>/dev/null

echo
echo "=== images ==="
docker images --filter "reference=authmesh/*" \
  --format 'table {{.Repository}}\t{{.Tag}}\t{{.Size}}' 2>/dev/null

echo
echo "=== compose state ==="
docker compose ps --format 'table {{.Service}}\t{{.State}}\t{{.Status}}' 2>/dev/null
