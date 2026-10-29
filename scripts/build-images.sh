#!/usr/bin/env bash
# Builds the three service images. Output is teed to .logs/build.log so long
# builds can be inspected after the fact.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

REGISTRY="${REGISTRY:-authmesh}"
TAG="${TAG:-dev}"
mkdir -p .logs

build() {
  local name="$1" dockerfile="$2"
  echo "==> building ${REGISTRY}/${name}:${TAG}"
  # No --progress flag: this repo is expected to build with either the legacy
  # builder or BuildKit, and the flag only exists on the latter.
  docker build \
    -f "$dockerfile" \
    -t "${REGISTRY}/${name}:${TAG}" \
    .
}

{
  build user-service services/user/Dockerfile
  build auth-service services/auth/Dockerfile
  build gateway services/gateway/Dockerfile
} 2>&1 | tee .logs/build.log

echo "==> images"
docker images --filter "reference=${REGISTRY}/*:${TAG}" \
  --format 'table {{.Repository}}\t{{.Tag}}\t{{.Size}}'
