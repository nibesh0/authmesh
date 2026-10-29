#!/usr/bin/env bash
# Ruff lint + format check, run in a container so no host Python is required.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUFF_VERSION="${RUFF_VERSION:-0.11.6}"

docker run --rm \
  --user "$(id -u):$(id -g)" \
  -e HOME=/tmp \
  -e PIP_CACHE_DIR=/tmp/pipcache \
  -v "${ROOT}:/work" \
  -w /work \
  python:3.12-slim \
  bash -euo pipefail -c "
    pip install --quiet --no-warn-script-location --target /tmp/tools 'ruff==${RUFF_VERSION}'
    export PYTHONPATH=/tmp/tools
    echo '==> ruff check'
    python -m ruff check .
    echo '==> ruff format --check'
    python -m ruff format --check .
  "
