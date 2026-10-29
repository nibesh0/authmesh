#!/usr/bin/env bash
# Generates Python gRPC stubs from proto/ into libs/common/src/authmesh/.
#
# Codegen runs inside a pinned container so the result does not depend on the
# host's Python version or on grpcio-tools being installed locally.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GRPCIO_TOOLS_VERSION="${GRPCIO_TOOLS_VERSION:-1.71.0}"
PYTHON_IMAGE="${PYTHON_IMAGE:-python:3.12-slim}"
OUT_DIR="libs/common/src"

echo "==> generating protobuf stubs (grpcio-tools ${GRPCIO_TOOLS_VERSION})"

docker run --rm \
  --user "$(id -u):$(id -g)" \
  -e HOME=/tmp \
  -e PIP_CACHE_DIR=/tmp/pipcache \
  -v "${ROOT}:/work" \
  -w /work \
  "${PYTHON_IMAGE}" \
  bash -euo pipefail -c "
    pip install --quiet --no-warn-script-location --target /tmp/tools \
      'grpcio-tools==${GRPCIO_TOOLS_VERSION}'
    export PYTHONPATH=/tmp/tools
    rm -rf ${OUT_DIR}/authmesh
    mkdir -p ${OUT_DIR}
    python -m grpc_tools.protoc \
      --proto_path=proto \
      --python_out=${OUT_DIR} \
      --pyi_out=${OUT_DIR} \
      --grpc_python_out=${OUT_DIR} \
      \$(find proto -name '*.proto' | sort)

    # protoc emits plain directories; make them importable packages.
    find ${OUT_DIR}/authmesh -type d -exec touch {}/__init__.py \;
  "

echo "==> generated files:"
find "${ROOT}/${OUT_DIR}/authmesh" -type f -name '*.py' | sed "s|${ROOT}/||" | sort
