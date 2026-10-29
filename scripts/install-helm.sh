#!/usr/bin/env bash
# Installs the Helm CLI into ~/.local/bin (no root required).
set -euo pipefail

HELM_VERSION="${HELM_VERSION:-v3.19.0}"
DEST="${DEST:-$HOME/.local/bin}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

if command -v helm >/dev/null 2>&1; then
  echo "helm already installed: $(helm version --short)"
  exit 0
fi

mkdir -p "$DEST"
echo "downloading helm ${HELM_VERSION}..."
curl -fsSL "https://get.helm.sh/helm-${HELM_VERSION}-linux-amd64.tar.gz" -o "$TMP/helm.tgz"
tar -xzf "$TMP/helm.tgz" -C "$TMP"
install -m 0755 "$TMP/linux-amd64/helm" "$DEST/helm"
echo "installed -> $DEST/helm"
"$DEST/helm" version --short
