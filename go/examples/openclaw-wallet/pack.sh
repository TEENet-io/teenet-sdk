#!/usr/bin/env bash
# Build the openclaw-wallet Docker image and export it to user-management-system/static/.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONTEXT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"

IMAGE_NAME="${IMAGE_NAME:-openclaw-wallet}"
IMAGE_TAG="${IMAGE_TAG:-latest}"

echo "==> Building Docker image ${IMAGE_NAME}:${IMAGE_TAG}..."
docker build \
  -f "${SCRIPT_DIR}/Dockerfile" \
  -t "${IMAGE_NAME}:${IMAGE_TAG}" \
  "${CONTEXT_DIR}"

echo "==> Exporting image..."
docker save "${IMAGE_NAME}:${IMAGE_TAG}" | gzip > "${SCRIPT_DIR}/openclaw-wallet.tar.gz"

echo "==> Moving to user-management-system/static/..."
mv "${SCRIPT_DIR}/openclaw-wallet.tar.gz" ~/tee/user-management-system/static/openclaw-wallet.tar.gz

echo "✅ 完成: ~/tee/user-management-system/static/openclaw-wallet.tar.gz"
