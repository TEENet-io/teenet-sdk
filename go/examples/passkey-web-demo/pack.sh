#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONTEXT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"

# 构建 Docker 镜像
docker build -f "${SCRIPT_DIR}/Dockerfile" -t passkey-web-demo:latest "${CONTEXT_DIR}"

# 导出并压缩
docker save passkey-web-demo:latest | gzip > "${SCRIPT_DIR}/passkey-web-demo.tar.gz"

echo "✅ 完成: passkey-web-demo.tar.gz"
