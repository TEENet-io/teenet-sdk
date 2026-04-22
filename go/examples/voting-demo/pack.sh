#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONTEXT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"

# 构建 Docker 镜像（context 指向 SDK 根目录，以满足 go.mod 中的 replace ../../）
docker build -f "${SCRIPT_DIR}/Dockerfile" -t voting-demo:latest "${CONTEXT_DIR}"

# 导出并压缩
docker save voting-demo:latest | gzip > "${SCRIPT_DIR}/voting-demo.tar.gz"

echo "✅ 完成: voting-demo.tar.gz"
