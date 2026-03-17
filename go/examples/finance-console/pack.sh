#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONTEXT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"

# 构建 Docker 镜像
docker build -f "${SCRIPT_DIR}/Dockerfile" -t finance-console:latest "${CONTEXT_DIR}"

# 导出并压缩
docker save finance-console:latest | gzip > "${SCRIPT_DIR}/finance-console.tar.gz"

echo "✅ 完成: finance-console.tar.gz"
mv finance-console.tar.gz ~/tee/user-management-system/static/finance-demo.tar.gz