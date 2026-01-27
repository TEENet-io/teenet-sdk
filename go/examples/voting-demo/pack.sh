#!/bin/bash

# 构建 Docker 镜像
docker build -t voting-demo:latest .

# 导出并压缩
docker save voting-demo:latest | gzip > voting-demo.tar.gz

echo "✅ 完成: voting-demo.tar.gz"
