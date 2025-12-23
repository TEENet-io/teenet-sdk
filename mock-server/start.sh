#!/bin/bash

# TEENet SDK Mock Server 启动脚本

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

PORT="${MOCK_SERVER_PORT:-8089}"
BINARY="./mock-server"

# 颜色
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}  TEENet SDK Mock Consensus Server${NC}"
echo -e "${GREEN}========================================${NC}"

# 检查是否已有进程在运行
if pgrep -f "mock-server" > /dev/null 2>&1; then
    echo -e "${YELLOW}⚠️  Mock server 已在运行，正在停止...${NC}"
    pkill -f "mock-server" 2>/dev/null
    sleep 1
fi

# 检查端口是否被占用
if lsof -i:$PORT > /dev/null 2>&1; then
    echo -e "${RED}❌ 端口 $PORT 已被占用${NC}"
    echo "请使用: MOCK_SERVER_PORT=其他端口 $0"
    exit 1
fi

# 编译（如果需要）
if [ ! -f "$BINARY" ] || [ "main.go" -nt "$BINARY" ]; then
    echo -e "${YELLOW}📦 正在编译...${NC}"
    go build -o mock-server .
    if [ $? -ne 0 ]; then
        echo -e "${RED}❌ 编译失败${NC}"
        exit 1
    fi
    echo -e "${GREEN}✅ 编译成功${NC}"
fi

# 启动服务
echo -e "${GREEN}🚀 启动 Mock Server (端口: $PORT)${NC}"
echo ""

MOCK_SERVER_PORT=$PORT exec $BINARY
