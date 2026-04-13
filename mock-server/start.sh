#!/bin/bash

# TEENet SDK Mock Server 启动脚本

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

PORT="${MOCK_SERVER_PORT:-8089}"
BINARY="./mock-server"

# WebAuthn / Passkey 配置。mock-server 在启动时会强制读取
# PASSKEY_RP_ID 和 PASSKEY_RP_ORIGIN,没设会直接退出。
# 本地开发默认指向 localhost:8080;如需改,请在外部导出。
export PASSKEY_RP_ID="${PASSKEY_RP_ID:-localhost}"
export PASSKEY_RP_ORIGIN="${PASSKEY_RP_ORIGIN:-http://localhost:8080}"
export PASSKEY_RP_NAME="${PASSKEY_RP_NAME:-TEENet Mock}"
export PASSKEY_REQUIRE_UV="${PASSKEY_REQUIRE_UV:-true}"
export PASSKEY_PLATFORM_ONLY="${PASSKEY_PLATFORM_ONLY:-false}"

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
    echo -e "${YELLOW}⚠️  Mock server 已在运行,正在停止...${NC}"
    pkill -f "mock-server" 2>/dev/null
    sleep 1
fi

# 检查端口是否被占用
if lsof -i:$PORT > /dev/null 2>&1; then
    echo -e "${RED}❌ 端口 $PORT 已被占用${NC}"
    echo "请使用: MOCK_SERVER_PORT=其他端口 $0"
    exit 1
fi

# 判断是否需要重新编译:只要任一非测试源文件比二进制新,就重建。
# 之前只看 main.go,webauthn.go 等新增文件改动会被忽略,跑旧二进制。
needs_rebuild=0
if [ ! -f "$BINARY" ]; then
    needs_rebuild=1
else
    for src in *.go; do
        case "$src" in
            *_test.go) continue ;;
        esac
        if [ "$src" -nt "$BINARY" ]; then
            needs_rebuild=1
            break
        fi
    done
fi

if [ "$needs_rebuild" = "1" ]; then
    echo -e "${YELLOW}📦 正在编译...${NC}"
    if ! go build -o mock-server .; then
        echo -e "${RED}❌ 编译失败${NC}"
        exit 1
    fi
    echo -e "${GREEN}✅ 编译成功${NC}"
fi

# 启动服务
echo -e "${GREEN}🚀 启动 Mock Server (端口: $PORT, RP: $PASSKEY_RP_ID)${NC}"
echo ""

MOCK_SERVER_PORT=$PORT exec $BINARY
