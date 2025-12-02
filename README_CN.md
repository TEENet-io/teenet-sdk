# TEENet SDK

TEE-DAO密钥管理操作的简化Go SDK，支持投票共识功能。

## 特性

- **透明投票**: 自动处理M-of-N阈值投票，无需手动协调
- **简洁API**: 类似teenet-sdk的简洁接口：Sign(), Verify(), GetPublicKey()
- **回调支持**: 通过HTTP回调异步通知投票完成
- **签名验证**: 离线验证，支持多种协议(ECDSA, Schnorr)和曲线(ED25519, SECP256K1, SECP256R1)
- **基于HTTP**: 无TLS/gRPC复杂性，简单的REST API通信

## 安装

```bash
go get github.com/TEENet-io/teenet-sdk
```

## 快速开始

```go
import sdk "github.com/TEENet-io/teenet-sdk"

// 创建客户端
client := sdk.NewClient("http://localhost:8089")
client.SetDefaultAppID("your-app-id")
defer client.Close()

// 签名消息
result, err := client.Sign([]byte("Hello, TEENet!"))
if err != nil || !result.Success {
    log.Fatal(err)
}

fmt.Printf("签名: %x\n", result.Signature)

// 验证签名
valid, err := client.Verify([]byte("Hello, TEENet!"), result.Signature)
fmt.Printf("签名有效: %v\n", valid)
```

查看详细的英文文档: [README.md](README.md)

## 项目结构

```
teenet-sdk/
├── client.go           # 公共 API 门面
├── types.go            # 公共类型定义和常量
├── internal/           # 内部实现（不对外暴露）
│   ├── client/         # 客户端实现
│   ├── crypto/         # 加密操作
│   ├── network/        # HTTP 和回调服务器
│   ├── types/          # 内部类型定义
│   └── util/           # 工具函数
└── examples/           # 示例应用程序
    ├── basic/          # 基础使用示例
    ├── signature-tool/ # Web签名工具
    └── voting-demo/    # 多方投票演示
```

## 示例程序

SDK包含多个完整的示例应用程序：

### 1. Basic Examples (`examples/basic/`)
- `simple/`: 基本签名和验证
- `voting/`: 多方投票场景
- `forwarding/`: 请求转发示例

### 2. Signature Tool (`examples/signature-tool/`)
Web界面的签名工具，提供完整的前端UI。

### 3. Voting Demo (`examples/voting-demo/`)
交互式多实例投票功能的演示应用。

## 测试

运行测试：
```bash
go test ./...
```

## 许可证

Copyright (c) 2025 TEENet Technology (Hong Kong) Limited. All Rights Reserved.

详见 [LICENSE](LICENSE)
