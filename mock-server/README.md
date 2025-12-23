# TEENet SDK Mock Consensus Server

用于测试 TEENet SDK 的模拟 Consensus 服务。

## 功能

- 模拟 `app-comm-consensus` HTTP API
- 支持所有签名算法：
  - ED25519 (Schnorr/EdDSA)
  - SECP256K1 (ECDSA 和 Schnorr)
  - SECP256R1 (ECDSA)
- 支持密钥生成 API
- 支持 API Key 和 Secret 操作
- 使用真实的密码学签名（非模拟数据）

## 快速开始

```bash
# 编译
make build

# 运行（默认端口 8089）
make run

# 或直接运行
go run .

# 自定义端口
MOCK_SERVER_PORT=9000 ./mock-server
```

## API 接口

### 健康检查
```bash
GET /api/health
```

### 获取公钥
```bash
GET /api/publickey/:app_instance_id
```

### 签名请求
```bash
POST /api/submit-request
Content-Type: application/json

{
  "app_instance_id": "test-ecdsa-secp256k1",
  "message": "base64编码的消息"
}
```

### 生成密钥
```bash
POST /api/generate-key
Content-Type: application/json

{
  "app_instance_id": "your-app-id",
  "curve": "secp256k1",
  "protocol": "ecdsa"
}
```

### 获取 API Key
```bash
GET /api/apikey/:name?app_instance_id=your-app-id
```

### 使用 API Secret 签名
```bash
POST /api/apikey/:name/sign
Content-Type: application/json

{
  "app_instance_id": "your-app-id",
  "message": "消息内容"
}
```

## 预置测试 App ID

| App ID | Protocol | Curve |
|--------|----------|-------|
| test-schnorr-ed25519 | schnorr | ed25519 |
| test-schnorr-secp256k1 | schnorr | secp256k1 |
| test-ecdsa-secp256k1 | ecdsa | secp256k1 |
| test-ecdsa-secp256r1 | ecdsa | secp256r1 |
| ethereum-wallet-app | ecdsa | secp256k1 |
| secure-messaging-app | schnorr | ed25519 |

## 使用 SDK 进行测试

```go
package main

import (
    "fmt"
    sdk "github.com/TEENet-io/teenet-sdk"
)

func main() {
    // 连接到 mock server
    client := sdk.NewClient("http://localhost:8089")
    client.SetDefaultAppID("test-ecdsa-secp256k1")
    defer client.Close()

    // 签名
    result, err := client.Sign([]byte("hello world"))
    if err != nil {
        panic(err)
    }
    fmt.Printf("Signature: %x\n", result.Signature)

    // 验证
    valid, err := client.Verify([]byte("hello world"), result.Signature)
    fmt.Printf("Valid: %v\n", valid)
}
```

## 注意事项

- 此服务仅用于开发和测试，不要在生产环境使用
- 使用确定性的私钥，签名可以验证但不安全
- 不支持投票模式（voting），所有请求都直接签名
