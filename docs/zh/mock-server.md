# Mock Server

Mock Server 用于本地开发和测试,模拟 TEENet 的签名服务。它使用**真实的密码学签名** —— 输出与生产完全相同的代码路径可校验 —— 但不依赖 TEE、不依赖 TEE-DAO 集群、不依赖任何外部服务。

## 运行

```bash
cd mock-server
make build && make run
# 监听 :8089
```

或指定端口:

```bash
MOCK_SERVER_PORT=9000 ./mock-server
```

## 内置配置

Mock Server 自带 8 个预置 app instance,覆盖全部协议 + 曲线组合,以及 M-of-N 投票和 Passkey 审批:

| App Instance ID | 协议 | 曲线 | 说明 |
|---|---|---|---|
| `mock-app-id-01` | Schnorr | ED25519 | 直签 |
| `mock-app-id-02` | Schnorr(BIP-340) | SECP256K1 | 直签 |
| `mock-app-id-03` | ECDSA | SECP256K1 | 直签 |
| `mock-app-id-04` | ECDSA | SECP256R1 | 直签 |
| `mock-app-id-05` | ECDSA | SECP256K1 | 2-of-3 投票(voter 1) |
| `mock-app-id-06` | ECDSA | SECP256K1 | 2-of-3 投票(voter 2) |
| `mock-app-id-07` | ECDSA | SECP256K1 | 2-of-3 投票(voter 3) |
| `mock-app-id-08` | ECDSA | SECP256K1 | 需 Passkey 审批 |

将 SDK 指向 `http://localhost:8089`,选任意一个作为 `APP_INSTANCE_ID` 即可。不需要提前生成密钥 —— 启动时会自动生成测试密钥,名称统一为 `default`。

## 接口

```
GET  /api/health
GET  /api/publickeys/:app_instance_id
POST /api/submit-request
GET  /api/cache/:hash
POST /api/generate-key
GET  /api/apikey/:name
POST /api/apikey/:name/sign
```

请求和响应格式与真实的签名服务一致,所以针对 Mock Server 写的代码可以直接跑在生产环境。

## 源码

在仓库的 [`mock-server/`](https://github.com/TEENet-io/teenet-sdk/tree/main/mock-server) 目录 —— 是一个很小的 Gin 应用(基本就一个文件)。
