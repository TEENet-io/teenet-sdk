# 示例

完整的端到端示例在 [`go/examples/`](https://github.com/TEENet-io/teenet-sdk/tree/main/go/examples) 和 [`typescript/examples/`](https://github.com/TEENet-io/teenet-sdk/tree/main/typescript/examples) 目录下。

## 按类别

### 入门

| 示例 | 语言 | 说明 |
|---|---|---|
| [`basic/simple`](https://github.com/TEENet-io/teenet-sdk/tree/main/go/examples/basic/simple) | Go | 最小化的签名 + 校验 CLI |
| [`basic/voting`](https://github.com/TEENet-io/teenet-sdk/tree/main/go/examples/basic/voting) | Go | 多方 M-of-N 投票流程 |
| [`basic/forwarding`](https://github.com/TEENet-io/teenet-sdk/tree/main/go/examples/basic/forwarding) | Go | 跨节点转发请求 |
| [`generate-key`](https://github.com/TEENet-io/teenet-sdk/tree/main/go/examples/generate-key) | Go | 生成新的门限密钥 |
| [`typescript-test`](https://github.com/TEENet-io/teenet-sdk/tree/main/typescript/examples/typescript-test) | TypeScript | 集成测试用例 |

### API 密钥 & HMAC

| 示例 | 语言 | 说明 |
|---|---|---|
| [`apikey`](https://github.com/TEENet-io/teenet-sdk/tree/main/go/examples/apikey) | Go | 在 TEE 内保管应用密钥并签名 HMAC |

### Passkey 审批

| 示例 | 语言 | 说明 |
|---|---|---|
| [`passkey-web-demo`](https://github.com/TEENet-io/teenet-sdk/tree/main/go/examples/passkey-web-demo) | Go + 浏览器 | 基于 WebAuthn 的签名请求审批 |
| [`passkey-web-demo`](https://github.com/TEENet-io/teenet-sdk/tree/main/typescript/examples/passkey-web-demo) | TypeScript + 浏览器 | 同样的流程,TypeScript 版 |

### 投票 UI

| 示例 | 语言 | 说明 |
|---|---|---|
| [`voting-demo`](https://github.com/TEENet-io/teenet-sdk/tree/main/go/examples/voting-demo) | Go + 浏览器 | 交互式 M-of-N 投票面板 |

### 真实应用

| 示例 | 语言 | 说明 |
|---|---|---|
| [`teenet-wallet`](https://github.com/TEENet-io/teenet-wallet) | Go | 基于 SDK 构建的 Passkey 保护加密钱包(独立仓库) |
| [`finance-console`](https://github.com/TEENet-io/finance-console) | Go | 金融仪表盘示例(独立仓库) |
| [`admin`](https://github.com/TEENet-io/teenet-sdk/tree/main/go/examples/admin) | Go | 邀请 Passkey 用户、配置权限策略、管理 API 密钥 |

## 运行示例

大部分示例需要下面二者之一:

- 运行中的 TEENet 服务(环境变量里有 `SERVICE_URL` + `APP_INSTANCE_ID`),**或**
- [Mock Server](mock-server.md) 在 `:8089` 上运行

每个示例都有自己的 README 说明具体步骤。
