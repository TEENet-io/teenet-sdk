# TEENet SDK

在 [TEENet](https://teenet.io) 平台上构建应用的官方客户端 SDK —— TEENet 为需要保护密钥的应用提供硬件级隔离运行时和托管密钥服务。

只需几行代码,你的应用就能使用门限签名、校验签名、管理 API 密钥,以及通过 Passkey(WebAuthn)审批敏感操作 —— 全程都不接触私钥。

支持 **Go** 和 **TypeScript**。

> **开发者预览版。** API 可能会调整。请先在非生产密钥上测试。

---

## 运行原理

你的应用作为托管容器运行在 TEENet 的 **Application Nodes** 上。SDK 调用是本地的 —— 不会走公网。签名之前,TEENet 会执行策略检查(M-of-N 投票、Passkey 审批、支出规则)。真正的签名由独立的 **Key Management Nodes** 完成,密钥分片存储于硬件 TEE 中,**任何地方都不会把完整密钥组装出来** —— TEE 内部也不会。

```
+-- TEENet ----------------------------------------+
|                                                  |
|   +-- Application Nodes ---------------------+   |
|   |                                          |   |
|   |   +-- Docker container -------------+    |   |
|   |   |   Your Application              |    |   |
|   |   +-----+---------------------------+    |   |
|   |         |                                |   |
|   |         |  teenet-sdk  (HTTP, local)     |   |
|   |         v                                |   |
|   |   Policy & Approval                      |   |
|   |   M-of-N voting, Passkey, spending       |   |
|   |                                          |   |
|   +--------+---------------------------------+   |
|            |                                     |
|            v                                     |
|   +-- Key Management Nodes ------------------+   |
|   |                                          |   |
|   |   +-----+ +-----+ +-----+ +-----+        |   |
|   |   |Node1| |Node2| |Node3| |Node4|  ...   |   |
|   |   |shard| |shard| |shard| |shard|        |   |
|   |   +-----+ +-----+ +-----+ +-----+        |   |
|   |                                          |   |
|   |   Threshold signing on hardware TEE      |   |
|   |   Intel TDX / AMD SEV                    |   |
|   |   Keys never assembled anywhere          |   |
|   |                                          |   |
|   +------------------------------------------+   |
|                                                  |
+--------------------------------------------------+
```

你的应用只需调用 `Sign()`、`Verify()`、`GenerateKey()` 及审批相关 API。其他一切 —— 策略执行、密钥分片、签名、审计 —— 都在 SDK 后面完成。

---

## 特性

- **门限签名** —— 请求签名,密钥分片在多个独立 TEE 节点间协作;M-of-N 投票在 `Sign()` 内部透明完成。
- **多算法** —— ECDSA(SECP256K1、SECP256R1)和 Schnorr(ED25519、SECP256K1 / BIP-340 Taproot)。
- **本地校验** —— 本地校验签名,无需再访问平台。
- **API 密钥保险箱** —— 应用密钥存储在 TEE 内;可直接获得 HMAC 签名结果,永不接触原始密钥。
- **Passkey 审批** —— 高价值或敏感操作可由 WebAuthn 审批把关,支持多级审批策略。
- **双语言 SDK** —— Go 和 TypeScript 的 API 一致,后端服务和 Node.js 应用可共用同一套心智模型。
- **Mock Server** —— 真实密码学实现、零基础设施,用于本地开发和 CI。

---

## 快速入口

- [**快速上手**](zh/quick-start.md) —— 安装 SDK 并完成首次签名
- [**API 参考**](zh/api.md) —— Go + TypeScript 完整 API,代码示例点击标签即可切换
- [**Mock Server**](zh/mock-server.md) —— 真实密码学、零基础设施,本地开发用
- [**示例**](zh/examples.md) —— 端到端示例应用

---

## 支持的算法

| 协议 | 曲线 | 适用场景 |
|------|------|---------|
| Schnorr (FROST) | ED25519 | EdDSA(也可通过 `ProtocolEdDSA`) |
| Schnorr (FROST) | SECP256K1 | BIP-340 / Bitcoin Taproot |
| ECDSA (GG20) | SECP256K1 | Bitcoin、Ethereum |
| ECDSA (GG20) | SECP256R1 | NIST P-256、WebAuthn |

---

## TEENet 平台

这个 SDK 是 [TEENet](https://teenet.io) 的客户端 ——该平台为需要保护密钥的应用提供硬件级隔离运行时和托管密钥服务,覆盖 AI Agent 钱包、自动交易系统、跨链桥等场景。目前处于开发者预览阶段。

基于 TEENet 构建的应用:[TEENet Wallet](https://github.com/TEENet-io/teenet-wallet) —— 使用 Passkey 保护、面向 AI Agent 的加密货币钱包。

[平台文档](https://teenet-io.github.io/) · [SDK on GitHub](https://github.com/TEENet-io/teenet-sdk)

**[← English docs](/)**
