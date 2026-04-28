# API 参考

**Go** 和 **TypeScript** SDK 的统一 API 参考。每个代码块都有 **Go** 和 **TypeScript** 两个标签 —— 点击切换即可,页面会记住你这次会话的选择。

> Go SDK 使用 `PascalCase`,TypeScript SDK 使用 `camelCase`。方法集、参数和返回值结构完全一致。

---

## 安装

<!-- tabs:start -->

#### **Go**

```bash
go get github.com/TEENet-io/teenet-sdk/go
```

```go
import sdk "github.com/TEENet-io/teenet-sdk/go"
```

#### **TypeScript**

```bash
npm install @teenet/sdk
```

```ts
import { Client, Protocol, Curve } from '@teenet/sdk';
```

<!-- tabs:end -->

---

## 创建客户端

由 App Lifecycle Manager 部署的容器已经在环境变量里注入了 `SERVICE_URL` 和 `APP_INSTANCE_ID`,默认构造函数会自动读取。本地开发时显式传 URL 即可。

<!-- tabs:start -->

#### **Go**

```go
import (
    "time"
    sdk "github.com/TEENet-io/teenet-sdk/go"
)

// 自动从环境变量读取 SERVICE_URL 和 APP_INSTANCE_ID。
client := sdk.NewClient()
defer client.Close()

// 本地开发时显式传 URL。
client := sdk.NewClient("http://localhost:8089")
client.SetDefaultAppInstanceID("my-app-instance")

// 带选项(传空字符串时仍然会读环境变量)。
opts := &sdk.ClientOptions{
    RequestTimeout:     45 * time.Second,
    PendingWaitTimeout: 10 * time.Second, // 等待投票完成的最大时间
    Debug:              true,             // 打印签名/轮询日志
}
client := sdk.NewClientWithOptions("", opts)
```

#### **TypeScript**

```ts
import { Client } from '@teenet/sdk';

// 自动从 process.env 读取 SERVICE_URL 和 APP_INSTANCE_ID。
const client = new Client();

// 本地开发时显式传 URL。
const client = new Client('http://localhost:8089', {
    requestTimeout: 45_000,
    pendingWaitTimeout: 10_000, // 等待投票完成的最大时间
    debug: true,
});
client.setDefaultAppInstanceID('my-app-instance');

// ... 用完记得关
client.close();
```

<!-- tabs:end -->

---

## 签名与校验

**哈希由谁做。** **ECDSA**(secp256k1/secp256r1)要求调用方先哈希,再把 32 字节传给 `Sign` / `Verify` —— TEE 后端只接受 32 字节预哈希输入。**Schnorr** 和 **EdDSA** 直接传原始消息,SDK 内部哈希。

<!-- tabs:start -->

#### **Go**

```go
// Schnorr / EdDSA —— 传原始消息
result, err := client.Sign(ctx, []byte("hello, teenet"), "my-schnorr-key")
if result != nil && !result.Success {
    log.Fatalf("签名失败: %s (%s)", result.Error, result.ErrorCode)
}
if err != nil {
    log.Fatalf("签名失败: %v", err)
}
if result == nil {
    log.Fatal("签名失败: 空结果")
}
ok, _ := client.Verify(ctx, []byte("hello, teenet"), result.Signature, "my-schnorr-key")

// ECDSA secp256k1 —— 调用方做哈希(以太坊风格 Keccak-256)
hashedMsg := crypto.Keccak256(rawMessage)
result, err = client.Sign(ctx, hashedMsg, "my-ecdsa-key")
if result != nil && !result.Success {
    log.Fatalf("签名失败: %s (%s)", result.Error, result.ErrorCode)
}
if err != nil {
    log.Fatalf("签名失败: %v", err)
}
if result == nil {
    log.Fatal("签名失败: 空结果")
}
ok, _ = client.Verify(ctx, hashedMsg, result.Signature, "my-ecdsa-key")
```

#### **TypeScript**

```ts
// Schnorr / EdDSA —— 传原始消息
const message = Buffer.from('hello, teenet');
const result  = await client.sign(message, 'my-schnorr-key');
if (!result.success) throw new Error(`${result.error} (${result.errorCode})`);
const ok = await client.verify(message, result.signature, 'my-schnorr-key');

// ECDSA secp256k1 —— 调用方做哈希(Keccak-256)
import { keccak_256 } from '@noble/hashes/sha3';
const hash   = Buffer.from(keccak_256(rawMessage));
const result = await client.sign(hash, 'my-ecdsa-key');
const ok     = await client.verify(hash, result.signature, 'my-ecdsa-key');
```

<!-- tabs:end -->

> **离线校验。** 两个 SDK 还提供独立的校验函数(`VerifySignature` / `verifySignature`),无需 client 实例,适合离线 / 第三方校验。

---

## 投票状态查询

按 hash 查询签名请求的当前状态。`Sign()` 内部会自动轮询 —— 一般不需要手动调用,但适合在长流程或面板里展示进度。

<!-- tabs:start -->

#### **Go**

```go
status, err := client.GetStatus(ctx, "0xabc...")
if status.Found {
    fmt.Printf("status=%s votes=%d/%d\n",
        status.Status, status.CurrentVotes, status.RequiredVotes)
}
```

#### **TypeScript**

```ts
const status = await client.getStatus('0xabc...');
if (status.found) {
    console.log(`status=${status.status} votes=${status.currentVotes}/${status.requiredVotes}`);
}
```

<!-- tabs:end -->

---

## 密钥生成

`GenerateKey(protocol, curve)` 是唯一的入口。选择你目标链对应的一行:

| 目标 | protocol | curve |
|---|---|---|
| Bitcoin Taproot(P2TR / BIP-340) | `ProtocolSchnorrBIP340` | `CurveSECP256K1` |
| Bitcoin 传统地址 / SegWit v0 | `ProtocolECDSA` | `CurveSECP256K1` |
| Ethereum / EVM 系链 | `ProtocolECDSA` | `CurveSECP256K1` |
| Solana / Ed25519 生态 | `ProtocolEdDSA` | `CurveED25519` |
| WebAuthn / NIST P-256 | `ProtocolECDSA` | `CurveSECP256R1` |
| 通用 Schnorr 逃生口 | `ProtocolSchnorr` | 任意受支持曲线 |

`ProtocolEdDSA` 和 `ProtocolSchnorrBIP340` 是**语义别名**,底层都走 FROST/Schnorr,但限制了曲线 —— 用错会在网络请求之前被拦截。

<!-- tabs:start -->

#### **Go**

```go
// Bitcoin Taproot
res, err := client.GenerateKey(ctx, sdk.ProtocolSchnorrBIP340, sdk.CurveSECP256K1)

// Ethereum / EVM
res, err := client.GenerateKey(ctx, sdk.ProtocolECDSA, sdk.CurveSECP256K1)

// Solana
res, err := client.GenerateKey(ctx, sdk.ProtocolEdDSA, sdk.CurveED25519)

if res.Success {
    fmt.Printf("id=%d name=%s pubkey=%s\n",
        res.PublicKey.ID, res.PublicKey.Name, res.PublicKey.KeyData)
}
```

#### **TypeScript**

```ts
// Bitcoin Taproot
const taproot = await client.generateKey(Protocol.SchnorrBIP340, Curve.SECP256K1);

// Ethereum / EVM
const eth = await client.generateKey(Protocol.ECDSA, Curve.SECP256K1);

// Solana
const sol = await client.generateKey(Protocol.EdDSA, Curve.ED25519);

if (taproot.success) {
    console.log(`id=${taproot.publicKey.id} name=${taproot.publicKey.name}`);
}
```

<!-- tabs:end -->

---

## 列出公钥

返回当前 `APP_INSTANCE_ID` 绑定的所有公钥。

<!-- tabs:start -->

#### **Go**

```go
keys, err := client.GetPublicKeys(ctx)
for _, k := range keys {
    fmt.Printf("%s  %s/%s  %s\n", k.Name, k.Protocol, k.Curve, k.KeyData)
}
```

#### **TypeScript**

```ts
const keys = await client.getPublicKeys();
for (const k of keys) {
    console.log(`${k.name}  ${k.protocol}/${k.curve}  ${k.keyData}`);
}
```

<!-- tabs:end -->

---

## API 密钥(HMAC 保险箱)

在 TEE 内部保管应用密钥。调用方能拿到非保密部分(`apiKey`)并签名 HMAC 负载,全程都接触不到真正的 secret。

<!-- tabs:start -->

#### **Go**

```go
// 取回 API 密钥的元信息(公开部分)。
key, err := client.GetAPIKey(ctx, "my-api-key")
if key.Success {
    fmt.Printf("api key: %s\n", key.APIKey)
}

// 用存储的 secret 对负载做 HMAC-SHA256 签名 —— secret 留在 TEE 内。
sig, err := client.SignWithAPISecret(ctx, "my-api-key", []byte("payload"))
if sig.Success {
    fmt.Printf("%s: %s\n", sig.Algorithm, sig.Signature)
}
```

#### **TypeScript**

```ts
const key = await client.getAPIKey('my-api-key');
if (key.success) console.log('api key:', key.apiKey);

const sig = await client.signWithAPISecret('my-api-key', Buffer.from('payload'));
if (sig.success) console.log(`${sig.algorithm}: ${sig.signature}`);
```

<!-- tabs:end -->

---

## Passkey 审批

敏感签名可以用 WebAuthn 把关。SDK 会帮你处理挑战 / 响应的往返 —— 你的代码只需要在需要凭证时调用 `navigator.credentials.get(...)`(或平台等价 API)。

<!-- tabs:start -->

#### **Go**

```go
// 调用方提供的 WebAuthn 执行器 —— SDK 需要凭证时会调用它。
getCredential := func(options interface{}) ([]byte, error) {
    // 实际场景:把 options 传到浏览器,调用 navigator.credentials.get,
    // 再把凭证 JSON 字节返回来。
    return []byte(`{}`), nil
}

// 0) 用 Passkey 登录,拿到 approval token。
login, err := client.PasskeyLoginWithCredential(ctx, getCredential)
if err != nil {
    log.Fatalf("登录失败: %v", err)
}
if login == nil {
    log.Fatal("登录失败: 空结果")
}
if !login.Success {
    log.Fatalf("登录失败: %s", login.Error)
}
approvalToken := login.Data["token"].(string)

// 1) 发起方直接调用 Sign。后端策略会自动创建审批请求。
sign, err := client.Sign(ctx, []byte(`{"to":"0x1234","amount":"1"}`), "my-key")
if sign == nil {
    if err != nil {
        log.Fatalf("签名失败: %v", err)
    }
    log.Fatal("签名失败: 空结果")
}
if sign.ErrorCode != "APPROVAL_PENDING" {
    if err != nil {
        log.Fatalf("签名失败: %v", err)
    }
    log.Fatalf("期望 APPROVAL_PENDING,实际得到 %+v", sign)
}
if sign.VotingInfo == nil {
    log.Fatal("审批请求缺少 voting info")
}
requestID := sign.VotingInfo.RequestID

// 可选:审批方查询当前 Passkey 身份下待处理的任务。
pending, _ := client.ApprovalPending(ctx, approvalToken, nil)
_ = pending

// 2) 审批方确认请求(SDK = 挑战 + WebAuthn + 确认)。
confirm, _ := client.ApprovalRequestConfirmWithCredential(ctx, requestID, getCredential, approvalToken)
taskID := uint64(confirm.Data["task_id"].(float64))

// 3) 审批方对生成的任务执行 Action。
_, _ = client.ApprovalActionWithCredential(ctx, taskID, "APPROVE", getCredential, approvalToken)
```

#### **TypeScript**

```ts
const getCredential = async (options: unknown) => {
    // 实际场景:在浏览器里调用 navigator.credentials.get(options),返回凭证 JSON。
    return {};
};

// 0) Passkey 登录 → approval token
const login = await client.passkeyLoginWithCredential(getCredential);
if (!login.success) throw new Error(login.error || 'passkey 登录失败');
const approvalToken = String(login.data?.token || '');

// 1) 发起方直接调用 sign()
const sign = await client.sign(Buffer.from('{"to":"0x1234","amount":"1"}'), 'my-key');
if (sign.errorCode !== 'APPROVAL_PENDING') throw new Error('期望 APPROVAL_PENDING');
const requestId = sign.votingInfo!.requestId;

// 可选:按 app + key 过滤待处理任务
const pending = await client.approvalPending(approvalToken, {
    applicationId: 42,
    publicKeyName: 'my-key',
});

// 2) 审批方确认(挑战 + WebAuthn + 确认)
const confirm = await client.approvalRequestConfirmWithCredential(requestId, getCredential, approvalToken);
const taskId  = Number(confirm.data?.task_id);

// 3) 审批方执行 Action
await client.approvalActionWithCredential(taskId, 'APPROVE', getCredential, approvalToken);
```

<!-- tabs:end -->

> SDK 负责协议编排,但 WebAuthn 本身(`navigator.credentials`)仍在浏览器 / 应用代码里跑 —— SDK 不负责 UI 交互。

---

## 管理员接口

需要具备管理员权限的 approval token 才能调用。所有管理员接口在两个 SDK 之间完全对应。

| 能力 | Go | TypeScript |
|---|---|---|
| 邀请 Passkey 用户 | `InvitePasskeyUser(ctx, req)` | `invitePasskeyUser(req)` |
| 列出 Passkey 用户 | `ListPasskeyUsers(ctx, page, limit)` | `listPasskeyUsers(page, limit)` |
| 删除 Passkey 用户 | `DeletePasskeyUser(ctx, userID)` | `deletePasskeyUser(userId)` |
| 更新权限策略 | `UpsertPermissionPolicy(ctx, req)` | `upsertPermissionPolicy(req)` |
| 查询权限策略 | `GetPermissionPolicy(ctx, keyName)` | `getPermissionPolicy(keyName)` |
| 删除权限策略 | `DeletePermissionPolicy(ctx, keyName)` | `deletePermissionPolicy(keyName)` |
| 创建 API 密钥 | `CreateAPIKey(ctx, req)` | `createAPIKey(req)` |
| 删除 API 密钥 | `DeleteAPIKey(ctx, keyName)` | `deleteAPIKey(keyName)` |
| 删除公钥 | `DeletePublicKey(ctx, keyName)` | `deletePublicKey(keyName)` |
| 审计记录 | `ListAuditRecords(ctx, page, limit)` | `listAuditRecords(page, limit)` |
| 部署日志 | `GetDeploymentLogs(ctx, query)` | `getDeploymentLogs(query)` |

<!-- tabs:start -->

#### **Go**

```go
// 邀请新的 Passkey 用户
inv, _ := client.InvitePasskeyUser(ctx, sdk.PasskeyInviteRequest{
    Email: "alice@example.com",
    Role:  "approver",
})

// 给密钥附加权限策略
pol, _ := client.UpsertPermissionPolicy(ctx, sdk.PolicyRequest{
    PublicKeyName: "treasury-key",
    Levels:        []sdk.PolicyLevel{ /* ... */ },
})
_ = pol

// 创建 API 密钥
k, _ := client.CreateAPIKey(ctx, sdk.CreateAPIKeyRequest{Name: "deploy-bot"})
fmt.Println(k.APIKey)
```

#### **TypeScript**

```ts
// 邀请新的 Passkey 用户
const inv = await client.invitePasskeyUser({
    email: 'alice@example.com',
    role:  'approver',
});

// 给密钥附加权限策略
const pol = await client.upsertPermissionPolicy({
    publicKeyName: 'treasury-key',
    levels: [ /* ... */ ],
});

// 创建 API 密钥
const k = await client.createAPIKey({ name: 'deploy-bot' });
console.log(k.apiKey);
```

<!-- tabs:end -->

---

## 常量

<!-- tabs:start -->

#### **Go**

```go
// 协议
sdk.ProtocolECDSA         // "ecdsa"
sdk.ProtocolSchnorr       // "schnorr"        —— 通用 Schnorr(逃生口)
sdk.ProtocolEdDSA         // "eddsa"          —— 别名;只能搭配 CurveED25519
sdk.ProtocolSchnorrBIP340 // "schnorr-bip340" —— 别名;只能搭配 CurveSECP256K1

// 曲线
sdk.CurveED25519    // "ed25519"
sdk.CurveSECP256K1  // "secp256k1"
sdk.CurveSECP256R1  // "secp256r1"
```

#### **TypeScript**

```ts
// 协议
Protocol.ECDSA          // 'ecdsa'
Protocol.Schnorr        // 'schnorr'         —— 通用 Schnorr(逃生口)
Protocol.EdDSA          // 'eddsa'           —— 别名;只能搭配 Curve.ED25519
Protocol.SchnorrBIP340  // 'schnorr-bip340'  —— 别名;只能搭配 Curve.SECP256K1

// 曲线
Curve.ED25519     // 'ed25519'
Curve.SECP256K1   // 'secp256k1'
Curve.SECP256R1   // 'secp256r1'
```

<!-- tabs:end -->

---

## 错误码

返回在 `SignResult.ErrorCode`(Go)/ `result.errorCode`(TypeScript)。

| 错误码 | 含义 |
|------|---------|
| `INVALID_INPUT` | 客户端校验失败 |
| `SIGN_REQUEST_FAILED` | 提交请求 / 网络失败 |
| `SIGN_REQUEST_REJECTED` | 服务拒绝请求 |
| `SIGNATURE_DECODE_FAILED` | 签名字节解码失败 |
| `UNEXPECTED_STATUS` | 服务返回未知状态 |
| `MISSING_HASH` | 响应缺少 hash |
| `STATUS_QUERY_FAILED` | 轮询状态请求失败 |
| `SIGN_FAILED` | 投票最终为失败 |
| `THRESHOLD_TIMEOUT` | 在 `PendingWaitTimeout` (Go) / `pendingWaitTimeout` (TypeScript) 内未达到门限 |
| `APPROVAL_PENDING` | 需要 Passkey 审批 —— 走审批流程 |

Go 里,`APPROVAL_PENDING` 还通过哨兵 `sdk.ErrApprovalPending` 暴露:

```go
if errors.Is(err, sdk.ErrApprovalPending) { /* 提示审批方 */ }
```

---

## 支持的算法

| 协议 | 曲线 | 调用方需哈希? | 签名长度 | 适用场景 |
|------|------|---------------|-----------|----------|
| Schnorr (FROST) | ED25519 | 否(传原始消息) | 64 B | EdDSA(也可用 `ProtocolEdDSA`) |
| Schnorr (FROST) | SECP256K1 | 否(传原始消息) | 64 B | BIP-340 / Bitcoin Taproot |
| ECDSA (GG20) | SECP256K1 | **是**(32 B) | 64 B(r‖s) | Bitcoin、Ethereum |
| ECDSA (GG20) | SECP256R1 | **是**(32 B) | 64 B(r‖s) | NIST P-256、WebAuthn |
