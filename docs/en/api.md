# API Reference

Unified API reference for both the **Go** and **TypeScript** SDKs. Each code
block has **Go** and **TypeScript** tabs — click the one you care about and
the page remembers your choice for the rest of the session.

> The Go SDK uses `PascalCase`, the TypeScript SDK uses `camelCase`. The method
> set, arguments, and return shapes are otherwise identical.

---

## Installation

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

## Creating a client

Containers deployed by the App Lifecycle Manager have `SERVICE_URL` and
`APP_INSTANCE_ID` injected into the environment. The default constructor picks
them up automatically. For local development, pass the URL explicitly.

<!-- tabs:start -->

#### **Go**

```go
import (
    "time"
    sdk "github.com/TEENet-io/teenet-sdk/go"
)

// Reads SERVICE_URL and APP_INSTANCE_ID from env.
client := sdk.NewClient()
defer client.Close()

// Explicit URL for local dev.
client := sdk.NewClient("http://localhost:8089")
client.SetDefaultAppInstanceID("my-app-instance")

// With options (empty string still reads env).
opts := &sdk.ClientOptions{
    RequestTimeout:     45 * time.Second,
    PendingWaitTimeout: 10 * time.Second, // max wait for voting completion
    Debug:              true,             // verbose sign/polling logs
}
client := sdk.NewClientWithOptions("", opts)
```

#### **TypeScript**

```ts
import { Client } from '@teenet/sdk';

// Reads SERVICE_URL and APP_INSTANCE_ID from process.env.
const client = new Client();

// Explicit URL for local dev.
const client = new Client('http://localhost:8089', {
    requestTimeout: 45_000,
    pendingWaitTimeout: 10_000, // max wait for voting completion
    debug: true,
});
client.setDefaultAppInstanceID('my-app-instance');

// ... later
client.close();
```

<!-- tabs:end -->

---

## Signing &amp; verification

**Hashing responsibility.** For **ECDSA** (secp256k1/secp256r1), hash the
message yourself before calling `Sign` / `Verify` — the TEE backend requires
exactly 32 bytes of pre-hashed input. For **Schnorr** and **EdDSA**, pass the
raw message and the SDK handles hashing.

<!-- tabs:start -->

#### **Go**

```go
// Schnorr / EdDSA — raw message
result, err := client.Sign(ctx, []byte("hello, teenet"), "my-schnorr-key")
if result != nil && !result.Success {
    log.Fatalf("sign failed: %s (%s)", result.Error, result.ErrorCode)
}
if err != nil {
    log.Fatalf("sign failed: %v", err)
}
if result == nil {
    log.Fatal("sign failed: empty result")
}
ok, _ := client.Verify(ctx, []byte("hello, teenet"), result.Signature, "my-schnorr-key")

// ECDSA secp256k1 — caller hashes (Ethereum-style Keccak-256)
hashedMsg := crypto.Keccak256(rawMessage)
result, err = client.Sign(ctx, hashedMsg, "my-ecdsa-key")
if result != nil && !result.Success {
    log.Fatalf("sign failed: %s (%s)", result.Error, result.ErrorCode)
}
if err != nil {
    log.Fatalf("sign failed: %v", err)
}
if result == nil {
    log.Fatal("sign failed: empty result")
}
ok, _ = client.Verify(ctx, hashedMsg, result.Signature, "my-ecdsa-key")
```

#### **TypeScript**

```ts
// Schnorr / EdDSA — raw message
const message = Buffer.from('hello, teenet');
const result  = await client.sign(message, 'my-schnorr-key');
if (!result.success) throw new Error(`${result.error} (${result.errorCode})`);
const ok = await client.verify(message, result.signature, 'my-schnorr-key');

// ECDSA secp256k1 — caller hashes (Keccak-256)
import { keccak_256 } from '@noble/hashes/sha3';
const hash   = Buffer.from(keccak_256(rawMessage));
const result = await client.sign(hash, 'my-ecdsa-key');
const ok     = await client.verify(hash, result.signature, 'my-ecdsa-key');
```

<!-- tabs:end -->

> **Standalone verification.** Both SDKs also expose signature verification
> helpers (`VerifySignature` / `verifySignature`) that don't require a client,
> useful for offline / third-party verification.

---

## Voting status

Query the current status of a signing request by its hash. `Sign()` polls this
internally — you rarely need to call it directly, but it's useful for long
flows and dashboards.

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

## Key generation

`GenerateKey(protocol, curve)` is the single entry point. Pick the row matching
your target chain:

| Target | protocol | curve |
|---|---|---|
| Bitcoin Taproot (P2TR / BIP-340) | `ProtocolSchnorrBIP340` | `CurveSECP256K1` |
| Bitcoin Legacy / SegWit v0 | `ProtocolECDSA` | `CurveSECP256K1` |
| Ethereum / EVM chains | `ProtocolECDSA` | `CurveSECP256K1` |
| Solana / Ed25519 ecosystem | `ProtocolEdDSA` | `CurveED25519` |
| WebAuthn / NIST P-256 | `ProtocolECDSA` | `CurveSECP256R1` |
| Generic Schnorr escape hatch | `ProtocolSchnorr` | any supported curve |

`ProtocolEdDSA` and `ProtocolSchnorrBIP340` are **semantic aliases** that route
to the same FROST/Schnorr backend path but restrict the curve — misuse is
caught before any network round-trip.

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

## Listing public keys

Return every public key bound to the current `APP_INSTANCE_ID`.

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

## API keys (HMAC vault)

Store application secrets inside the TEE. Callers can retrieve the non-secret
portion (`apiKey`) and sign HMAC payloads without ever seeing the raw secret.

<!-- tabs:start -->

#### **Go**

```go
// Retrieve the API key metadata (the public portion).
key, err := client.GetAPIKey(ctx, "my-api-key")
if key.Success {
    fmt.Printf("api key: %s\n", key.APIKey)
}

// Sign an HMAC-SHA256 payload using the stored secret — secret stays in the TEE.
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

## Passkey approval

Gate sensitive signing behind WebAuthn. The SDK orchestrates the
challenge/response round-trips — your code only needs to invoke
`navigator.credentials.get(...)` (or the platform equivalent) when prompted.

<!-- tabs:start -->

#### **Go**

```go
// Caller-supplied WebAuthn runner — SDK calls this when a credential is needed.
getCredential := func(options interface{}) ([]byte, error) {
    // In practice: marshal options to the browser, run navigator.credentials.get,
    // return the credential JSON bytes.
    return []byte(`{}`), nil
}

// 0) Log in with a passkey to obtain an approval token.
login, err := client.PasskeyLoginWithCredential(ctx, getCredential)
if err != nil {
    log.Fatalf("login failed: %v", err)
}
if login == nil {
    log.Fatal("login failed: empty result")
}
if !login.Success {
    log.Fatalf("login: %s", login.Error)
}
approvalToken := login.Data["token"].(string)

// 1) Initiator: just call Sign. Backend policy auto-creates the approval request.
sign, err := client.Sign(ctx, []byte(`{"to":"0x1234","amount":"1"}`), "my-key")
if sign == nil {
    if err != nil {
        log.Fatalf("sign failed: %v", err)
    }
    log.Fatal("sign failed: empty result")
}
if sign.ErrorCode != "APPROVAL_PENDING" {
    if err != nil {
        log.Fatalf("sign failed: %v", err)
    }
    log.Fatalf("expected APPROVAL_PENDING, got %+v", sign)
}
if sign.VotingInfo == nil {
    log.Fatal("approval request missing voting info")
}
requestID := sign.VotingInfo.RequestID

// Optional: approver lists pending tasks for the current passkey identity.
pending, _ := client.ApprovalPending(ctx, approvalToken, nil)
_ = pending

// 2) Approver confirms the request (SDK = challenge + WebAuthn + confirm).
confirm, _ := client.ApprovalRequestConfirmWithCredential(ctx, requestID, getCredential, approvalToken)
taskID := uint64(confirm.Data["task_id"].(float64))

// 3) Approver takes action on the resulting task.
_, _ = client.ApprovalActionWithCredential(ctx, taskID, "APPROVE", getCredential, approvalToken)
```

#### **TypeScript**

```ts
const getCredential = async (options: unknown) => {
    // In practice: run navigator.credentials.get(options) in the browser,
    // return the credential JSON.
    return {};
};

// 0) Passkey login → approval token
const login = await client.passkeyLoginWithCredential(getCredential);
if (!login.success) throw new Error(login.error || 'passkey login failed');
const approvalToken = String(login.data?.token || '');

// 1) Initiator: just call sign()
const sign = await client.sign(Buffer.from('{"to":"0x1234","amount":"1"}'), 'my-key');
if (sign.errorCode !== 'APPROVAL_PENDING') throw new Error('expected APPROVAL_PENDING');
const requestId = sign.votingInfo!.requestId;

// Optional: filter pending tasks by app + key
const pending = await client.approvalPending(approvalToken, {
    applicationId: 42,
    publicKeyName: 'my-key',
});

// 2) Approver confirms (challenge + WebAuthn + confirm)
const confirm = await client.approvalRequestConfirmWithCredential(requestId, getCredential, approvalToken);
const taskId  = Number(confirm.data?.task_id);

// 3) Approver takes action
await client.approvalActionWithCredential(taskId, 'APPROVE', getCredential, approvalToken);
```

<!-- tabs:end -->

> The SDK orchestrates the protocol. WebAuthn itself (`navigator.credentials`)
> still runs in browser/app code — the SDK never owns UI interaction.

---

## Admin operations

Available to callers holding an admin-capable approval token. All admin methods
mirror each other across languages.

| Capability | Go | TypeScript |
|---|---|---|
| Invite passkey user | `InvitePasskeyUser(ctx, req)` | `invitePasskeyUser(req)` |
| List passkey users | `ListPasskeyUsers(ctx, page, limit)` | `listPasskeyUsers(page, limit)` |
| Delete passkey user | `DeletePasskeyUser(ctx, userID)` | `deletePasskeyUser(userId)` |
| Upsert permission policy | `UpsertPermissionPolicy(ctx, req)` | `upsertPermissionPolicy(req)` |
| Get permission policy | `GetPermissionPolicy(ctx, keyName)` | `getPermissionPolicy(keyName)` |
| Delete permission policy | `DeletePermissionPolicy(ctx, keyName)` | `deletePermissionPolicy(keyName)` |
| Create API key | `CreateAPIKey(ctx, req)` | `createAPIKey(req)` |
| Delete API key | `DeleteAPIKey(ctx, keyName)` | `deleteAPIKey(keyName)` |
| Delete public key | `DeletePublicKey(ctx, keyName)` | `deletePublicKey(keyName)` |
| Audit records | `ListAuditRecords(ctx, page, limit)` | `listAuditRecords(page, limit)` |
| Deployment logs | `GetDeploymentLogs(ctx, query)` | `getDeploymentLogs(query)` |

<!-- tabs:start -->

#### **Go**

```go
// Invite a new passkey user
inv, _ := client.InvitePasskeyUser(ctx, sdk.PasskeyInviteRequest{
    Email: "alice@example.com",
    Role:  "approver",
})

// Attach a permission policy to a key
pol, _ := client.UpsertPermissionPolicy(ctx, sdk.PolicyRequest{
    PublicKeyName: "treasury-key",
    Levels:        []sdk.PolicyLevel{ /* ... */ },
})
_ = pol

// Create an API key
k, _ := client.CreateAPIKey(ctx, sdk.CreateAPIKeyRequest{Name: "deploy-bot"})
fmt.Println(k.APIKey)
```

#### **TypeScript**

```ts
// Invite a new passkey user
const inv = await client.invitePasskeyUser({
    email: 'alice@example.com',
    role:  'approver',
});

// Attach a permission policy to a key
const pol = await client.upsertPermissionPolicy({
    publicKeyName: 'treasury-key',
    levels: [ /* ... */ ],
});

// Create an API key
const k = await client.createAPIKey({ name: 'deploy-bot' });
console.log(k.apiKey);
```

<!-- tabs:end -->

---

## Constants

<!-- tabs:start -->

#### **Go**

```go
// Protocols
sdk.ProtocolECDSA         // "ecdsa"
sdk.ProtocolSchnorr       // "schnorr"        — generic Schnorr (escape hatch)
sdk.ProtocolEdDSA         // "eddsa"          — alias; only valid with CurveED25519
sdk.ProtocolSchnorrBIP340 // "schnorr-bip340" — alias; only valid with CurveSECP256K1

// Curves
sdk.CurveED25519    // "ed25519"
sdk.CurveSECP256K1  // "secp256k1"
sdk.CurveSECP256R1  // "secp256r1"
```

#### **TypeScript**

```ts
// Protocols
Protocol.ECDSA          // 'ecdsa'
Protocol.Schnorr        // 'schnorr'         — generic Schnorr (escape hatch)
Protocol.EdDSA          // 'eddsa'           — alias; only valid with Curve.ED25519
Protocol.SchnorrBIP340  // 'schnorr-bip340'  — alias; only valid with Curve.SECP256K1

// Curves
Curve.ED25519     // 'ed25519'
Curve.SECP256K1   // 'secp256k1'
Curve.SECP256R1   // 'secp256r1'
```

<!-- tabs:end -->

---

## Error codes

Returned on `SignResult.ErrorCode` (Go) / `result.errorCode` (TypeScript).

| Code | Meaning |
|------|---------|
| `INVALID_INPUT` | Client-side validation failed |
| `SIGN_REQUEST_FAILED` | Submit request / network failure |
| `SIGN_REQUEST_REJECTED` | Service rejected the request |
| `SIGNATURE_DECODE_FAILED` | Signature bytes could not be decoded |
| `UNEXPECTED_STATUS` | Unexpected status value from service |
| `MISSING_HASH` | Pending response missing hash |
| `STATUS_QUERY_FAILED` | Polling status request failed |
| `SIGN_FAILED` | Voting finalized as failed |
| `THRESHOLD_TIMEOUT` | Threshold not met before `PendingWaitTimeout` (Go) / `pendingWaitTimeout` (TypeScript) |
| `APPROVAL_PENDING` | Request requires passkey approval — follow the approval flow |

In Go, `APPROVAL_PENDING` is also surfaced as the sentinel `sdk.ErrApprovalPending`:

```go
if errors.Is(err, sdk.ErrApprovalPending) { /* prompt approver */ }
```

---

## Supported algorithms

| Protocol | Curve | Caller hashes? | Signature | Use case |
|----------|-------|---------------|-----------|----------|
| Schnorr (FROST) | ED25519 | No (raw message) | 64 B | EdDSA (also via `ProtocolEdDSA`) |
| Schnorr (FROST) | SECP256K1 | No (raw message) | 64 B | BIP-340 / Bitcoin Taproot |
| ECDSA (GG20) | SECP256K1 | **Yes** (32 B) | 64 B (r‖s) | Bitcoin, Ethereum |
| ECDSA (GG20) | SECP256R1 | **Yes** (32 B) | 64 B (r‖s) | NIST P-256, WebAuthn |
