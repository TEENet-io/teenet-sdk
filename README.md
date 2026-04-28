# TEENet SDK

[![License: GPL-3.0](https://img.shields.io/badge/License-GPL--3.0-blue.svg)](LICENSE)
[![Go](https://img.shields.io/badge/Go-1.24+-00ADD8.svg?logo=go&logoColor=white)](https://go.dev)
[![Node.js](https://img.shields.io/badge/Node.js-18+-339933.svg?logo=node.js&logoColor=white)](https://nodejs.org)
[![npm](https://img.shields.io/badge/npm-%40teenet%2Fsdk-CB3837.svg?logo=npm&logoColor=white)](https://www.npmjs.com/package/@teenet/sdk)
[![Developer Preview](https://img.shields.io/badge/Status-Developer_Preview-orange.svg)]()
[![Docs](https://img.shields.io/badge/Docs-teenet--io.github.io-7c3aed.svg)](https://teenet-io.github.io/teenet-sdk/)

The official client SDK for building applications on [TEENet](https://teenet.io) — a platform that provides hardware-isolated runtime and managed key custody for any application that needs to protect secrets.

With a few lines of code, your application can sign messages with threshold keys, verify signatures, manage API secrets, and gate sensitive actions behind Passkey (WebAuthn) approval — all without ever touching a private key.

Available in **Go** and **TypeScript**.

> **Developer Preview.** APIs may evolve. Always test on non-production keys first.

## Requirements

- **Go SDK** — Go 1.24 or later
- **TypeScript SDK** — Node.js 18 or later
- **Mock server** (optional, for local development) — Go 1.24+ and `make`

No TEENet account is needed to try the SDK — the included mock server uses real cryptography and runs entirely locally.

## Quick Start

The fastest way to see the SDK working is against the local mock server: zero infrastructure, real cryptography, pre-generated test keys.

### 1. Run the mock server

```bash
cd mock-server
make build && make run
# listens on :8089 with pre-configured test keys
```

The mock ships with 8 ready-to-use app instances (`mock-app-id-01` through `mock-app-id-08`) covering every supported algorithm, M-of-N voting, and Passkey approval. All share the key name `default`. See [mock-server/README.md](mock-server/README.md) for the full table.

### 2. Install the SDK

**Go:**
```bash
go get github.com/TEENet-io/teenet-sdk/go
```

**TypeScript:**
```bash
npm install @teenet/sdk
```

### 3. Sign and verify

**Go:**
```go
package main

import (
    "context"
    "fmt"
    "log"

    sdk "github.com/TEENet-io/teenet-sdk/go"
)

func main() {
    ctx := context.Background()

    // For local dev with the mock server:
    client := sdk.NewClient("http://localhost:8089")
    client.SetDefaultAppInstanceID("mock-app-id-01") // Schnorr/ED25519
    defer client.Close()

    // When deployed on TEENet, SERVICE_URL and APP_INSTANCE_ID are
    // injected automatically — you can just call sdk.NewClient().

    msg := []byte("hello, teenet")
    res, err := client.Sign(ctx, msg, "default") // "default" is the mock's key name
    if err != nil {
        log.Fatal(err)
    }
    if !res.Success {
        log.Fatalf("sign failed: %s (%s)", res.Error, res.ErrorCode)
    }

    ok, _ := client.Verify(ctx, msg, res.Signature, "default")
    fmt.Printf("signature=%x valid=%v\n", res.Signature, ok)
}
```

**TypeScript:**
```ts
import { Client } from '@teenet/sdk';

async function main() {
    // For local dev with the mock server:
    const client = new Client('http://localhost:8089');
    client.setDefaultAppInstanceID('mock-app-id-01'); // Schnorr/ED25519

    // When deployed on TEENet, SERVICE_URL and APP_INSTANCE_ID are
    // injected automatically — you can just call `new Client()`.

    const msg = Buffer.from('hello, teenet');
    const res = await client.sign(msg, 'default'); // "default" is the mock's key name
    if (!res.success) {
        throw new Error(`sign failed: ${res.error} (${res.errorCode})`);
    }

    const ok = await client.verify(msg, res.signature, 'default');
    console.log(`signature=${res.signature.toString('hex')} valid=${ok}`);

    client.close();
}

main();
```

### Handling errors

`result.ErrorCode` / `result.errorCode` gives you a stable, typed hint. Common codes:

| Code | What to do |
|---|---|
| `SIGN_REQUEST_FAILED` | Retry — network or transient service issue |
| `SIGN_REQUEST_REJECTED` | Fix the request; inspect `result.Error` |
| `THRESHOLD_TIMEOUT` | Voting didn't finish in time — raise `PendingWaitTimeout` (Go) / `pendingWaitTimeout` (TypeScript) |
| `APPROVAL_PENDING` | Prompt a Passkey approver — follow the [approval flow](https://teenet-io.github.io/teenet-sdk/#/en/api?id=passkey-approval) |

Full list in the [API reference → Error codes](https://teenet-io.github.io/teenet-sdk/#/en/api?id=error-codes).

## How It Works

Your application runs as a managed container on TEENet **Application Nodes**. The SDK call is local — not a round-trip over the public internet. Before a signature is produced, TEENet enforces your policy (M-of-N voting, Passkey approval, spending limits). Signing itself happens on separate **Key Management Nodes**, where keys are sharded across hardware TEE and **never assembled in any single place** — not even inside the TEE.

<details>
<summary><b>Architecture diagram</b> — click to expand</summary>

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

Your app calls `Sign()`, `Verify()`, `GenerateKey()`, and approval APIs. Everything else — policy enforcement, key sharding, signing, audit — happens behind the SDK.

</details>

## Features

- **Threshold signing** — request signatures from keys sharded across independent TEE nodes; M-of-N voting is handled transparently inside `Sign()`.
- **Multi-algorithm** — ECDSA (SECP256K1, SECP256R1) and Schnorr (ED25519, SECP256K1 / BIP-340 Taproot).
- **Offline verification** — verify signatures locally without a round-trip to the platform.
- **API key vault** — store application secrets inside the TEE; sign HMAC payloads without ever seeing the raw key.
- **Passkey approval** — gate high-value or sensitive actions behind WebAuthn confirmation, with multi-level approval policies.
- **Dual-SDK** — identical surface in Go and TypeScript, so backend services and Node.js apps share the same mental model.
- **Mock server** — real cryptography, zero infrastructure, for local development and CI.

## What You Can Do

| Category | Methods |
|----------|---------|
| **Signing** | `Sign`, `Verify`, `GetStatus` |
| **Key management** | `GenerateKey`, `GetPublicKeys` |
| **API keys** | `GetAPIKey`, `SignWithAPISecret` |
| **Passkey approval** | `PasskeyLoginWithCredential`, `ApprovalRequestInit`, `ApprovalRequestConfirm`, `ApprovalAction`, `ApprovalPending` |
| **Admin** | `InvitePasskeyUser`, `UpsertPermissionPolicy`, `CreateAPIKey`, `ListAuditRecords`, `DeletePublicKey`, `DeleteAPIKey` |

Both SDKs expose the same surface — Go uses `PascalCase`, TypeScript uses `camelCase`.

> **Full API reference:** [**teenet-io.github.io/teenet-sdk**](https://teenet-io.github.io/teenet-sdk/) — unified Go + TypeScript reference with click-to-switch code tabs.

## Environment Variables

The SDK reads these automatically when constructed with no URL argument. Containers deployed by the TEENet platform have both injected.

| Variable | Description |
|---|---|
| `SERVICE_URL` | URL of the local TEENet service the SDK should talk to (e.g. `http://host.docker.internal:8089`) |
| `APP_INSTANCE_ID` | Unique identifier for this application instance — used to scope keys, policies, and signatures |

Override at runtime via `NewClient(url)` / `SetDefaultAppInstanceID(id)` (Go) or `new Client(url)` / `setDefaultAppInstanceID(id)` (TypeScript).

## Supported Algorithms

| Protocol | Curve | Use Case |
|----------|-------|----------|
| Schnorr (FROST) | ED25519 | EdDSA (also accessible via `ProtocolEdDSA`) |
| Schnorr (FROST) | SECP256K1 | BIP-340 / Bitcoin Taproot |
| ECDSA (GG20) | SECP256K1 | Bitcoin, Ethereum |
| ECDSA (GG20) | SECP256R1 | NIST P-256, WebAuthn |

### Picking a combo by target chain

Use `GenerateKey(protocol, curve)` with the row that matches your chain:

| Target | protocol | curve |
|---|---|---|
| Bitcoin Taproot (P2TR / BIP-340) | `ProtocolSchnorrBIP340` | `CurveSECP256K1` |
| Bitcoin Legacy / SegWit v0 | `ProtocolECDSA` | `CurveSECP256K1` |
| Ethereum / EVM chains | `ProtocolECDSA` | `CurveSECP256K1` |
| Solana / Ed25519 ecosystem | `ProtocolEdDSA` | `CurveED25519` |
| WebAuthn / NIST P-256 | `ProtocolECDSA` | `CurveSECP256R1` |
| Generic Schnorr escape hatch | `ProtocolSchnorr` | any supported curve |

`ProtocolEdDSA` and `ProtocolSchnorrBIP340` are semantic aliases that route to the same FROST/Schnorr backend path but restrict the curve, making intent obvious at the call site (and catching misuse before any network round-trip).

## Examples

Complete working examples live under [`go/examples/`](go/examples) and [`typescript/examples/`](typescript/examples):

- **basic** — sign, verify, multi-party voting
- **generate-key** — create new threshold keys
- **apikey** — store secrets and sign HMAC payloads inside the TEE
- **passkey-web-demo** — browser WebAuthn approval flow
- **voting-demo** — interactive M-of-N voting UI
- **admin** — invite users, manage permission policies

## Repository Layout

```
teenet-sdk/
├── go/             # Go SDK + examples
├── typescript/     # TypeScript SDK (@teenet/sdk) + examples
├── mock-server/    # Local platform mock with real cryptography
└── docs/           # Bilingual (EN + 中文) Docsify site — deployed via GitHub Pages
```

## Documentation

- **[teenet-io.github.io/teenet-sdk](https://teenet-io.github.io/teenet-sdk/)** — SDK docs site, bilingual (EN + 中文), with Go/TS tab switching
- **[Platform overview](https://teenet-io.github.io/)** — TEENet platform docs
- **[Go SDK README](go/README.md)** — Go-specific notes
- **[TypeScript SDK README](typescript/README.md)** — TypeScript-specific notes
- **[Mock server README](mock-server/README.md)** — local-first testing

## Getting Help

- **Bug reports, feature requests, questions** — [open a GitHub issue](https://github.com/TEENet-io/teenet-sdk/issues)
- **Security vulnerabilities** — follow [SECURITY.md](SECURITY.md); do not disclose details in public issues
- **Website** — [teenet.io](https://teenet.io)

Built on TEENet: [TEENet Wallet](https://github.com/TEENet-io/teenet-wallet) — a Passkey-protected, AI-agent-ready crypto wallet.

## Contributing

Contributions are welcome — bug fixes, new examples, additional language bindings, documentation improvements. Please open an issue or pull request.

## Disclaimer

This software is experimental and provided "as is" without warranty. It is intended for development and evaluation. Test thoroughly before using with production keys or real assets.

## License

Copyright (C) 2025-2026 TEENet Technology (Hong Kong) Limited.

GPL-3.0 — see [LICENSE](LICENSE).
