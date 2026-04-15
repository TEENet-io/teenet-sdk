# TEENet SDK

[![License: GPL-3.0](https://img.shields.io/badge/License-GPL--3.0-blue.svg)](LICENSE)
[![Go](https://img.shields.io/badge/Go-1.24-00ADD8.svg?logo=go&logoColor=white)](https://go.dev)
[![npm](https://img.shields.io/badge/npm-%40teenet%2Fsdk-CB3837.svg?logo=npm&logoColor=white)](https://www.npmjs.com/package/@teenet/sdk)
[![Developer Preview](https://img.shields.io/badge/Status-Developer_Preview-orange.svg)]()

The official client SDK for building applications on [TEENet](https://teenet.io) — a platform that provides hardware-isolated runtime and managed key custody for any application that needs to protect secrets.

With a few lines of code, your application can sign messages with threshold keys, verify signatures, manage API secrets, and gate sensitive actions behind Passkey (WebAuthn) approval — all without ever touching a private key.

Available in **Go** and **TypeScript**.

> **Developer Preview.** APIs may evolve. Always test on non-production keys first.

## How It Works

```
       Your Application
              |
              v   teenet-sdk  (HTTP)
       +--------------+
       |   TEENet     |
       |   Platform   |   Hardware TEE (Intel TDX / AMD SEV)
       +--------------+   Threshold signing across isolated nodes
```

Your app calls `Sign()`, `Verify()`, `GenerateKey()`, and approval APIs. The platform handles everything else: key sharding, threshold consensus, Passkey flows, and audit logging. Private keys are never assembled in any single place — not even inside the TEE.

## Features

- **Threshold signing** — request signatures from keys sharded across independent TEE nodes; M-of-N voting is handled transparently inside `Sign()`.
- **Multi-algorithm** — ECDSA (SECP256K1, SECP256R1) and Schnorr (ED25519, SECP256K1 / BIP-340 Taproot).
- **Offline verification** — verify signatures locally without a round-trip to the platform.
- **API key vault** — store application secrets inside the TEE; sign HMAC payloads without ever seeing the raw key.
- **Passkey approval** — gate high-value or sensitive actions behind WebAuthn confirmation, with multi-level approval policies.
- **Dual-SDK** — identical surface in Go and TypeScript, so backend services and Node.js apps share the same mental model.
- **Mock server** — real cryptography, zero infrastructure, for local development and CI.

## Quick Start

### Go

```bash
go get github.com/TEENet-io/teenet-sdk/go
```

```go
import (
    "context"
    sdk "github.com/TEENet-io/teenet-sdk/go"
)

ctx := context.Background()
client := sdk.NewClient("http://localhost:8089")
defer client.Close()

// Load APP_INSTANCE_ID from the environment. Containers deployed by the
// App Lifecycle Manager have this variable injected automatically.
client.Init()

// For local development, set it explicitly instead:
// client.SetDefaultAppInstanceID("my-app-instance")

// Sign — voting, if configured, is handled internally.
result, err := client.Sign(ctx, []byte("hello, teenet"), "my-key")
if err != nil || !result.Success {
    // inspect result.Error / result.ErrorCode
}

// Verify offline.
ok, _ := client.Verify(ctx, []byte("hello, teenet"), result.Signature, "my-key")
```

### TypeScript

```bash
npm install @teenet/sdk
```

```ts
import { Client } from '@teenet/sdk';

const client = new Client('http://localhost:8089');
client.init(); // loads APP_INSTANCE_ID from process.env (auto-injected when deployed)

const result = await client.sign(Buffer.from('hello, teenet'), 'my-key');
const valid  = await client.verify(Buffer.from('hello, teenet'), result.signature, 'my-key');
```

### Mock Server

Run a local mock of the platform (real crypto, pre-configured test keys) for development and testing:

```bash
cd mock-server
make build && make run
```

The mock listens on `:8089` and ships with ready-to-use app instances for every supported curve and protocol. See [`mock-server/README.md`](mock-server/README.md).

## What You Can Do

| Category | Methods |
|----------|---------|
| **Signing** | `Sign`, `Verify`, `GetStatus` |
| **Key management** | `GenerateKey`, `GetPublicKeys` |
| **API keys** | `GetAPIKey`, `SignWithAPISecret` |
| **Passkey approval** | `PasskeyLoginWithCredential`, `ApprovalRequestInit`, `ApprovalRequestConfirm`, `ApprovalAction` |
| **Admin** | `InvitePasskeyUser`, `UpsertPermissionPolicy`, `CreateAPIKey`, … |

Both SDKs expose the same surface — Go uses `PascalCase`, TypeScript uses `camelCase`.

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

`ProtocolEdDSA` and `ProtocolSchnorrBIP340` are semantic aliases that route to
the same FROST/Schnorr backend path but restrict the curve, making intent
obvious at the call site (and catching misuse before any network round-trip).

## Examples

Complete working examples live under [`go/examples/`](go/examples) and [`typescript/examples/`](typescript/examples):

- **basic** — sign, verify, multi-party voting
- **generate-key** — create new threshold keys
- **apikey** — store secrets and sign HMAC payloads inside the TEE
- **passkey-web-demo** — browser WebAuthn approval flow
- **voting-demo** — interactive M-of-N voting UI
- **finance-console** — sample dashboard built on the SDK
- **admin** — invite users, manage permission policies

## Repository Layout

```
teenet-sdk/
├── go/             # Go SDK + examples
├── typescript/     # TypeScript SDK (@teenet/sdk) + examples
├── mock-server/    # Local platform mock with real crypto
└── docs/
```

## Documentation

- **Platform overview** — [teenet-io.github.io](https://teenet-io.github.io/)
- **Go SDK** — [`go/`](go)
- **TypeScript SDK** — [`typescript/README.md`](typescript/README.md)
- **Mock server** — [`mock-server/README.md`](mock-server/README.md)

## TEENet Platform

The SDK is the client surface for [TEENet](https://teenet.io) — a platform providing hardware-isolated runtime and managed key custody for applications that need to protect secrets, from AI agent wallets to autonomous trading systems to cross-chain bridges. TEENet is currently in Developer Preview.

Built on TEENet: [TEENet Wallet](https://github.com/TEENet-io/teenet-wallet) — a Passkey-protected, AI-agent-ready crypto wallet.

## Contributing

Contributions are welcome — bug fixes, new examples, additional language bindings, documentation improvements. Please open an issue or pull request.

## Disclaimer

This software is experimental and provided "as is" without warranty. It is intended for development and evaluation. Test thoroughly before using with production keys or real assets.

## License

Copyright (C) 2025-2026 TEENet Technology (Hong Kong) Limited.

GPL-3.0 — see [LICENSE](LICENSE).
