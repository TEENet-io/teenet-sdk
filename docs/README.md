# TEENet SDK

The official client SDK for building applications on [TEENet](https://teenet.io) — a platform providing hardware-isolated runtime and managed key custody for any application that needs to protect secrets.

With a few lines of code, your application can sign messages with threshold keys, verify signatures, manage API secrets, and gate sensitive actions behind Passkey (WebAuthn) approval — all without ever touching a private key.

Available in **Go** and **TypeScript**.

> **Developer Preview.** APIs may evolve. Always test on non-production keys first.

---

## How It Works

Your application runs as a managed container on TEENet **Application Nodes**. The SDK call is local — not a round-trip over the public internet. Before a signature is produced, TEENet enforces your policy (M-of-N voting, Passkey approval, spending limits). Signing itself happens on separate **Key Management Nodes**, where keys are sharded across hardware TEE and **never assembled in any single place** — not even inside the TEE.

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

---

## Features

- **Threshold signing** — request signatures from keys sharded across independent TEE nodes; M-of-N voting is handled transparently inside `Sign()`.
- **Multi-algorithm** — ECDSA (SECP256K1, SECP256R1) and Schnorr (ED25519, SECP256K1 / BIP-340 Taproot).
- **Offline verification** — verify signatures locally without a round-trip to the platform.
- **API key vault** — store application secrets inside the TEE; sign HMAC payloads without ever seeing the raw key.
- **Passkey approval** — gate high-value or sensitive actions behind WebAuthn confirmation, with multi-level approval policies.
- **Dual-SDK** — identical surface in Go and TypeScript, so backend services and Node.js apps share the same mental model.
- **Mock server** — real cryptography, zero infrastructure, for local development and CI.

---

## Jump in

- [**Quick Start**](en/quick-start.md) — install the SDK and sign your first message
- [**API Reference**](en/api.md) — full Go + TypeScript reference with click-to-switch code tabs
- [**Mock Server**](en/mock-server.md) — real crypto, zero infra, for local dev
- [**Examples**](en/examples.md) — end-to-end sample apps

---

## Supported Algorithms

| Protocol | Curve | Use Case |
|----------|-------|----------|
| Schnorr (FROST) | ED25519 | EdDSA (also via `ProtocolEdDSA`) |
| Schnorr (FROST) | SECP256K1 | BIP-340 / Bitcoin Taproot |
| ECDSA (GG20) | SECP256K1 | Bitcoin, Ethereum |
| ECDSA (GG20) | SECP256R1 | NIST P-256, WebAuthn |

---

## TEENet Platform

The SDK is the client surface for [TEENet](https://teenet.io) — a platform providing hardware-isolated runtime and managed key custody for applications that need to protect secrets, from AI agent wallets to autonomous trading systems to cross-chain bridges.

Built on TEENet: [TEENet Wallet](https://github.com/TEENet-io/teenet-wallet) — a Passkey-protected, AI-agent-ready crypto wallet.

[Platform docs](https://teenet-io.github.io/) · [SDK on GitHub](https://github.com/TEENet-io/teenet-sdk)

**[中文文档 →](zh/)**
