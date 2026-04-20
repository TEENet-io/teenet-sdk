# TEENet SDK

The official client SDK for building applications on [TEENet](https://teenet.io) — a platform providing hardware-isolated runtime and managed key custody for any application that needs to protect secrets.

With a few lines of code, your application can sign messages with threshold keys, verify signatures, manage API secrets, and gate sensitive actions behind Passkey (WebAuthn) approval — all without ever touching a private key.

Available in **Go** and **TypeScript**.

> **Developer Preview.** APIs may evolve. Always test on non-production keys first.

---

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

Your app calls `Sign()`, `Verify()`, `GenerateKey()`, and approval APIs. The platform handles everything else: key sharding, threshold signing, Passkey flows, and audit logging. Private keys are never assembled in any single place — not even inside the TEE.

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

- [**Quick Start**](quick-start.md) — install the SDK and sign your first message
- [**API Reference**](API.md) — full Go + TypeScript reference with click-to-switch code tabs
- [**Mock Server**](mock-server.md) — real crypto, zero infra, for local dev
- [**Examples**](examples.md) — end-to-end sample apps

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
