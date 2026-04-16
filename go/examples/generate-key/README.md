# Key Generation Example

This example demonstrates how to generate cryptographic keys using the TEENet SDK.

## Overview

The SDK provides a single unified key generation function:

```go
result, err := client.GenerateKey(ctx, protocol, curve)
```

Pick the protocol/curve combination that matches your target chain:

| Target | protocol | curve |
|---|---|---|
| Bitcoin Taproot (P2TR / BIP-340) | `sdk.ProtocolSchnorrBIP340` | `sdk.CurveSECP256K1` |
| Bitcoin Legacy / Ethereum | `sdk.ProtocolECDSA` | `sdk.CurveSECP256K1` |
| Solana / Ed25519 ecosystem | `sdk.ProtocolEdDSA` | `sdk.CurveED25519` |
| WebAuthn / NIST P-256 | `sdk.ProtocolECDSA` | `sdk.CurveSECP256R1` |
| Generic Schnorr | `sdk.ProtocolSchnorr` | any supported curve |

## Prerequisites

1. TEENet service running (default: `http://localhost:8089`)
2. Valid `APP_INSTANCE_ID` environment variable set

## Usage

```bash
# Set your app instance ID
export APP_INSTANCE_ID="your-app-instance-id"

# Optional: set service URL
export SERVICE_URL="http://localhost:8089"

# Run the example
go run main.go
```

## Example Output

```
=== TEENet Key Generation and Signing Example ===
Service URL: http://localhost:8089
App Instance ID: abc123

Generating EdDSA key (ed25519)...
EdDSA key generated successfully!
  Key ID: 1
  Protocol: schnorr
  Curve: ed25519

Generating ECDSA key (secp256k1)...
ECDSA key generated successfully!
  Key ID: 2
  Protocol: ecdsa
  Curve: secp256k1

All keys generated successfully!
```

## Key Features

- **Automatic validation**: The SDK validates protocol-curve combinations before the network call
- **TEE security**: Keys are generated via Trusted Execution Environment
- **Persistent storage**: Keys are stored in user management system
- **Multi-curve support**: Choose the best curve for your use case
- **DKG support**: Distributed Key Generation for threshold signatures

## Integration

After generating keys, you can use them for signing:

```go
ctx := context.Background()

// Generate a key
keyResult, err := client.GenerateKey(ctx, sdk.ProtocolSchnorrBIP340, sdk.CurveSECP256K1)
if err != nil {
    log.Fatal(err)
}

// Sign with generated key name
signResult, err := client.Sign(ctx, []byte("message to sign"), keyResult.PublicKey.Name)
if err != nil {
    log.Fatal(err)
}
fmt.Printf("Signature: %x\n", signResult.Signature)
```

## Available Constants

The SDK provides constants for protocols and curves:

```go
// Protocol constants
sdk.ProtocolECDSA         // "ecdsa"
sdk.ProtocolSchnorr       // "schnorr"        — generic Schnorr (escape hatch)
sdk.ProtocolEdDSA         // "eddsa"          — alias; only valid with CurveED25519
sdk.ProtocolSchnorrBIP340 // "schnorr-bip340" — alias; only valid with CurveSECP256K1

// Curve constants
sdk.CurveED25519     // "ed25519"
sdk.CurveSECP256K1   // "secp256k1"
sdk.CurveSECP256R1   // "secp256r1"
```

Using constants is recommended to avoid typos and get compile-time safety.

## Error Handling

The SDK provides detailed error messages for common issues:
- Invalid protocol-curve combinations (e.g. EdDSA + secp256k1)
- Missing APP_INSTANCE_ID
- Network connectivity problems

## Related Examples

- [Basic Signing Example](../basic/)
- [Voting Demo](../voting-demo/)
