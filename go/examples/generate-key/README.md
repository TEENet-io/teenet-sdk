# Key Generation Example

This example demonstrates how to generate cryptographic keys using the TEENet SDK.

## Overview

The SDK provides two key generation functions:
- `GenerateSchnorrKey(name, curve)` - For Schnorr signature keys
- `GenerateECDSAKey(name, curve)` - For ECDSA signature keys

## Supported Combinations

### Schnorr Protocol
- `ed25519` - Edwards curve (recommended for EdDSA-style Schnorr)
- `secp256k1` - Bitcoin/Ethereum curve
- `secp256r1` - NIST P-256 curve

### ECDSA Protocol
- `secp256k1` - Bitcoin/Ethereum curve (recommended for blockchain)
- `secp256r1` - NIST P-256 curve (recommended for general use)

## Prerequisites

1. TEENet consensus service running (default: `http://localhost:8080`)
2. Valid `APP_INSTANCE_ID` environment variable set

## Usage

```bash
# Set your app instance ID
export APP_INSTANCE_ID="your-app-instance-id"

# Optional: set consensus URL
export CONSENSUS_URL="http://localhost:8080"

# Run the example
go run main.go
```

## Example Output

```
=== TEENet Key Generation Example ===
Consensus URL: http://localhost:8080
App Instance ID: abc123

📝 Generating Schnorr key (secp256k1)...
✅ Schnorr key generated successfully!
  Key ID: 1
  Name: my-schnorr-key
  Protocol: schnorr
  Curve: secp256k1
  Public Key: 0x1234567890abcdef...
  Application ID: 42
  Created by Instance: abc123
  DKG Threshold: 2 of 5 participants

📝 Generating ECDSA key (secp256k1)...
✅ ECDSA key generated successfully!
  Key ID: 2
  Name: my-ecdsa-key
  Protocol: ecdsa
  Curve: secp256k1
  Public Key: 0xfedcba0987654321...
  Application ID: 42
  Created by Instance: abc123

🎉 All keys generated successfully!
```

## Key Features

- **Automatic validation**: The SDK validates curve-protocol combinations
- **TEE security**: Keys are generated via Trusted Execution Environment
- **Persistent storage**: Keys are stored in user management system
- **Multi-curve support**: Choose the best curve for your use case
- **DKG support**: Distributed Key Generation for threshold signatures

## Integration

After generating keys, you can use them for signing:

```go
// Generate a key using constants (recommended)
keyResult, err := client.GenerateSchnorrKey("my-key", sdk.CurveSECP256K1)
if err != nil {
    log.Fatal(err)
}

// Sign with generated key name
signResult, err := client.Sign([]byte("message to sign"), keyResult.PublicKey.Name)
if err != nil {
    log.Fatal(err)
}
fmt.Printf("Signature: %x\n", signResult.Signature)
```

## Available Constants

The SDK provides constants for protocols and curves:

```go
// Protocol constants
sdk.ProtocolECDSA    // "ecdsa"
sdk.ProtocolSchnorr  // "schnorr"

// Curve constants
sdk.CurveED25519     // "ed25519"
sdk.CurveSECP256K1   // "secp256k1"
sdk.CurveSECP256R1   // "secp256r1"
```

Using constants is recommended to avoid typos and get compile-time safety.

## Error Handling

The SDK provides detailed error messages for common issues:
- Invalid curve-protocol combinations
- Missing APP_INSTANCE_ID
- Network connectivity problems
- Invalid key names (must be ≤50 characters)

## Related Examples

- [Basic Signing Example](../basic/)
- [Voting Demo](../voting-demo/)
