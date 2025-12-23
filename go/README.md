# TEENet SDK for Go

Go SDK for TEENet cryptographic signing services via TEE consensus nodes.

## Installation

```bash
go get github.com/TEENet-io/teenet-sdk/go
```

## Quick Start

```go
package main

import (
    "fmt"
    "log"

    sdk "github.com/TEENet-io/teenet-sdk/go"
)

func main() {
    // Create client
    client := sdk.NewClient("http://localhost:8089")
    client.SetDefaultAppID("your-app-id")
    defer client.Close()

    // Sign a message
    message := []byte("Hello, TEENet!")
    result, err := client.Sign(message)
    if err != nil {
        log.Fatal(err)
    }
    if !result.Success {
        log.Fatalf("Signing failed: %s", result.Error)
    }
    fmt.Printf("Signature: %x\n", result.Signature)

    // Verify the signature
    valid, err := client.Verify(message, result.Signature)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("Valid: %v\n", valid)
}
```

## Features

- Multiple cryptographic curves: ED25519, SECP256K1, SECP256R1
- Multiple signing protocols: ECDSA, Schnorr, EdDSA
- Key generation via TEE consensus
- API Key management
- HMAC-SHA256 signing with API secrets
- Automatic M-of-N threshold voting support

## API Reference

### Client Creation

```go
// Default settings (30s request timeout, 60s callback timeout)
client := sdk.NewClient("http://localhost:8089")

// Custom options
opts := &sdk.ClientOptions{
    RequestTimeout:  45 * time.Second,
    CallbackTimeout: 120 * time.Second,
}
client := sdk.NewClientWithOptions("http://localhost:8089", opts)
```

### Configuration

```go
// Set App ID manually
client.SetDefaultAppID("your-app-id")

// Load from environment variable (APP_INSTANCE_ID)
err := client.SetDefaultAppIDFromEnv()

// Initialize from environment (logs warning if not set)
client.Init()
```

### Signing

```go
// Sign with default key
result, err := client.Sign([]byte("message"))

// Sign with specific public key
pubKeyBytes, _ := hex.DecodeString(publicKeyHex)
result, err := client.Sign([]byte("message"), pubKeyBytes)

// Check result
if result.Success {
    fmt.Printf("Signature: %x\n", result.Signature)
} else {
    fmt.Printf("Error: %s\n", result.Error)
}
```

### Verification

```go
// Verify with default App ID's public key
valid, err := client.Verify(message, signature)

// Verify with specific public key
valid, err := client.VerifyWithPublicKey(
    message,
    signature,
    publicKeyBytes,
    sdk.ProtocolECDSA,    // or sdk.ProtocolSchnorr
    sdk.CurveSECP256K1,   // or sdk.CurveED25519, sdk.CurveSECP256R1
)
```

### Get Public Key

```go
publicKey, protocol, curve, err := client.GetPublicKey()
// publicKey: hex-encoded public key
// protocol: "ecdsa" or "schnorr"
// curve: "ed25519", "secp256k1", or "secp256r1"
```

### Key Generation

```go
// Generate ECDSA key
result, err := client.GenerateECDSAKey("secp256k1")  // or "secp256r1"

// Generate Schnorr key
result, err := client.GenerateSchnorrKey("ed25519")  // or "secp256k1", "secp256r1"

// Use generated key
if result.Success {
    fmt.Printf("Key ID: %d\n", result.PublicKey.ID)
    fmt.Printf("Public Key: %s\n", result.PublicKey.KeyData)

    // Sign with generated key
    pubKeyBytes, _ := hex.DecodeString(result.PublicKey.KeyData)
    signResult, _ := client.Sign(message, pubKeyBytes)
}
```

### API Key Management

```go
// Get API key
result, err := client.GetAPIKey("my-api-key")
if result.Success {
    fmt.Printf("API Key: %s\n", result.APIKey)
}

// Sign with API secret (HMAC-SHA256)
result, err := client.SignWithAPISecret("my-secret", []byte("message"))
if result.Success {
    fmt.Printf("Signature: %s\n", result.Signature)
    fmt.Printf("Algorithm: %s\n", result.Algorithm)
}
```

## Supported Algorithms

| Protocol | Curve | Description |
|----------|-------|-------------|
| Schnorr | ED25519 | Edwards curve EdDSA |
| ECDSA | SECP256K1 | Bitcoin/Ethereum curve |
| Schnorr | SECP256K1 | BIP-340 Schnorr |
| ECDSA | SECP256R1 | NIST P-256 curve |

## Constants

```go
// Protocols
sdk.ProtocolECDSA   = "ecdsa"
sdk.ProtocolSchnorr = "schnorr"

// Curves
sdk.CurveED25519   = "ed25519"
sdk.CurveSECP256K1 = "secp256k1"
sdk.CurveSECP256R1 = "secp256r1"
```

## Types

### SignResult

```go
type SignResult struct {
    Success   bool
    Signature []byte
    Error     string
}
```

### GenerateKeyResult

```go
type GenerateKeyResult struct {
    Success   bool
    Message   string
    PublicKey *PublicKeyInfo
}

type PublicKeyInfo struct {
    ID                  uint32
    Name                string
    KeyData             string  // Hex-encoded public key
    Curve               string
    Protocol            string
    Threshold           uint32
    ParticipantCount    uint32
    MaxParticipantCount uint32
    ApplicationID       uint32
    CreatedByInstanceID string
}
```

### APIKeyResult

```go
type APIKeyResult struct {
    Success bool
    APIKey  string
    Error   string
}
```

### APISignResult

```go
type APISignResult struct {
    Success   bool
    Signature string  // Hex-encoded signature
    Algorithm string  // e.g., "HMAC-SHA256"
    Error     string
}
```

## Testing

Run with mock server:

```bash
# Start mock server
cd ../mock-server
./start.sh

# Run tests
go test ./...
```

## License

Copyright (c) 2025 TEENet Technology (Hong Kong) Limited. All Rights Reserved.
