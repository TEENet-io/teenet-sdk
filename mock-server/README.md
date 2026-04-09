# TEENet SDK Mock Consensus Server

A mock consensus service for testing the TEENet SDK.

## Features

- Simulates the `app-comm-consensus` HTTP API
- Supports all signing algorithms:
  - ED25519 (Schnorr/EdDSA)
  - SECP256K1 (ECDSA and Schnorr)
  - SECP256R1 (ECDSA)
- Supports key generation API
- Supports API Key and Secret operations
- Uses real cryptographic signing (not mock data)

## Quick Start

```bash
# Build
make build

# Run (default port 8089)
make run

# Or run directly
go run .

# Custom port
MOCK_SERVER_PORT=9000 ./mock-server
```

## API Endpoints

### Health Check
```bash
GET /api/health
```

### Get Public Keys
```bash
GET /api/publickey/:app_instance_id
```

### Sign Request
```bash
POST /api/submit-request
Content-Type: application/json

{
  "app_instance_id": "test-ecdsa-secp256k1",
  "message": "base64-encoded message"
}
```

### Generate Key
```bash
POST /api/generate-key
Content-Type: application/json

{
  "app_instance_id": "your-app-instance-id",
  "curve": "secp256k1",
  "protocol": "ecdsa"
}
```

### Get API Key
```bash
GET /api/apikey/:name?app_instance_id=your-app-instance-id
```

### Sign with API Secret
```bash
POST /api/apikey/:name/sign
Content-Type: application/json

{
  "app_instance_id": "your-app-instance-id",
  "message": "message content"
}
```

## Pre-configured Test App Instance IDs

| App Instance ID | Protocol | Curve |
|--------|----------|-------|
| test-schnorr-ed25519 | schnorr | ed25519 |
| test-schnorr-secp256k1 | schnorr | secp256k1 |
| test-ecdsa-secp256k1 | ecdsa | secp256k1 |
| test-ecdsa-secp256r1 | ecdsa | secp256r1 |
| ethereum-wallet-app | ecdsa | secp256k1 |
| secure-messaging-app | schnorr | ed25519 |

## Testing with the SDK

```go
package main

import (
    "context"
    "fmt"

    sdk "github.com/TEENet-io/teenet-sdk/go"
)

func main() {
    ctx := context.Background()

    // Connect to mock server
    client := sdk.NewClient("http://localhost:8089")
    client.SetDefaultAppInstanceID("test-ecdsa-secp256k1")
    defer client.Close()

    // Sign
    result, err := client.Sign(ctx, []byte("hello world"), "my-key")
    if err != nil {
        panic(err)
    }
    fmt.Printf("Signature: %x\n", result.Signature)

    // Verify
    valid, err := client.Verify(ctx, []byte("hello world"), result.Signature, "my-key")
    fmt.Printf("Valid: %v\n", valid)
}
```

## Notes

- This service is for development and testing only; do not use in production
- Uses deterministic private keys; signatures can be verified but are not secure
- Does not support voting mode; all requests are signed directly
