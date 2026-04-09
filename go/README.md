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
    "context"
    "fmt"
    "log"

    sdk "github.com/TEENet-io/teenet-sdk/go"
)

func main() {
    ctx := context.Background()

    // Create client
    client := sdk.NewClient("http://localhost:8089")
    client.SetDefaultAppInstanceID("your-app-instance-id")
    defer client.Close()

    // Sign a message
    message := []byte("Hello, TEENet!")
    result, err := client.Sign(ctx, message, "my-key")
    if err != nil {
        log.Fatal(err)
    }
    if !result.Success {
        log.Fatalf("Signing failed: %s", result.Error)
    }
    fmt.Printf("Signature: %x\n", result.Signature)

    // Verify the signature
    valid, err := client.Verify(ctx, message, result.Signature, "my-key")
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
// Default settings (30s request timeout)
client := sdk.NewClient("http://localhost:8089")

// Custom options
opts := &sdk.ClientOptions{
    RequestTimeout:     45 * time.Second,
    PendingWaitTimeout: 10 * time.Second, // Max wait in Sign() for voting completion
    Debug:              true, // Enable verbose sign/polling trace logs
}
client := sdk.NewClientWithOptions("http://localhost:8089", opts)
```

Polling interval/backoff is managed internally by SDK.

### Configuration

```go
// Set APP_INSTANCE_ID manually
client.SetDefaultAppInstanceID("your-app-instance-id")

// Load from environment variable (APP_INSTANCE_ID)
err := client.SetDefaultAppInstanceIDFromEnv()

// Initialize from environment (logs warning if not set)
client.Init()
```

### Signing

**Hashing responsibility:** For ECDSA (secp256k1/secp256r1), the caller must hash the message before calling `Sign()` and `Verify()`. The TEE-DAO backend requires exactly 32 bytes of pre-hashed input. For Schnorr and EdDSA, pass the raw message.

```go
// ECDSA secp256k1 — user hashes with Keccak-256 (Ethereum-style)
hashedMsg := crypto.Keccak256(rawMessage)
result, err := client.Sign(ctx, hashedMsg, "my-ecdsa-key")
valid, err := client.Verify(ctx, hashedMsg, result.Signature, "my-ecdsa-key")

// Schnorr / EdDSA — pass raw message (hashing is handled internally)
result, err := client.Sign(ctx, rawMessage, "my-schnorr-key")
valid, err := client.Verify(ctx, rawMessage, result.Signature, "my-schnorr-key")
```

### Get Status

```go
status, err := client.GetStatus(ctx, "0x...")
if err != nil {
    log.Fatal(err)
}
if status.Found {
    fmt.Printf("Status: %s (%d/%d)\n", status.Status, status.CurrentVotes, status.RequiredVotes)
}
```

### Passkey Approval (New Flow)

Use these methods when your app uses passkey approval instead of threshold voting.

```go
getCredential := func(options interface{}) ([]byte, error) {
    // Browser/app side should run WebAuthn and return credential JSON bytes.
    // example: navigator.credentials.get(options)
    return []byte(`{}`), nil
}

// 0) Passkey login (SDK orchestrates options + verify)
loginRes, _ := client.PasskeyLoginWithCredential(ctx, getCredential)
if !loginRes.Success {
    log.Fatalf("login failed: %s", loginRes.Error)
}
approvalToken, _ := loginRes.Data["token"].(string)
if approvalToken == "" {
    log.Fatal("missing approval token in login response")
}

// 1) Initiator side: just call Sign (approval request is auto-initialized by backend policy)
signRes, err := client.Sign(ctx, []byte(`{"to":"0x1234","amount":"1"}`), "my-key")
if err != nil {
    log.Fatalf("sign failed: %v", err)
}
if signRes.ErrorCode != "APPROVAL_PENDING" {
    log.Fatalf("expected approval pending, got: %+v", signRes)
}
requestID := signRes.VotingInfo.RequestID

// Optional: approver can query pending tasks for current passkey identity
pending, _ := client.ApprovalPending(ctx, approvalToken, nil)
_ = pending

// 2) Approver confirms request (SDK orchestrates challenge + confirm)
confirmRes, _ := client.ApprovalRequestConfirmWithCredential(ctx, requestID, getCredential, approvalToken)
taskID := uint64(confirmRes.Data["task_id"].(float64))

// 3) Approver takes task action (SDK orchestrates challenge + action)
_, _ = client.ApprovalActionWithCredential(ctx, taskID, "APPROVE", getCredential, approvalToken)
```

Notes:
- SDK can orchestrate request/response sequence.
- WebAuthn execution (`navigator.credentials.create/get`) still runs in app/browser code.
- SDK does not own UI interaction.

### Verification

```go
// Verify with specific bound key name
valid, err := client.Verify(ctx, message, signature, "my-key")
```

### Get Public Key

```go
keys, err := client.GetPublicKeys(ctx)
// publicKey: hex-encoded public key
// protocol: "ecdsa" or "schnorr"
// curve: "ed25519", "secp256k1", or "secp256r1"
```

### Key Generation

```go
// Generate ECDSA key
result, err := client.GenerateECDSAKey(ctx, "secp256k1")  // or "secp256r1"

// Generate Schnorr key
result, err := client.GenerateSchnorrKey(ctx, "ed25519")  // or "secp256k1", "secp256r1"

// Use generated key
if result.Success {
    fmt.Printf("Key ID: %d\n", result.PublicKey.ID)
    fmt.Printf("Public Key: %s\n", result.PublicKey.KeyData)

    // Sign with generated key
    signResult, _ := client.Sign(ctx, message, result.PublicKey.Name)
}
```

### API Key Management

```go
// Get API key
result, err := client.GetAPIKey(ctx, "my-api-key")
if result.Success {
    fmt.Printf("API Key: %s\n", result.APIKey)
}

// Sign with API secret (HMAC-SHA256)
result, err := client.SignWithAPISecret(ctx, "my-secret", []byte("message"))
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
    ErrorCode string
}
```

### Error Codes

`SignResult.ErrorCode` values:

| Code | Meaning |
|------|---------|
| `SIGN_REQUEST_FAILED` | Submit request/network failure |
| `SIGN_REQUEST_REJECTED` | Consensus rejected request |
| `SIGNATURE_DECODE_FAILED` | Signature decode failed |
| `UNEXPECTED_STATUS` | Unexpected status value |
| `MISSING_HASH` | Pending response missing hash |
| `STATUS_QUERY_FAILED` | Polling status request failed |
| `SIGN_FAILED` | Voting finalized as failed |
| `THRESHOLD_TIMEOUT` | Threshold not met before timeout |

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

Copyright (c) 2025-2026 TEENet Technology (Hong Kong) Limited.
