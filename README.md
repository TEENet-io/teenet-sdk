# TEENet SDK

A simplified Go SDK for TEE-DAO key management operations using the consensus service.

## Features

- **Transparent Voting**: Automatically handles M-of-N threshold voting without manual coordination
- **Simple API**: Clean interface similar to teenet-sdk with Sign(), Verify(), and GetPublicKey()
- **Callback Support**: Asynchronous notifications for voting completion via HTTP callbacks
- **Signature Verification**: Offline verification supporting multiple protocols (ECDSA, Schnorr) and curves (ED25519, SECP256K1, SECP256R1)
- **HTTP-based**: No TLS/gRPC complexity, simple REST API communication

## Installation

```bash
go get github.com/TEENet-io/teenet-sdk
```

## Quick Start

### 1. Initialize Client

```go
import sdk "github.com/TEENet-io/teenet-sdk"

// Create client pointing to consensus service
client := sdk.NewClient("http://localhost:8089")

// Set your App ID (required for signing)
client.SetDefaultAppID("your-app-id")
// Or load from environment variable
client.SetDefaultAppIDFromEnv() // Reads from APP_ID environment variable
```

### 2. Sign a Message

```go
message := []byte("Hello, TEENet!")

// Sign the message (handles both direct signing and voting automatically)
result, err := client.Sign(message)
if err != nil {
    log.Fatalf("Signing failed: %v", err)
}

if result.Success {
    fmt.Printf("Signature: %x\n", result.Signature)

    // Check if voting was involved
    if result.VotingInfo != nil && result.VotingInfo.NeedsVoting {
        fmt.Printf("Voting completed: %d/%d votes\n",
            result.VotingInfo.CurrentVotes,
            result.VotingInfo.RequiredVotes)
    }
} else {
    fmt.Printf("Signing failed: %s\n", result.Error)
}
```

### 3. Verify a Signature

```go
message := []byte("Hello, TEENet!")
signature := result.Signature

// Verify signature (automatically fetches public key)
valid, err := client.Verify(message, signature)
if err != nil {
    log.Fatalf("Verification failed: %v", err)
}

fmt.Printf("Signature valid: %v\n", valid)
```

### 4. Get Public Key

```go
publicKey, protocol, curve, err := client.GetPublicKey()
if err != nil {
    log.Fatalf("Failed to get public key: %v", err)
}

fmt.Printf("Public Key: %s\n", publicKey)
fmt.Printf("Protocol: %s, Curve: %s\n", protocol, curve)
```

## How It Works

### Direct Signing Mode

When voting is not configured for an App ID, signing happens immediately:

```
SDK → app-comm-consensus → TEE-DAO → Response with signature
```

The `Sign()` method returns immediately with the signature.

### Voting Mode (M-of-N Threshold)

When voting is configured (e.g., 2-of-3 threshold):

```
SDK 1 → Submit vote → app-comm-consensus (cache: 1/2 votes)
SDK 2 → Submit vote → app-comm-consensus (cache: 2/2 votes) → Threshold met!
                    ↓
                TEE-DAO signs
                    ↓
        Callback notifications sent to all SDKs
```

Each SDK:
1. Starts fixed-port HTTP callback server on port 19080 (at Client initialization)
2. Submits signing request with app_id (consensus service queries container IP)
3. Waits for either:
   - Immediate response (direct signing)
   - Callback notification to `http://{container_ip}:19080/callback/{hash}` (voting mode)
   - Timeout (default 60 seconds)
4. Reuses the same callback server for all signing operations

## Network Requirements

TEENet SDK uses fixed port **19080** to receive callback notifications from the consensus service.

### Firewall Configuration

Ensure that port 19080 is accessible from the consensus service:

```bash
# Linux iptables
sudo iptables -A INPUT -p tcp --dport 19080 -j ACCEPT

# firewalld (RHEL/CentOS/Fedora)
sudo firewall-cmd --permanent --add-port=19080/tcp
sudo firewall-cmd --reload

# UFW (Ubuntu/Debian)
sudo ufw allow 19080/tcp
```

### Docker Deployment

When running in Docker, expose port 19080:

```yaml
# docker-compose.yml
services:
  your-app:
    image: your-app:latest
    ports:
      - "19080:19080"  # Callback server port
```

```bash
# Docker CLI
docker run -p 19080:19080 your-app:latest
```

### Kubernetes Deployment

Ensure the Service exposes port 19080:

```yaml
apiVersion: v1
kind: Service
metadata:
  name: your-app
spec:
  selector:
    app: your-app
  ports:
    - name: callback
      port: 19080
      targetPort: 19080
      protocol: TCP
```

**Important Notes:**
- Only one SDK client instance can run per machine (port 19080 is exclusive)
- The consensus service must be able to reach your container/host on port 19080
- Port conflicts will prevent the callback server from starting (check logs for errors)

## Configuration

### Client Options

```go
opts := &sdk.ClientOptions{
    RequestTimeout:  30 * time.Second, // HTTP request timeout (default: 30s)
    CallbackTimeout: 60 * time.Second, // Callback waiting timeout (default: 60s)
}
client := sdk.NewClientWithOptions("http://localhost:8089", opts)
```

### Environment Variables

- `APP_ID`: Default App ID for signing operations

## API Reference

### Client Methods

#### `NewClient(consensusURL string) *Client`
Creates a new SDK client with default settings.

#### `NewClientWithOptions(consensusURL string, opts *ClientOptions) *Client`
Creates a new SDK client with custom configuration options.

#### `SetDefaultAppID(appID string)`
Sets the default App ID for signing operations.

#### `SetDefaultAppIDFromEnv() error`
Loads default App ID from `APP_ID` environment variable.

#### `Sign(message []byte, opt ...*SignOptions) (*SignResult, error)`
Signs a message. Automatically handles both direct signing and voting modes.

**Returns:**
- `SignResult`: Contains signature, success status, and voting information
- `error`: Error if signing fails

#### `Verify(message []byte, signature []byte) (bool, error)`
Verifies a signature against the message. Automatically fetches public key.

#### `GetPublicKey() (publicKey, protocol, curve string, err error)`
Retrieves public key information for the default App ID.

#### `Close() error`
Closes the client and releases resources.

### Types

#### `SignResult`
```go
type SignResult struct {
    Signature  []byte       `json:"signature,omitempty"` // Signature bytes
    Success    bool         `json:"success"`             // Whether signing succeeded
    Error      string       `json:"error,omitempty"`     // Error message if failed
    VotingInfo *VotingInfo  `json:"voting_info,omitempty"` // Voting details (if applicable)
}
```

#### `VotingInfo`
```go
type VotingInfo struct {
    NeedsVoting   bool   `json:"needs_voting"`    // Whether voting was performed
    CurrentVotes  int    `json:"current_votes"`   // Current number of votes
    RequiredVotes int    `json:"required_votes"`  // Required vote threshold
    Status        string `json:"status"`          // pending, signed, error
    Hash          string `json:"hash"`            // Message hash
}
```

## Examples

### Example 1: Simple Signing and Verification

```go
package main

import (
    "fmt"
    "log"

    sdk "github.com/TEENet-io/teenet-sdk"
)

func main() {
    // Initialize client
    client := sdk.NewClient("http://localhost:8089")
    client.SetDefaultAppID("my-app-id")
    defer client.Close()

    // Sign message
    message := []byte("Important transaction data")
    result, err := client.Sign(message)
    if err != nil {
        log.Fatalf("Sign error: %v", err)
    }

    if !result.Success {
        log.Fatalf("Signing failed: %s", result.Error)
    }

    fmt.Printf("✅ Signed successfully\n")
    fmt.Printf("Signature: %x\n", result.Signature)

    // Verify signature
    valid, err := client.Verify(message, result.Signature)
    if err != nil {
        log.Fatalf("Verify error: %v", err)
    }

    fmt.Printf("✅ Signature valid: %v\n", valid)
}
```

### Example 2: Voting Scenario

```go
package main

import (
    "fmt"
    "log"
    "sync"

    sdk "github.com/TEENet-io/teenet-sdk"
)

func main() {
    // Simulate 2-of-3 voting scenario
    // Three applications with different App IDs vote on same message

    message := []byte("Multi-party approval required")

    var wg sync.WaitGroup
    results := make([]*sdk.SignResult, 3)

    // App 1 submits vote
    wg.Add(1)
    go func() {
        defer wg.Done()
        client1 := sdk.NewClient("http://localhost:8089")
        client1.SetDefaultAppID("voter-app-1")
        defer client1.Close()

        result, err := client1.Sign(message)
        if err != nil {
            log.Printf("App 1 error: %v", err)
            return
        }
        results[0] = result
        fmt.Printf("App 1: Vote submitted, waiting...\n")
    }()

    // App 2 submits vote (threshold will be met after this)
    wg.Add(1)
    go func() {
        defer wg.Done()
        client2 := sdk.NewClient("http://localhost:8089")
        client2.SetDefaultAppID("voter-app-2")
        defer client2.Close()

        result, err := client2.Sign(message)
        if err != nil {
            log.Printf("App 2 error: %v", err)
            return
        }
        results[1] = result
        fmt.Printf("App 2: Vote submitted, threshold met!\n")
    }()

    // App 3 submits vote (after threshold already met)
    wg.Add(1)
    go func() {
        defer wg.Done()
        client3 := sdk.NewClient("http://localhost:8089")
        client3.SetDefaultAppID("voter-app-3")
        defer client3.Close()

        result, err := client3.Sign(message)
        if err != nil {
            log.Printf("App 3 error: %v", err)
            return
        }
        results[2] = result
        fmt.Printf("App 3: Received result\n")
    }()

    wg.Wait()

    // Check results
    for i, result := range results {
        if result != nil && result.Success {
            fmt.Printf("App %d: ✅ Signature received: %x\n", i+1, result.Signature[:16])
            if result.VotingInfo != nil {
                fmt.Printf("       Votes: %d/%d\n",
                    result.VotingInfo.CurrentVotes,
                    result.VotingInfo.RequiredVotes)
            }
        }
    }
}
```

## Architecture

### Components

```
┌─────────────────────┐
│   Your Application  │
│     (SDK Client)    │
└──────────┬──────────┘
           │ HTTP REST API
           ↓
┌─────────────────────┐
│ app-comm-consensus  │
│  - Voting Manager   │
│  - Cache System     │
│  - Callback Sender  │
└──────────┬──────────┘
           │ gRPC
           ↓
┌─────────────────────┐
│user-management-system│
│  (TEE-DAO Gateway)  │
└──────────┬──────────┘
           │ TEE SDK
           ↓
┌─────────────────────┐
│   TEE-DAO Network   │
│  (Signing Service)  │
└─────────────────────┘
```

### Callback Flow

```
1. SDK creates callback server on 127.0.0.1:random_port
2. SDK submits: POST /api/submit-request
   {
     "app_id": "voter-1",
     "hash": "0x1234...",
     "requestor_id": "voter-1",
     "callback_url": "http://127.0.0.1:54321/callback/0x1234..."
   }

3. app-comm-consensus caches the request and callback URL

4. When threshold met:
   - app-comm-consensus signs via TEE-DAO
   - Sends callback: POST http://127.0.0.1:54321/callback/0x1234...
     {
       "hash": "0x1234...",
       "status": "signed",
       "signature": "0xabcd..."
     }

5. SDK receives callback and returns result to application
```

## Error Handling

### Common Errors

- `"default App ID is not set"`: Call `SetDefaultAppID()` or `SetDefaultAppIDFromEnv()` before signing
- `"timeout waiting for callback"`: Voting threshold not met within timeout period
- `"Failed to decode signature"`: Invalid signature format from server
- `"Failed to get public key"`: App ID not found or not configured

### Error Response Structure

```go
result, err := client.Sign(message)
if err != nil {
    // Network or system error
    log.Printf("System error: %v", err)
}

if !result.Success {
    // Application-level error (e.g., signing failed)
    log.Printf("Application error: %s", result.Error)
}
```

## Project Structure

```
teenet-sdk/
├── client.go           # Public API facade
├── types.go            # Public type definitions and constants
├── internal/           # Internal implementation (not exposed)
│   ├── client/         # Client implementation
│   ├── crypto/         # Cryptographic operations
│   ├── network/        # HTTP and callback server
│   ├── types/          # Internal type definitions
│   └── util/           # Utility functions
└── examples/           # Example applications
    ├── basic/          # Basic usage examples
    ├── signature-tool/ # Web-based signature tool
    └── voting-demo/    # Multi-party voting demo
```

### Architecture

The SDK uses a clean facade pattern:
- **Public API** (`client.go`, `types.go`): Simple, stable interface for users
- **Internal packages** (`internal/*`): Modular implementation with separation of concerns
- **Examples**: Complete working applications demonstrating various use cases

## Examples

See the `examples/` directory for complete working applications:

- **basic/**: Simple command-line examples
  - `simple/`: Basic signing and verification
  - `voting/`: Multi-party voting scenario
  - `forwarding/`: Request forwarding example

- **signature-tool/**: Web-based signature tool with frontend UI
- **voting-demo/**: Interactive voting demonstration app

## Testing

Run tests:
```bash
go test ./...
```

## License

Copyright (c) 2025 TEENet Technology (Hong Kong) Limited. All Rights Reserved.
