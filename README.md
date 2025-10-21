# TEENet SDK

A comprehensive TEENet sdk library with multi-language support, distributed voting signature mechanism, and signature verification, including a complete local testing environment.

> **🎉 New in v3.0**: Simplified API with default App ID support! No need to pass App ID in every method call. See [Latest Updates](#-latest-updates-v30) for details.
>
> **⚠️ Breaking Change in v3.0**: API simplified - `Sign()`, `Verify()`, and `GetPublicKey()` now use default App ID set during initialization.

## 🚀 Core Components

### 1. Client Libraries
- **Go** - Production-ready implementation with distributed voting signatures and signature verification
- **TypeScript** - Node.js compatible implementation with full feature parity

### 2. Example Applications
- **TEENet Signature Tool** - Unified web application supporting digital signatures, verification, and distributed voting
- **Distributed Voting Signatures** - M-of-N threshold voting mechanism
- **Signature Verification** - Verify signatures across all supported protocols and curves
- **Multi-Protocol Support** - ECDSA and Schnorr protocols
- **Multi-Curve Support** - ED25519, SECP256K1, SECP256R1 curves
- **Docker Ready** - Containerized deployment

### 3. Mock Server Environment
- **Mock DAO Server** - Simulates distributed key management with real cryptographic operations
- **Mock Config Server** - Provides node discovery and configuration
- **Mock App Node** - Simulates user management system

## ✨ Key Features

### Distributed Voting Signatures
- **Server-Configured Voting**: Target nodes and required votes automatically fetched from server
- **M-of-N Threshold Voting**: Server-configured voting requirements based on project settings
- **Concurrent Processing**: Simultaneous voting requests to all target nodes
- **Complete Collection**: Waits for all voting responses with detailed status
- **Automatic Signing**: Generates cryptographic signatures upon voting approval
- **Loop Prevention**: Uses `is_forwarded` flag to prevent infinite loops

### Key Management
- **Secure Message Signing**: Sign messages using distributed cryptographic keys
- **Signature Verification**: Verify signatures with automatic protocol and curve detection
- **AppID Service Integration**: Get public keys and sign messages using AppID
- **Multi-Protocol Support**: ECDSA and Schnorr signature protocols
- **Multi-Curve Support**: ED25519, SECP256K1, SECP256R1 curves
- **TLS Security**: Secure communication using mutual TLS authentication

### Mock Server Features
- **Semantic App IDs**: 
  - `secure-messaging-app` (Schnorr + ED25519)
  - `financial-trading-platform` (ECDSA + SECP256R1)
  - `digital-identity-service` (Schnorr + SECP256K1)
  - `bitcoin-wallet-app` (ECDSA + SECP256K1)
- **Deterministic Testing**: Reproducible key generation for testing
- **Complete Environment**: Config server, DAO server, app node

## 🏁 Quick Start

### Start Mock Server Environment

```bash
cd mock-server
./start-test-env.sh
```

This starts:
- Config Server on localhost:50052
- DAO Server on localhost:50051  
- App Node on localhost:50053

### Run Client Examples

**Go Example:**
```bash
cd go
go run example/main.go
```

**TypeScript Example:**
```bash
cd typescript
npm install
npm run example
```

### TEENet Signature Tool

**Start Signature Tool:**
```bash
cd go/example/signature-tool
APP_ID=secure-messaging-app TEE_CONFIG_ADDR=localhost:50052 go run .
```

Web interface available at: `http://localhost:8080`

**Docker Deployment:**
```bash
cd go/example/signature-tool
docker build -t teenet-signature-tool .
docker run -p 8080:8080 \
  -e APP_ID=secure-messaging-app \
  -e TEE_CONFIG_ADDR=host.docker.internal:50052 \
  teenet-signature-tool
```

### Stop Mock Server

```bash
cd mock-server
./stop-test-env.sh
```

## API Reference

### Core Methods

#### Sign (Simplified v3.0 API)
```go
// Go - Simple signing (voting disabled)
result, err := client.Sign(message []byte) (*SignResult, error)

// Go - Voting signature (voting enabled automatically by AppID configuration)
result, err := client.Sign(message []byte, &SignOptions{
    LocalApproval: true,
    HTTPRequest:   httpReq,
}) (*SignResult, error)

// TypeScript
result = await client.sign(message: Uint8Array, options?: SignOptions): Promise<SignResult>
```

#### GetPublicKey (v3.0 - Uses Default AppID)
```go
// Go - Uses default AppID set during initialization
publicKey, protocol, curve, err := client.GetPublicKey()

// TypeScript
const { publicKey, protocol, curve } = await client.getPublicKey()
```

#### Verify (v3.0 - Uses Default AppID)
```go
// Go - Uses default AppID set during initialization
valid, err := client.Verify(message []byte, signature []byte) (bool, error)

// TypeScript
valid = await client.verify(message: Buffer, signature: Buffer): Promise<boolean>
```

### Core Types

#### SignOptions (v3.0 - Simplified)
```go
// Go
type SignOptions struct {
    LocalApproval bool          // Local voting decision (for voting)
    HTTPRequest   *http.Request // HTTP request context (for voting)
}

// TypeScript
interface SignOptions {
    localApproval?: boolean;   // Local voting decision
    httpRequest?: any;         // HTTP request object
}
```

#### SignResult
```go
// Go
type SignResult struct {
    Success    bool        // Operation success
    Signature  []byte      // Generated signature
    Error      string      // Error message if failed
    VotingInfo *VotingInfo // Voting details (when voting enabled)
}

// TypeScript
interface SignResult {
    success: boolean;          // Operation success
    signature?: Uint8Array;    // Generated signature
    error?: string;            // Error message
    votingInfo?: VotingInfo;   // Voting details
}
```

#### VotingInfo
```go
// Go
type VotingInfo struct {
    TotalTargets    int          // Total voting nodes
    SuccessfulVotes int          // Number of approvals
    RequiredVotes   int          // Threshold for approval
    VoteDetails     []VoteDetail // Individual vote information
}

// TypeScript
interface VotingInfo {
    totalTargets: number;      // Total voting nodes
    successfulVotes: number;    // Number of approvals
    requiredVotes: number;      // Threshold for approval
    voteDetails: VoteDetail[];  // Individual vote information
}
```

### Protocol and Curve Constants

**Protocols:**
- `ProtocolECDSA` (1)
- `ProtocolSchnorr` (2)

**Curves:**
- `CurveED25519` (1)
- `CurveSECP256K1` (2)
- `CurveSECP256R1` (3)

## 🗳️ Distributed Voting Signature Workflow

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Frontend UI   │    │   Application   │    │ TEE DAO Client  │    │ TEE DAO Network │
│                 │    │                 │    │                 │    │                 │
└─────────┬───────┘    └─────────┬───────┘    └─────────┬───────┘    └─────────┬───────┘
          │                      │                      │                      │
          │ 1. POST /api/vote    │                      │                      │
          ├─────────────────────►│                      │                      │
          │ {                    │                      │                      │
          │   message,           │                      │                      │
          │   signer_app_id      │                      │                      │
          │ }                    │                      │                      │
          │                      │                      │                      │
          │ (target_app_ids and │                      │                      │
          │ required_votes are  │                      │                      │
          │ fetched from server)│                      │                      │
          │                      │                      │                      │
          │                      │ 2. VotingSign()      │                      │
          │                      ├─────────────────────►│                      │
          │                      │                      │                      │
          │                      │                      │ 3. Concurrent voting requests   │
          │                      │                      │ ┌─────────────────┐             │
          │                      │                      │ │                 │             │
          │                      │                      ├─┤ Target App ID 1 │             │
          │                      │                      │ │ (Local decision)│             │
          │                      │                      │ └─────────────────┘             │
          │                      │                      │ ┌─────────────────┐             │
          │                      │                      │ │                 │             │
          │                      │                      ├─┤ Target App ID 2 │             │
          │                      │                      │ │ (Local decision)│             │
          │                      │                      │ └─────────────────┘             │
          │                      │                      │ ┌─────────────────┐             │
          │                      │                      │ │                 │             │
          │                      │                      ├─┤ Target App ID N │             │
          │                      │                      │ │ (Local decision)│             │
          │                      │                      │ └─────────────────┘             │
          │                      │                      │                                  │
          │                      │                      │ 4. Collect all voting results   │
          │                      │                      │ (Wait for all responses)        │
          │                      │                      │                                  │
          │                      │                      │ 5. Internal processing:         │
          │                      │                      │ - Count approvals               │
          │                      │                      │ - Check threshold               │
          │                      │                      │                                  │
          │                      │                      │ 6. Generate signature           │
          │                      │                      │ (if voting passes)              │
          │                      │                      ├─────────────────────────────────►│
          │                      │                      │                                  │
          │                      │                      │ 7. Return signature             │
          │                      │                      │◄─────────────────────────────────┤
          │                      │                      │                                  │
          │                      │ 8. Return results    │                                  │
          │                      │◄─────────────────────┤                                  │
          │                      │                      │                                  │
          │ 9. Complete response │                      │                                  │
          │ {                    │                      │                                  │
          │   success: true,     │                      │                                  │
          │   approved: true,    │                      │                                  │
          │   voting_results: {  │                      │                                  │
          │     vote_details,    │                      │                                  │
          │     final_result     │                      │                                  │
          │   },                 │                      │                                  │
          │   signature          │                      │                                  │
          │ }                    │                      │                                  │
          │◄─────────────────────┤                      │                                  │
          │                      │                      │                                  │
```

### Key Features
- **Server-Driven Configuration**: Target nodes and voting threshold from server settings
- **M-of-N Threshold**: Server-configured voting requirements
- **Concurrent Processing**: Parallel voting requests to all target nodes
- **Complete Collection**: Waits for all responses before making decisions
- **Detailed Tracking**: Records each node's voting status and errors
- **Automatic Signing**: Generates cryptographic signature upon voting approval
- **Real-time UI**: Dynamic display of voting progress and results

### Voting Decision Logic
Current voting decision implementation:
- **Auto-Approval**: Messages containing "test" (case-insensitive) are automatically approved
- **Auto-Rejection**: Messages without "test" are automatically rejected
- **Customizable**: Can be modified in the application code to implement custom approval logic
- **Consistent**: Same logic applied across all voting nodes for predictable testing

## Go Implementation

### Installation

```bash
go get github.com/TEENet-io/teenet-sdk/go
```

### Basic Usage (v3.0)

```go
package main

import (
    "encoding/base64"
    "encoding/hex"
    "encoding/json"
    "fmt"
    "log"
    "net/http"
    "strings"
    "time"

    client "github.com/TEENet-io/teenet-sdk/go"
)

func main() {
    // Create client with custom options
    opts := &client.ClientOptions{
        CacheTTL:           5 * time.Minute,
        MaxConcurrentVotes: 10,
        FrostTimeout:       10 * time.Second,
        ECDSATimeout:       20 * time.Second,
    }
    teeClient := client.NewClientWithOptions("localhost:50052", opts)
    defer teeClient.Close()

    // Set default App ID before initialization
    appID := "secure-messaging-app"
    teeClient.SetDefaultAppID(appID)

    // Or load from environment variable (APP_ID)
    // teeClient.SetDefaultAppIDFromEnv()

    if err := teeClient.Init(); err != nil {
        log.Fatalf("Initialization failed: %v", err)
    }

    fmt.Printf("Client connected, Node ID: %d\n", teeClient.GetNodeID())
    fmt.Printf("Default App ID: %s\n", appID)

    // Example 1: Simple signature (v3.0 - no AppID needed)
    message := []byte("Hello from AppID Service!")

    result, err := teeClient.Sign(message)
    if err != nil {
        log.Printf("Signing failed: %v", err)
    } else if result.Success {
        fmt.Printf("Signature: %x\n", result.Signature)
    }

    // Example 2: Get public key (v3.0 - uses default AppID)
    publicKey, protocol, curve, err := teeClient.GetPublicKey()
    if err != nil {
        log.Printf("Failed to get public key: %v", err)
    } else {
        fmt.Printf("Public key:\n")
        fmt.Printf("  - Protocol: %s\n", protocol)
        fmt.Printf("  - Curve: %s\n", curve)
        fmt.Printf("  - Public Key: %s\n", publicKey)
    }

    // Example 3: Verify signature (v3.0 - no AppID needed)
    if result.Success && result.Signature != nil {
        valid, err := teeClient.Verify(message, result.Signature)
        if err != nil {
            log.Printf("Verification failed: %v", err)
        } else {
            fmt.Printf("Signature valid: %v\n", valid)
        }
    }
}

// Example 4: Voting signature in HTTP handler (v3.0)
func handleVotingRequest(w http.ResponseWriter, r *http.Request) {
    var req struct {
        Message string `json:"message"`
    }
    json.NewDecoder(r.Body).Decode(&req)

    // Decode message
    messageBytes, _ := base64.StdEncoding.DecodeString(req.Message)

    // Make local voting decision
    localApproval := strings.Contains(string(messageBytes), "test")

    // Use Sign API with voting options (voting auto-enabled by AppID config)
    result, err := teeClient.Sign(messageBytes, &client.SignOptions{
        LocalApproval: localApproval,
        HTTPRequest:   r,  // Pass the incoming HTTP request
    })

    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    // Return results
    response := map[string]interface{}{
        "success": result.Success,
        "signature": hex.EncodeToString(result.Signature),
    }

    if result.VotingInfo != nil {
        response["voting_info"] = result.VotingInfo
    }

    json.NewEncoder(w).Encode(response)
}
```

## TypeScript Implementation

### Installation

```bash
npm install @teenet/teenet-sdk
```

### Basic Usage (v3.0)

```typescript
import { Client, SignOptions } from '@teenet/teenet-sdk';

async function main() {
  // Create client with custom options
  const client = new Client('localhost:50052', {
    cacheTTL: 5 * 60 * 1000,        // 5 minutes
    maxConcurrentVotes: 10,
    frostTimeout: 10 * 1000,        // 10 seconds
    ecdsaTimeout: 20 * 1000,        // 20 seconds
  });

  // Set default App ID before initialization
  const appID = 'secure-messaging-app';
  client.setDefaultAppID(appID);

  // Or load from environment variable (APP_ID)
  // client.setDefaultAppIDFromEnv();

  await client.init();

  console.log(`Client connected, Node ID: ${client.getNodeId()}`);
  console.log(`Default App ID: ${appID}`);

  // Example 1: Simple signature (v3.0 - no AppID needed)
  const message = new TextEncoder().encode('Hello from AppID Service!');

  const result = await client.sign(message);

  if (result.success) {
    console.log(`Signature: ${Buffer.from(result.signature).toString('hex')}`);
  }

  // Example 2: Get public key (v3.0 - uses default AppID)
  const { publicKey, protocol, curve } = await client.getPublicKey();
  console.log('Public key:');
  console.log(`  - Protocol: ${protocol}`);
  console.log(`  - Curve: ${curve}`);
  console.log(`  - Public Key: ${publicKey}`);

  // Example 3: Verify signature (v3.0 - no AppID needed)
  if (result.success && result.signature) {
    const valid = await client.verify(message, result.signature);
    console.log(`Signature valid: ${valid}`);
  }

  await client.close();
}

// Example 4: Voting signature in Express handler (v3.0)
app.post('/vote', async (req, res) => {
  // Extract message from incoming request
  const message = Buffer.from(req.body.message, 'base64');

  // Make local voting decision
  const messageStr = message.toString();
  const localApproval = messageStr.includes('test');

  // Use sign API with voting options (voting auto-enabled by AppID config)
  const result = await client.sign(message, {
    localApproval: localApproval,
    httpRequest: req,  // Pass the incoming Express request
  });

  // Return results
  res.json({
    success: result.success,
    signature: result.signature ?
      Buffer.from(result.signature).toString('hex') : null,
    votingInfo: result.votingInfo
  });
});

main().catch(console.error);
```

## Project Structure

```
├── go/                     # Go client implementation
│   ├── client.go          # Main client (with distributed voting and verification)
│   ├── pkg/               # Core packages
│   │   ├── config/        # Configuration client
│   │   ├── constants/     # Protocol and curve constants
│   │   ├── task/          # Task client for signing
│   │   ├── usermgmt/      # User management client
│   │   ├── utils/         # Utility functions
│   │   ├── verification/  # Signature verification
│   │   └── voting/        # Voting service
│   ├── example/           # Go examples
│   │   ├── main.go        # Basic client example with verification
│   │   └── signature-tool/ # Signature tool web application
│   │       ├── main.go    # Web application main program
│   │       ├── types.go   # Data structures (simplified)
│   │       ├── server.go  # Static file service (no-cache)
│   │       ├── voting.go  # Voting processing logic
│   │       ├── frontend/  # Frontend files
│   │       ├── README.md  # Detailed documentation
│   │       └── Dockerfile      # Docker build configuration
│   └── proto/             # Generated Go protobuf files
├── typescript/            # TypeScript client implementation
│   ├── src/               # TypeScript source code
│   │   ├── client.ts      # Main client with verification
│   │   ├── config-client.ts # Configuration client
│   │   ├── task-client.ts # Task client
│   │   ├── appid-client.ts # AppID client
│   │   ├── types.ts       # Types and constants
│   │   ├── verification/  # Signature verification
│   │   │   └── verify.ts  # Verification implementation
│   │   └── example.ts     # TypeScript example with verification
│   ├── proto/             # Protobuf definitions
│   └── dist/              # Compiled JavaScript
├── mock-server/           # Complete Mock server environment
│   ├── dao-server.go      # Mock DAO server
│   ├── mock-config-server.go # Mock config server
│   ├── mock-app-node.go   # Mock app node
│   ├── proto/             # Protocol buffer definitions
│   ├── certs/             # TLS certificates (auto-generated)
│   ├── logs/              # Server logs
│   ├── start-test-env.sh  # Start all services
│   ├── stop-test-env.sh   # Stop all services
│   └── README.md          # Detailed documentation
```

## Examples and Documentation

- **Go Client**: See [go/example/main.go](go/example/main.go)
- **TypeScript Client**: See [typescript/src/example.ts](typescript/src/example.ts)
- **TEENet Signature Tool**: See [go/example/signature-tool/](go/example/signature-tool/) for detailed documentation
- **Mock Server**: See [mock-server/README.md](mock-server/README.md) for detailed documentation

## 🆕 Latest Updates (v3.0)

### ⭐ Breaking Changes (v3.0)
1. **Default AppID Support**: Simplified API with default AppID set during initialization
   - **Before (v2.x)**:
     ```go
     result, err := client.Sign(&SignRequest{
         Message: message,
         AppID: appID,
         EnableVoting: false,
     })
     publicKey, _, _, err := client.GetPublicKeyByAppID(appID)
     valid, err := client.Verify(message, signature, appID)
     ```
   - **After (v3.0)**:
     ```go
     // Set default AppID once during initialization
     client.SetDefaultAppID(appID)
     client.Init()

     // Use simplified methods without AppID parameter
     result, err := client.Sign(message)
     publicKey, _, _, err := client.GetPublicKey()
     valid, err := client.Verify(message, signature)
     ```

2. **Simplified Sign Method**: Changed from struct parameter to message + optional options
   - **Before (v2.x)**:
     ```go
     result, err := client.Sign(&SignRequest{
         Message: message,
         AppID: appID,
         EnableVoting: true,
         LocalApproval: localApproval,
         HTTPRequest: req,
     })
     ```
   - **After (v3.0)**:
     ```go
     // Simple signing
     result, err := client.Sign(message)

     // Voting signature
     result, err := client.Sign(message, &SignOptions{
         LocalApproval: localApproval,
         HTTPRequest: req,
     })
     ```

3. **Auto-detect Voting**: Removed `EnableVoting` field - voting is automatically determined by AppID configuration
   - Voting is enabled/disabled based on server configuration for the AppID
   - No need to manually specify voting flag

4. **Simplified SignOptions**: Removed redundant fields
   - Removed `VoteRequestData` and `Headers` (extracted automatically from HTTPRequest)
   - Only `LocalApproval` and `HTTPRequest` are needed for voting

### Migration Guide (v2.x → v3.0)

**Step 1**: Set default AppID during initialization
```go
// v2.x - AppID passed to each method
teeClient := client.NewClient("localhost:50052")
teeClient.Init()

// v3.0 - Set default AppID once
teeClient := client.NewClient("localhost:50052")
teeClient.SetDefaultAppID("secure-messaging-app")
// Or use environment variable: teeClient.SetDefaultAppIDFromEnv()
teeClient.Init()
```

**Step 2**: Update Sign calls
```go
// v2.x - Struct with all parameters
result, err := teeClient.Sign(&client.SignRequest{
    Message: message,
    AppID: appID,
    EnableVoting: false,
})

// v3.0 - Just message
result, err := teeClient.Sign(message)
```

**Step 3**: Update voting Sign calls
```go
// v2.x - Full struct with EnableVoting
result, err := teeClient.Sign(&client.SignRequest{
    Message: messageBytes,
    AppID: appID,
    EnableVoting: true,
    LocalApproval: localApproval,
    HTTPRequest: r,
})

// v3.0 - Message + options (voting auto-detected)
result, err := teeClient.Sign(messageBytes, &client.SignOptions{
    LocalApproval: localApproval,
    HTTPRequest: r,
})
```

**Step 4**: Update GetPublicKey calls
```go
// v2.x
publicKey, protocol, curve, err := teeClient.GetPublicKeyByAppID(appID)

// v3.0
publicKey, protocol, curve, err := teeClient.GetPublicKey()
```

**Step 5**: Update Verify calls
```go
// v2.x
valid, err := teeClient.Verify(message, signature, appID)

// v3.0
valid, err := teeClient.Verify(message, signature)
```

## 🆕 Previous Updates (v2.1)

### ⭐ New Features (v2.1)
1. **Signature Verification**: Added `Verify()` method to both Go and TypeScript SDKs
   - Automatic protocol and curve detection based on AppID
   - Support for all curves: ED25519, SECP256K1, SECP256R1
   - Support for all protocols: ECDSA, Schnorr, EdDSA
   - Multiple key formats supported (compressed, uncompressed, raw)
   - Production-ready implementation using established libraries (btcec for Go, elliptic for TypeScript)

2. **Updated Signature Tool**: Now uses SDK's built-in verification instead of custom implementation
   - Cleaner codebase with removed redundant verification code
   - Consistent verification across all SDK consumers

## 🆕 Previous Updates (v2.0)

### ⭐ Major API Changes
1. **Unified Sign API**: New `Sign()` method replaced separate `SignWithAppID` and `VotingSign` methods
   - Single method for both simple signing and voting signatures
   - Consistent API across different signing scenarios

2. **Automatic Server Configuration**: Target nodes and voting threshold fetched from server
   - No need to hardcode target App IDs in client code
   - Voting threshold automatically determined by server settings
   - More flexible and easier to maintain

### Distributed Voting System Improvements
1. **Server-Driven Configuration**: Target nodes and voting requirements from server settings
2. **HTTP Request Integration**: `VotingSign` accepts HTTP request objects for better header and body handling
3. **Unified API Signature**: Both Go and TypeScript versions have identical method signatures
4. **Smart Vote Filtering**: Only shows votes from target App IDs, excludes local vote when not in target list
5. **Correct Signer**: Uses `signer_app_id` as signature generator, not receiver
6. **Cache-Free Deployment**: Web application supports zero-cache deployment
7. **Improved Success Conditions**: Clear indication that messages containing "test" will succeed, others will fail

### Technical Features
- **Loop Prevention**: Uses `is_forwarded` flag to prevent infinite voting request loops
- **Concurrent Processing**: Uses goroutines to handle multiple voting requests concurrently
- **Complete Collection**: Waits for all voting responses, provides detailed voting status
- **Automatic Signing**: Automatically generates signatures using key management system upon voting approval
- **Modular Design**: Clean code structure for easy maintenance and extension

## Complete Testing Workflow

1. **Start Mock Environment:**
   ```bash
   cd mock-server
   ./start-test-env.sh
   ```

2. **Run Client Examples:**
   ```bash
   # Go client
   cd go && go run example/main.go
   
   # TypeScript client  
   cd typescript && npm run example
   
   # Signature tool web application
   cd go/example/signature-tool
   APP_ID=secure-messaging-app go run .
   ```

3. **View Server Logs:**
   ```bash
   tail -f mock-server/logs/*.log
   ```

4. **Stop Environment:**
   ```bash
   cd mock-server
   ./stop-test-env.sh
   ```

## Security Notes

- All communications use mutual TLS authentication
- Hostname verification is maintained (never disabled)
- Certificate and key files are excluded via .gitignore
- No hardcoded credentials or secrets
- Voting requests include loop prevention mechanism

## License

This project is part of the TEENet ecosystem for secure distributed key management.