# TEE DAO Mock Server

A local testing environment for TEE DAO distributed key management system that simulates complete DAO nodes, configuration servers, and user management systems, allowing developers to test their programs locally without connecting to real DAO networks.

> **🎉 Updated for SDK v3.0**: All examples below use the simplified v3.0 API with default App ID support. See usage examples for migration guidance.

## ⚡ Quick Start (3 Steps)

### Step 1: Start the Mock Server
```bash
cd mock-server
./start-test-env.sh
```

### Step 2: Choose an App ID
The server provides 4 pre-configured App IDs for different use cases:

| App ID | Use Case | Key Type | Signature Type |
|--------|----------|----------|----------------|
| `ethereum-wallet-app` | Ethereum/Web3 | 64-byte uncompressed | 65-byte (R+S+V) |
| `secure-messaging-app` | High-speed messaging | 32-byte ED25519 | 64-byte EdDSA |
| `financial-trading-platform` | Financial systems | 33-byte P-256 | 64-byte ECDSA |
| `digital-identity-service` | Bitcoin/DID | 33-byte secp256k1 | 64-byte BIP-340 |

### Step 3: Test with Example Code

**Go Example:**
```go
package main

import (
    "fmt"
    "log"
    "os"
    client "github.com/TEENet-io/teenet-sdk/go"
)

func main() {
    // Read from environment variables (with defaults)
    configAddr := os.Getenv("TEE_CONFIG_ADDR")
    if configAddr == "" {
        configAddr = "localhost:50052"
    }

    appID := os.Getenv("APP_ID")
    if appID == "" {
        appID = "ethereum-wallet-app"
    }

    // Create and initialize client
    teeClient := client.NewClient(configAddr)
    defer teeClient.Close()

    teeClient.SetDefaultAppID(appID)
    if err := teeClient.Init(); err != nil {
        log.Fatal(err)
    }

    fmt.Printf("✅ Connected to: %s\n", configAddr)
    fmt.Printf("✅ Using App ID: %s\n", appID)

    // Sign a message
    message := []byte("Hello, TEE DAO!")
    result, err := teeClient.Sign(message)
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("✅ Signature: %x\n", result.Signature)

    // Verify the signature
    valid, _ := teeClient.Verify(message, result.Signature)
    fmt.Printf("✅ Valid: %v\n", valid)
}
```

**Run the example:**
```bash
go run example-user-program.go
```

**Test all App IDs:**
```bash
go run test-all-apps.go
```

**Stop the server:**
```bash
./stop-test-env.sh
```

---

## 🚀 Detailed Setup

### 1. Start Services

```bash
# Start all services with one command (config server, DAO server, app node)
./start-test-env.sh
```

After successful startup, you'll see:
```
=======================================
   Test Environment Ready!
=======================================

Service Status:
  Config Server: localhost:50052 (PID: xxxx)
  DAO Server:    localhost:50051 (PID: xxxx)
  App Node:      localhost:50053 (PID: xxxx)
```

### 2. View Available App ID List

After starting services, the App node will print all available App IDs to the console:

```
Available App IDs for testing:
  - secure-messaging-app (schnorr + ed25519) - Secure Messaging Application - Schnorr/ED25519
  - financial-trading-platform (ecdsa + secp256r1) - Financial Trading Platform - ECDSA/SECP256R1
  - digital-identity-service (schnorr + secp256k1) - Digital Identity Service - Schnorr/SECP256K1
  - ethereum-wallet-app (ecdsa + secp256k1) - Ethereum Wallet - ECDSA/SECP256K1

💡 Usage Tips:
   Copy any of the above App IDs to use in your client programs
   Each App ID corresponds to different signature protocol and curve combinations
```

Or check the App node logs:

```bash
tail -f logs/app-node.log
```

### 3. Run Example Program

```bash
# Run example program
./example-program
```

### 4. Stop Services

```bash
# Stop all services
./stop-test-env.sh
```

## 🔧 Core Features

### Config Server (localhost:50052)
- **Node Discovery**: Provides DAO node and App node address information
- **Certificate Distribution**: Provides TLS certificates required for client connections
- **Configuration Management**: Returns node configuration and network topology information

### DAO Server (localhost:50051) 
- **Real Cryptographic Signatures**: Supports multiple signature protocols and curves with real cryptography
  - ECDSA (secp256k1, secp256r1)
  - Schnorr (ed25519, secp256k1)
- **TLS Security**: Mutual certificate authentication
- **Consistent Key Generation**: Deterministic key generation for reproducible testing

### App Node (localhost:50053)
- **App ID Management**: Retrieve real public keys by App ID
- **User Management**: Simulates user management system functionality
- **Real Public Key Mapping**: Pre-configured semantic App IDs with real cryptographic key pairs
- **Protocol Support**: Supports different cryptographic protocol combinations

## 📝 Usage Examples

### Basic Usage (v3.0 API)

```go
package main

import (
    "fmt"
    "log"
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

    // Initialize client
    if err := teeClient.Init(); err != nil {
        log.Fatal(err)
    }

    fmt.Printf("Client initialized for app: %s\n", appID)

    // Simple signature (v3.0 - no AppID parameter needed)
    message := []byte("Hello TEE DAO!")
    result, err := teeClient.Sign(message)
    if err != nil {
        log.Fatal(err)
    }

    if result.Success {
        fmt.Printf("Signature: %x\n", result.Signature)
    }

    // Get public key (v3.0 - uses default AppID)
    publicKey, protocol, curve, err := teeClient.GetPublicKey()
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("Public Key: %s\n", publicKey)
    fmt.Printf("Protocol: %s, Curve: %s\n", protocol, curve)

    // Verify signature (v3.0 - uses default AppID)
    valid, err := teeClient.Verify(message, result.Signature)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("Signature valid: %v\n", valid)
}
```

### Voting Signature Example (v3.0)

```go
import (
    "bytes"
    "encoding/base64"
    "encoding/json"
    "net/http"
    "strings"
)

// In HTTP handler for voting
func handleVote(w http.ResponseWriter, r *http.Request) {
    var req struct {
        Message string `json:"message"`
    }
    json.NewDecoder(r.Body).Decode(&req)

    // Decode message
    messageBytes, _ := base64.StdEncoding.DecodeString(req.Message)

    // Make local voting decision
    localApproval := strings.Contains(string(messageBytes), "test")

    // Sign with voting options (voting auto-enabled by AppID config)
    result, err := teeClient.Sign(messageBytes, &client.SignOptions{
        LocalApproval: localApproval,
        HTTPRequest:   r,
    })

    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    json.NewEncoder(w).Encode(result)
}
```

## 🧪 Test App IDs

The system provides semantic App IDs with real cryptographic keys. View available App IDs:

### Method 1: Check Startup Output
When starting services, the App node will directly display all available App IDs in the console

### Method 2: Check App Node Logs
```bash
tail -f logs/app-node.log
```

### Available App ID Types:

| App ID | Protocol | Curve | Public Key | Signature | Hash | Description |
|--------|----------|-------|------------|-----------|------|-------------|
| `secure-messaging-app` | Schnorr (EdDSA) | ed25519 | 32 bytes | 64 bytes | SHA-256 | Secure Messaging Application |
| `financial-trading-platform` | ECDSA | secp256r1 | 33 bytes (compressed) | 64 bytes (R+S) | SHA-256 | Financial Trading Platform |
| `digital-identity-service` | Schnorr (BIP-340) | secp256k1 | 33 bytes (compressed) | 64 bytes | SHA-256 | Digital Identity Service |
| `ethereum-wallet-app` | ECDSA | secp256k1 | **64 bytes (uncompressed)** | **65 bytes (R+S+V)** | **Keccak-256** | **Ethereum Wallet - Ethereum-Compatible** |

> **Note**: All App IDs use real cryptographic keys that are deterministically generated for consistent testing.
>
> 💡 **Usage Suggestion**: Copy complete App IDs directly from console output to use in your client programs.

#### Technical Specifications

##### 1. secure-messaging-app (Schnorr/ED25519)
- **Algorithm**: EdDSA (Edwards-curve Digital Signature Algorithm)
- **Curve**: Curve25519
- **Public Key**: 32 bytes (raw ED25519 public key)
- **Signature**: 64 bytes (standard ED25519 signature)
- **Hash**: SHA-256 (internally handled by ED25519)
- **Use Case**: High-performance messaging, IoT devices

##### 2. financial-trading-platform (ECDSA/SECP256R1)
- **Algorithm**: ECDSA (Elliptic Curve Digital Signature Algorithm)
- **Curve**: NIST P-256 (secp256r1)
- **Public Key**: 33 bytes (compressed format with 0x02/0x03 prefix)
- **Signature**: 64 bytes (R || S, 32 bytes each)
- **Hash**: SHA-256
- **Use Case**: Financial systems, regulatory compliance

##### 3. digital-identity-service (Schnorr/SECP256K1)
- **Algorithm**: BIP-340 Schnorr Signatures
- **Curve**: secp256k1 (Bitcoin curve)
- **Public Key**: 33 bytes (compressed format)
- **Signature**: 64 bytes (BIP-340 format)
- **Hash**: SHA-256
- **Use Case**: Decentralized identity, Bitcoin-compatible applications

##### 4. ethereum-wallet-app (ECDSA/SECP256K1) - Ethereum-Compatible

**Public Key (64 bytes)**:
- Format: Uncompressed (X + Y coordinates without 0x04 prefix)
- X coordinate: 32 bytes
- Y coordinate: 32 bytes
- Example: `fe713a72cd97a68b95c5610c4ae84e631e3a009913d688749e43fdb6ed680d8b6d45d073024ddb9c99bf61c07af0e09a46c0296a7ebfe4e6486783aecfea682e`

**Signature (65 bytes)**:
- Format: R + S + V (Ethereum standard)
- R: 32 bytes (signature component)
- S: 32 bytes (signature component)
- V: 1 byte (recovery ID, allows public key recovery from signature)
- Hash: **Keccak-256** (Ethereum standard, not SHA-256)
- Example: `1d9b9bc487584f9424583838d3b79fc3e26721bac779ccf1abdcedcd573b5005590c17fb30037e0a6af3c2c2c3434788f062b4ef045f02b358ee902aaa5124a200`

**Recovery ID (V)**:
- Value: 0 or 1 (based on Y coordinate parity)
- Allows recovering the public key from the signature alone
- Compatible with Ethereum's `ecrecover` function
- **Use Case**: Ethereum DApps, Web3 wallets, smart contracts

## 🔒 Security Features

- **Dynamic Certificate Generation**: TLS certificates are regenerated on each startup, not stored in version control
- **Mutual Authentication**: All services use mutual TLS certificate verification
- **CA Verification**: Both clients and servers verify each other's certificate chains
- **Encrypted Communication**: All gRPC communication is encrypted via TLS

## 📂 File Structure

```
tee-dao-mock-server/
├── dao-server.go               # DAO server main program
├── mock-config-server.go       # Config server
├── mock-app-node.go           # App node server
├── example-user-program.go    # User program example
├── proto/                     # Protocol Buffers definitions
│   ├── *.proto               # gRPC service definitions
│   └── *.pb.go               # Generated Go code
├── certs/                    # TLS certificate directory (dynamically generated)
├── logs/                     # Service logs directory
├── start-test-env.sh         # Startup script
├── stop-test-env.sh          # Stop script
├── generate-certs.sh         # Certificate generation script
├── Makefile                  # Build configuration
├── go.mod                    # Go module definition
└── README.md                # This documentation
```

## 🛠️ Development Commands

```bash
# Build all components
make build

# Quick start test environment
make start

# Run example program
make example

# Generate Protocol Buffers code
make proto

# Generate TLS certificates
make certs

# Clean build files
make clean

# View service logs
tail -f logs/*.log
```

## ⚠️ Important Notes

1. **Development Testing Only**: This is a mock environment, generated signatures are for testing purposes only
2. **Certificate Security**: TLS certificates are self-signed, suitable for local testing only
3. **Data Persistence**: All data is in memory, resets after restart
4. **Network Configuration**: Ensure ports 50051, 50052, 50053 are not occupied

## 🔧 Troubleshooting

### Service Startup Failure
```bash
# Check port usage
lsof -i :50051
lsof -i :50052  
lsof -i :50053

# Stop all services
./stop-test-env.sh
```

### Certificate Issues
```bash
# Regenerate certificates
./generate-certs.sh

# Check certificate validity
openssl x509 -in certs/dao-server.crt -text -noout
```

### Connection Issues
```bash
# Check service status
ps aux | grep -E "(dao-server|config-server|app-node)"

# View service logs
tail -f logs/dao-server.log
tail -f logs/config-server.log
tail -f logs/app-node.log
```

## 📞 Support

If you encounter issues, please check:
1. All dependencies are correctly installed (Go 1.19+, Protocol Buffers)
2. Ports are not occupied by other programs
3. Firewall settings are not blocking local connections
4. Error information in log files

---

**TEE DAO Mock Server** - Provides complete local development testing environment 🚀