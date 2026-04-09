# TEENet SDK Basic Examples

This directory contains basic command-line examples demonstrating core features of the TEENet SDK.

## Examples

### 1. Simple Signing (`simple/`)

Demonstrates basic signing and verification operations.

**Features:**
- Connect to consensus service
- Retrieve public key information
- Sign a message
- Verify the signature

**Usage:**
```bash
cd simple
export APP_INSTANCE_ID="your-app-instance-id"
export CONSENSUS_URL="http://localhost:8089"  # optional
go run main.go
```

### 2. Voting (`voting/`)

Demonstrates M-of-N threshold voting with multiple voters.

**Features:**
- Concurrent voting from multiple app instance IDs
- Threshold-based signature generation
- Vote tracking and status monitoring

**Usage:**
```bash
cd voting
go run main.go
```

**Note:** Edit `main.go` to configure your voter app instance IDs and consensus URL.

### 3. Forwarding Voting (`forwarding/`)

Tests cross-consensus-node voting with forwarding.

**Features:**
- Votes from different consensus nodes
- Request forwarding between nodes
- Distributed threshold signing

**Usage:**
```bash
cd forwarding
go run main.go
```

**Note:** Edit `main.go` to configure consensus URLs and voter app instance IDs.

## Building

Each example has its own `go.mod` file. To build an example:

```bash
cd <example-directory>
go mod tidy
go build
```

## Environment Variables

### Simple Example

- `APP_INSTANCE_ID` (required): Your TEENet application instance ID
- `CONSENSUS_URL` (optional): Consensus service URL (default: http://localhost:8089)

### Voting Examples

Configuration is hardcoded in the source files. Edit `main.go` to customize:
- Voter app instance IDs
- Consensus URLs
- Message content

## Common Operations

### Get Public Key
```go
keys, err := client.GetPublicKeys(ctx)
```

### Sign Message
```go
result, err := client.Sign(ctx, []byte("message"), "my-key")
if err != nil {
    log.Fatal(err)
}
fmt.Printf("Signature: %x\n", result.Signature)
```

### Verify Signature
```go
valid, err := client.Verify(ctx, message, signature, "my-key")
```

## More Examples

For web-based examples with GUI, see:
- `../voting-demo/` - Web voting demonstration
