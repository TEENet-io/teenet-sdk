# TEENet SDK Mock Consensus Server

A mock `app-comm-consensus` service for testing the TEENet SDK offline. Implements real cryptographic signing for all supported algorithms, plus voting, approval, and admin endpoint simulation.

## Quick Start

```bash
# Build and run
go build && ./mock-server

# Custom port / bind address
MOCK_SERVER_PORT=9000 MOCK_SERVER_BIND=0.0.0.0 ./mock-server
```

Default: `127.0.0.1:8089`

## API Endpoints (34 total)

### Core Signing & Keys (6)

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/health` | Health check |
| GET | `/api/publickeys/:app_instance_id` | Get bound public keys |
| POST | `/api/submit-request` | Sign a message (supports direct, voting, and approval modes) |
| POST | `/api/generate-key` | Generate a new key pair |
| GET | `/api/apikey/:name` | Retrieve API key value |
| POST | `/api/apikey/:name/sign` | HMAC-SHA256 sign with API secret |

### Voting Cache (4)

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/cache/:hash` | Poll voting/signing status (SDK polls this) |
| GET | `/api/cache/status` | List all cache entries |
| DELETE | `/api/cache/:hash` | Remove cache entry |
| GET | `/api/config/:app_instance_id` | Get voting configuration |

### Approval Bridge (12)

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/auth/passkey/options` | Passkey login challenge |
| POST | `/api/auth/passkey/verify` | Passkey login verify (returns token) |
| POST | `/api/auth/passkey/verify-as` | Login as specific user |
| POST | `/api/approvals/request/init` | Initialize approval request |
| GET | `/api/approvals/request/:id/challenge` | Get confirmation challenge |
| POST | `/api/approvals/request/:id/confirm` | Confirm request |
| GET | `/api/approvals/:taskId/challenge` | Get action challenge |
| POST | `/api/approvals/:taskId/action` | Approve/reject (auto-signs on approval) |
| GET | `/api/approvals/pending` | List pending approvals |
| GET | `/api/requests/mine` | List user's requests |
| GET | `/api/signature/by-tx/:txId` | Get signature by transaction ID |
| DELETE | `/api/requests/:id` | Cancel request |

### Admin Bridge (12)

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/admin/passkey/invite` | Invite passkey user |
| GET | `/api/admin/passkey/users` | List passkey users |
| DELETE | `/api/admin/passkey/users/:id` | Delete passkey user |
| GET | `/api/admin/audit-records` | List audit records |
| PUT | `/api/admin/policy` | Upsert permission policy |
| GET | `/api/admin/policy` | Get permission policy |
| DELETE | `/api/admin/policy` | Delete permission policy |
| DELETE | `/api/admin/publickeys/:name` | Delete public key |
| POST | `/api/admin/apikeys` | Create API key |
| DELETE | `/api/admin/apikeys/:name` | Delete API key |
| GET | `/api/passkey/register/options` | Passkey registration options |
| POST | `/api/passkey/register/verify` | Complete passkey registration |

## Signing Modes

`POST /api/submit-request` supports three modes based on the app's voting configuration:

### Direct Signing (default)
All test apps except `test-voting-2of3` and `test-approval-required`.

```bash
curl -X POST localhost:8089/api/submit-request \
  -H "Content-Type: application/json" \
  -d '{"app_instance_id":"test-ecdsa-secp256k1","message":"<base64>"}'
# → {"status":"signed", "signature":"<hex>", ...}
```

### Voting Mode
App: `test-voting-2of3` (requires 2 votes from different app_instance_ids).

```bash
# First vote → pending
curl -X POST localhost:8089/api/submit-request \
  -d '{"app_instance_id":"test-voting-2of3","message":"<base64>"}'
# → {"status":"pending", "needs_voting":true, "current_votes":1, "required_votes":2}

# Poll status
curl localhost:8089/api/cache/<hash>
# → {"found":true, "entry":{"status":"pending", ...}}

# Second vote (different instance) → signed
```

### Approval Mode
App: `test-approval-required` (requires passkey approval).

```bash
# Submit → pending_approval
curl -X POST localhost:8089/api/submit-request \
  -d '{"app_instance_id":"test-approval-required","message":"<base64>"}'
# → {"status":"pending_approval", "tx_id":"mock-tx-1", "request_id":2}

# Login, then approve via /api/approvals/:taskId/action
```

## Hashing Responsibility

The mock server matches the TEE-DAO backend behavior:

| Protocol | Curve | Who hashes? | Hash algorithm |
|----------|-------|-------------|----------------|
| ECDSA | secp256k1 | **User** (must pass 32-byte hash) | Keccak-256 (Ethereum) or SHA-256 |
| ECDSA | secp256r1 | **User** (must pass 32-byte hash) | SHA-256 |
| Schnorr | secp256k1 | **Mock server** internally | SHA-256 |
| Schnorr | ed25519 | **EdDSA protocol** internally | SHA-512 (part of EdDSA) |
| HMAC | — | **HMAC** internally | SHA-256 |

For ECDSA, pass the hash to both `Sign()` and `Verify()`:

```go
// secp256k1 ECDSA — hash with Keccak-256
hashedMsg := crypto.Keccak256(message)
result, _ := client.Sign(ctx, hashedMsg, "my-key")
valid, _ := client.Verify(ctx, hashedMsg, result.Signature, "my-key")

// For Schnorr / EdDSA — pass raw message
result, _ := client.Sign(ctx, message, "my-key")
valid, _ := client.Verify(ctx, message, result.Signature, "my-key")
```

## Pre-configured Test Apps

| App Instance ID | Protocol | Curve | Mode |
|----------------|----------|-------|------|
| test-schnorr-ed25519 | schnorr | ed25519 | Direct |
| test-schnorr-secp256k1 | schnorr | secp256k1 | Direct |
| test-ecdsa-secp256k1 | ecdsa | secp256k1 | Direct |
| test-ecdsa-secp256r1 | ecdsa | secp256r1 | Direct |
| ethereum-wallet-app | ecdsa | secp256k1 | Direct |
| secure-messaging-app | schnorr | ed25519 | Direct |
| test-voting-2of3 | ecdsa | secp256k1 | Voting (2-of-N) |
| test-approval-required | ecdsa | secp256k1 | Approval |

Pre-configured passkey users: Alice (ID=1), Bob (ID=2) — bound to `test-approval-required`.

## Notes

- For development and testing only; do not use in production
- All data is in-memory (resets on restart)
- Uses deterministic private keys for reproducible signatures
- Approval tokens use HMAC-SHA256 with a random secret (30-minute TTL)
