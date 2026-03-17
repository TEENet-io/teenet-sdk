# TEE Wallet for OpenClaw

A crypto wallet service powered by TEE (Trusted Execution Environment) hardware security.
Designed for [OpenClaw](https://openclaw.ai/) AI assistant to create and manage wallets,
sign transactions, and send crypto — with private keys that never leave secure hardware.

## Overview

TEE Wallet is a multi-chain crypto wallet service running inside a TEE mesh network,
built specifically for the OpenClaw AI assistant. It lets AI agents manage on-chain assets
on behalf of users — creating wallets, querying balances, constructing and signing
transactions — while keeping private keys safe in TEE hardware at all times.

**Core principle: private keys never leave the hardware.** Keys are split across TEE-DAO
nodes via Distributed Key Generation (DKG). No single node ever holds a complete private key.
Every signing operation requires threshold consensus across multiple TEE nodes inside secure
hardware — only the signature is ever returned to the application.

**Why it fits AI assistants:** Users just tell OpenClaw what to do. The AI handles the rest —
no manual key management, no browser extensions, no seed phrases. Users only interact
directly (via Passkey) for initial setup and large-transaction approvals. Everything else
is automated.

**Use cases:**
- Personal multi-chain asset management (Ethereum, Solana, and all EVM-compatible chains)
- AI-agent automated on-chain operations (scheduled transfers, DeFi interactions)
- Team treasury management (large transactions require human Passkey approval; small ones run automatically)
- Lightweight non-custodial wallets with no private key burden on the user

**Security boundaries:**
- The wallet app stores only public keys and addresses — it cannot sign independently
- API Keys cover daily operations; large transactions force Passkey hardware authentication
- All signing operations have system-level audit logs from the TEE layer
- The wallet container runs inside a TEE mesh node, isolated by hardware

## How It Works

```
OpenClaw (user's machine)
  → REST API (API Key)
      → Wallet App (TEE mesh container, :8080)
          → TEENet SDK → TEE-DAO cluster (threshold signing / DKG)
```

**Private keys are split across TEE-DAO nodes via DKG.**
No single node ever holds a complete private key. Signing requires threshold consensus
across multiple TEE nodes. The wallet app itself only stores public keys and addresses.

### Transaction Flow (e.g., Send ETH)

```
Wallet App (backend):
  1. Fetch nonce + gas price from chain RPC
  2. Construct unsigned transaction
  3. Compute signing hash (EIP-155)
  4. Sign via TEE-DAO threshold ECDSA
  5. Assemble signed transaction and broadcast
  6. Return tx_hash

If amount > policy threshold:
  4. Return pending_approval + approval_url
     → user approves via Passkey in Web UI
     → wallet signs and broadcasts
```

## Supported Chains

| Chain | Algorithm | Currency |
|-------|-----------|----------|
| Ethereum Mainnet | ECDSA secp256k1 | ETH |
| Sepolia Testnet | ECDSA secp256k1 | ETH |
| Holesky Testnet | ECDSA secp256k1 | ETH |
| Optimism | ECDSA secp256k1 | ETH |
| Base Sepolia | ECDSA secp256k1 | ETH |
| BSC Testnet | ECDSA secp256k1 | tBNB |
| Solana Mainnet | Schnorr Ed25519 | SOL |
| Solana Devnet | Schnorr Ed25519 | SOL |

All EVM chains support **ERC-20 token transfers** (contract address must be whitelisted per wallet).
Custom chains can be added via `chains.json`.

## Authentication

Two modes, two use cases:

**API Key** (`ocw_...` prefix) — for OpenClaw daily operations. Generated via the Web UI
after Passkey login. SHA-256 hashed at rest. Supports wallet creation, signing, balance
queries, and listing approvals.

**Passkey session** (`ps_...` prefix) — for Web UI management. Uses WebAuthn (device
biometrics or hardware security keys). Required for: generating/revoking API keys,
managing ERC-20 contract whitelists, approving large transactions, and account deletion.
**Approving large transactions via API Key is explicitly rejected** — only a human holding
a Passkey device can approve.

## API Reference

### Public Routes

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/health` | Health check |
| GET | `/api/chains` | List supported chains |
| POST | `/api/auth/passkey/register/begin` | Start registration (auto-invite) |
| POST | `/api/auth/passkey/register/verify` | Complete registration |
| GET | `/api/auth/passkey/login/begin` | Passkey login challenge |
| POST | `/api/auth/passkey/login/verify` | Passkey login → session token |

### API Key Management (Passkey session required)

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/auth/apikey/generate` | Generate API key (shown once) |
| GET | `/api/auth/apikey/list` | List API key prefixes |
| DELETE | `/api/auth/apikey` | Revoke API key |
| DELETE | `/api/auth/account` | Delete account + all wallets + TEE keys |

### Wallet Routes (API Key or Passkey session)

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/wallets` | Create wallet `{"chain":"ethereum","label":"..."}` |
| GET | `/api/wallets` | List wallets |
| GET | `/api/wallets/:id` | Wallet details |
| DELETE | `/api/wallets/:id` | Delete wallet + TEE key (Passkey required) |
| POST | `/api/wallets/:id/sign` | Sign message (with approval check) |
| GET | `/api/wallets/:id/balance` | On-chain balance |
| POST | `/api/wallets/:id/transfer` | Build + sign + broadcast transfer |
| PUT | `/api/wallets/:id/policy` | Set approval threshold policy (Passkey required) |
| GET | `/api/wallets/:id/policy` | Get approval policy |
| DELETE | `/api/wallets/:id/policy` | Delete approval policy (Passkey required) |

### ERC-20 Contract Whitelist (Passkey session required)

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/wallets/:id/contracts` | List whitelisted contracts |
| POST | `/api/wallets/:id/contracts` | Add contract to whitelist |
| DELETE | `/api/wallets/:id/contracts/:cid` | Remove contract from whitelist |

### Approval Routes

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/approvals/pending` | API Key or Passkey | List pending approvals |
| GET | `/api/approvals/:id` | API Key or Passkey | Approval status |
| POST | `/api/approvals/:id/approve` | **Passkey only** | Approve (hardware auth required) |
| POST | `/api/approvals/:id/reject` | **Passkey only** | Reject (hardware auth required) |

### Transfer Request / Response

**Native transfer:**
```json
POST /api/wallets/1/transfer
{ "to": "0xAb58...eC9B", "amount": "0.1", "memo": "optional" }
```

**ERC-20 transfer:**
```json
POST /api/wallets/1/transfer
{
  "to": "0xAb58...eC9B",
  "amount": "10.5",
  "token": { "contract": "0x1c7D...7238", "symbol": "USDC", "decimals": 6 }
}
```

**Success response:**
```json
{ "status": "completed", "tx_hash": "0xabc...", "chain": "ethereum", "amount": "0.1", "currency": "ETH" }
```

**Approval required response** (amount > policy threshold):
```json
{
  "status": "pending_approval",
  "approval_id": 123,
  "approval_url": "https://your-instance/#/approve/123",
  "tx_context": { "type": "transfer", "from": "0x...", "to": "0x...", "amount": "1.5", "currency": "ETH" }
}
```

## Deployment

### Prerequisites

- UMS (user-management-system) running with a TEE-DAO cluster
- Application + Instance created in the UMS Dashboard

### Build

```bash
# Local binary
go build -o wallet-app .

# Docker image
./pack.sh
```

### Deploy via UMS Dashboard

1. Create an Application in UMS Dashboard
2. Create an Instance under it
3. Deploy the Docker image to a mesh node
4. Access via `/instance/{app_instance_id}/api/...`

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `APP_INSTANCE_ID` | Instance ID (auto-set by UMS at deploy time) | — |
| `CONSENSUS_URL` | app-comm-consensus URL | `http://localhost:8089` |
| `HOST` | Listen address | `0.0.0.0` |
| `PORT` | Listen port | `8080` |
| `DATA_DIR` | SQLite data directory | `/data` |
| `BASE_URL` | Public URL of this service (used in approval links) | `http://localhost:8080` |
| `CHAINS_FILE` | Path to custom chains.json (optional) | built-in defaults |

## OpenClaw Skill

Install the `tee-wallet` skill to use this service from OpenClaw:

```bash
cp -r skill/tee-wallet ~/.openclaw/workspace/skills/
```

Configure environment variables:

```bash
export TEE_WALLET_API_URL=https://your-ums/instance/your-app-instance-id
export TEE_WALLET_API_KEY=ocw_your_api_key
```

**Example OpenClaw commands:**
- "Create an Ethereum wallet"
- "What are my wallets?"
- "Send 0.1 ETH to 0xAb5801a7D398351b8bE11C439e05C5B3259aeC9B"
- "Send 10 USDC to 0xAb58..."
- "Check balance of wallet 1"
- "Set approval threshold to 0.5 ETH for wallet 1"

## Security Model

| Layer | Protection |
|-------|-----------|
| Private Keys | Split via DKG across TEE-DAO nodes; threshold signing; never reconstructed outside TEE |
| Wallet App | Runs inside TEE mesh; stores only public keys and addresses |
| API Keys | SHA-256 hashed; shown once on creation |
| Large Transactions | Require Passkey (WebAuthn) hardware authentication |
| ERC-20 Transfers | Contract address must be whitelisted via Passkey before use |
| Account Deletion | Requires Passkey; deletes all wallets and TEE keys atomically |
| Audit Trail | All signing and management operations logged |

## Project Structure

```
openclaw-wallet/
├── main.go                  # Entry point: config, DB, SDK, routes
├── handler/
│   ├── middleware.go        # Dual auth middleware + SessionStore
│   ├── auth.go              # Passkey login/register + API key mgmt + account deletion
│   ├── wallet.go            # Wallet CRUD + transfer + sign + approval policy
│   ├── balance.go           # On-chain balance queries
│   ├── contract.go          # ERC-20 contract whitelist management
│   └── approval.go          # Approval lifecycle (list, get, approve, reject)
├── model/
│   ├── user.go              # User (passkey_user_id + API key hash)
│   ├── wallet.go            # Wallet + ChainConfig registry
│   ├── contract.go          # AllowedContract (ERC-20 whitelist)
│   ├── policy.go            # ApprovalPolicy + ApprovalRequest
│   └── audit.go             # AuditLog
├── chain/
│   ├── address.go           # ETH/SOL address derivation
│   ├── tx_eth.go            # ETH tx construction, ERC-20 encoding, broadcast
│   ├── tx_sol.go            # SOL tx construction + broadcast
│   └── rpc.go               # Chain RPC balance queries
├── frontend/
│   └── index.html           # Web UI (Passkey auth, wallets, transfers, approvals)
├── skill/
│   └── tee-wallet/
│       ├── SKILL.md         # OpenClaw skill definition
│       └── scripts/
├── Dockerfile
├── pack.sh
└── go.mod
```

## Roadmap

- Bitcoin address derivation + transfer (P2WPKH)
- EIP-712 structured data signing (DeFi permits)
- ClawHub publication

## License

MIT
