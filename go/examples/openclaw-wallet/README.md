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
- Personal multi-chain asset management (Ethereum, Solana; Bitcoin and more coming)
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
OpenClaw Skill (Python, user's machine):
  1. Query nonce + gas price from Ethereum RPC
  2. Construct unsigned transaction
  3. Compute tx hash (Keccak256 of RLP-encoded tx)

Wallet App (TEE):
  4. Sign tx hash via TEE-DAO threshold ECDSA
  5. Return signature (r, s)
  6. If amount > threshold → return pending_approval
     → user approves via Passkey in Web UI
     → then sign and return signature

OpenClaw Skill:
  7. Assemble signed transaction (unsigned tx + r,s,v)
  8. Broadcast via eth_sendRawTransaction
  9. Return tx hash to user
```

## Supported Chains

| Chain | Algorithm | Address Format |
|-------|-----------|----------------|
| Ethereum / EVM | ECDSA secp256k1 | 0x... (EIP-55 checksum) |
| Solana | Schnorr Ed25519 | Base58 |

## Authentication

Two modes, two use cases:

**API Key** (`ocw_...` prefix) — for OpenClaw daily operations. Generated via the Web UI
after Passkey login. SHA-256 hashed at rest. Supports wallet creation, signing, balance
queries, and listing approvals.

**Passkey session** (`ps_...` prefix) — for Web UI management. Uses WebAuthn (device
biometrics or hardware security keys). Required for: generating/revoking API keys, and
approving large transactions. **Approving large transactions via API Key is explicitly
rejected** — only a human holding a Passkey device can approve.

## API Reference

### Public Routes

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/health` | Health check |
| POST | `/api/auth/invite` | Invite a user (admin) |
| GET | `/api/auth/passkey/options` | Passkey login challenge |
| POST | `/api/auth/passkey/verify` | Passkey login → session token |
| GET | `/api/auth/passkey/register/options` | Registration options (invite token) |
| POST | `/api/auth/passkey/register/verify` | Complete registration |

### API Key Management (Passkey session required)

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/auth/apikey/generate` | Generate API key (shown once) |
| GET | `/api/auth/apikey/list` | List API key prefixes |
| DELETE | `/api/auth/apikey` | Revoke API key |

### Wallet Routes (API Key or Passkey session)

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/wallets` | Create wallet `{"chain":"ethereum","label":"..."}` |
| GET | `/api/wallets` | List wallets |
| GET | `/api/wallets/:id` | Wallet details |
| DELETE | `/api/wallets/:id` | Delete wallet |
| POST | `/api/wallets/:id/sign` | Sign message (with approval check) |
| GET | `/api/wallets/:id/pubkey` | Raw public key |
| GET | `/api/wallets/:id/balance` | On-chain balance |
| PUT | `/api/wallets/:id/policy` | Set approval threshold policy |
| GET | `/api/wallets/:id/policy` | Get approval policy |

### Approval Routes

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/approvals/pending` | API Key or Passkey | List pending approvals |
| GET | `/api/approvals/:id` | API Key or Passkey | Approval status (OpenClaw polling) |
| POST | `/api/approvals/:id/approve` | **Passkey only** | Approve (hardware auth required) |
| POST | `/api/approvals/:id/reject` | **Passkey only** | Reject (hardware auth required) |

### Sign Request / Response

**Request:**
```json
POST /api/wallets/1/sign
{
  "message": "0xdeadbeef...",
  "encoding": "hex",
  "tx_context": {
    "type": "transfer",
    "from": "0x742d...2bD18",
    "to": "0xAb58...eC9B",
    "amount": "1.5",
    "currency": "ETH",
    "memo": "Payment for services"
  }
}
```

**Direct sign response** (no policy, or amount ≤ threshold):
```json
{
  "status": "signed",
  "signature": "0xabc123...",
  "wallet_address": "0x742d...2bD18",
  "chain": "ethereum"
}
```

**Approval required response** (amount > threshold):
```json
{
  "status": "pending_approval",
  "approval_id": 123,
  "message": "Transfer 1.5 ETH from 0x742d... to 0xAb58... requires approval",
  "tx_context": { "type": "transfer", "from": "...", "to": "...", "amount": "1.5", "currency": "ETH" },
  "threshold": "0.1",
  "approval_url": "https://your-instance/#/approve/123"
}
```

When OpenClaw receives `pending_approval`, it immediately shows the user a summary
(from, to, amount, memo) and the approval URL, then polls `/api/approvals/123` until
the status changes to `approved` or `rejected`.

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
| `ETH_RPC_URL` | Ethereum RPC endpoint (for balance queries) | — |
| `SOL_RPC_URL` | Solana RPC endpoint | `https://api.mainnet-beta.solana.com` |

## OpenClaw Skill

Install the `tee-wallet` skill to use this service from OpenClaw:

```bash
cp -r skill/tee-wallet ~/.openclaw/workspace/skills/
```

Configure environment variables:

```bash
export TEE_WALLET_API_URL=https://your-ums/instance/your-app-instance-id
export TEE_WALLET_API_KEY=ocw_your_api_key
export ETH_RPC_URL=https://mainnet.infura.io/v3/YOUR_KEY
```

**Transfer script prerequisites:**
```bash
pip install web3     # Ethereum transfers
pip install solders  # Solana transfers
```

**Example OpenClaw commands:**
- "Create an Ethereum wallet"
- "What are my wallets?"
- "Send 0.1 ETH to 0xAb5801a7D398351b8bE11C439e05C5B3259aeC9B"
- "Check balance of wallet 1"
- "Set approval threshold to 0.5 ETH for wallet 1"

## Security Model

| Layer | Protection |
|-------|-----------|
| Private Keys | Split via DKG across TEE-DAO nodes; threshold signing; never reconstructed outside TEE |
| Wallet App | Runs inside TEE mesh; stores only public keys and addresses |
| API Keys | SHA-256 hashed; shown once on creation |
| Large Transactions | Require Passkey (WebAuthn) hardware authentication |
| Audit Trail | All signing operations logged in TEE system |

## Project Structure

```
openclaw-wallet/
├── main.go                  # Entry point: config, DB, SDK, routes
├── handler/
│   ├── middleware.go        # Dual auth middleware + SessionStore
│   ├── auth.go              # Passkey login/register + API key management
│   ├── wallet.go            # Wallet CRUD + sign + approval policy
│   ├── balance.go           # On-chain balance queries
│   └── approval.go          # Approval lifecycle (list, get, approve, reject)
├── model/
│   ├── user.go              # User (passkey_user_id + API key hash)
│   ├── wallet.go            # Wallet (chain, address, key_name, public_key)
│   └── policy.go            # ApprovalPolicy + ApprovalRequest
├── chain/
│   ├── address.go           # ETH Keccak256 + SOL Base58 address derivation
│   └── rpc.go               # Chain RPC balance queries
├── frontend/
│   └── index.html           # Web UI (Passkey login, API key mgmt, approvals)
├── skill/
│   └── tee-wallet/
│       ├── SKILL.md         # OpenClaw skill definition
│       └── scripts/
│           ├── eth_transfer.py   # ETH transfer helper (web3.py)
│           └── sol_transfer.py   # SOL transfer helper (solders)
├── Dockerfile
├── pack.sh
└── go.mod                   # Module: openclaw-wallet
```

## Roadmap

- Bitcoin address derivation + transfer script (P2WPKH)
- EVM chain expansion (BSC, Polygon, Arbitrum — same keys, different RPC)
- EIP-712 structured data signing (DeFi permits, multi-sig messages)
- ERC-20 token transfers
- ClawHub publication

## License

MIT
