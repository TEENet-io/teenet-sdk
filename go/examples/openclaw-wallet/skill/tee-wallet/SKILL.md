---
name: tee-wallet
description: "Manage crypto wallets secured by TEE. Use when user asks to create wallet, check balance, send crypto, sign messages, or manage crypto assets. Supports Ethereum and Solana."
metadata:
  openclaw:
    emoji: "🔐"
    requires:
      env:
        - TEE_WALLET_API_URL
        - TEE_WALLET_API_KEY
      anyBins:
        - python3
        - curl
    primaryEnv: TEE_WALLET_API_KEY
---

# TEE Wallet Skill

You manage crypto wallets backed by TEE (Trusted Execution Environment) hardware security.
Private keys are distributed across TEE nodes via threshold cryptography — they never exist
as a whole outside secure hardware.

## Configuration

- `TEE_WALLET_API_URL`: The wallet service URL (e.g. `https://ums.example.com/instance/abc123`)
- `TEE_WALLET_API_KEY`: Your API key (starts with `ocw_`)
- `ETH_RPC_URL`: Ethereum RPC endpoint (e.g. `https://mainnet.infura.io/v3/YOUR_KEY`)
- `SOL_RPC_URL`: Solana RPC endpoint (default: `https://api.mainnet-beta.solana.com`)

## Smart Wallet Selection

**Never ask the user to provide a wallet ID directly.** Always resolve the wallet automatically:

1. If the user already mentioned a wallet in this conversation (by label, address, or chain) — use that one.
2. Otherwise call `GET /api/wallets` and:
   - If only **one** wallet matches the required chain → use it silently.
   - If **multiple** wallets match → show a compact list and ask the user to pick:
     > Which wallet do you want to use?
     > 1. `0xabcd…1234` — My Main Wallet (ETH)
     > 2. `0x5678…9abc` — DeFi Wallet (ETH)
   - If **no** wallet exists for that chain → offer to create one.

You may cache wallet details briefly within the conversation for convenience, **but `/api/wallets` is the source of truth**.
Always re-fetch `/api/wallets` before:
- showing the wallet list
- showing “all balances” / totals / account-wide balances
- assuming a wallet still exists after prior create/delete activity
- checking balances for multiple wallets after any create/delete activity

Do not build an “all balances” response from a stale wallet list remembered from earlier in the chat.
Do not query chain balances for wallets that are no longer present in the latest `/api/wallets` response.

When the user refers to wallets as `1`, `2`, `3`, etc., interpret those numbers as the **current displayed list index**, not the raw wallet `id`.
Only interpret a number as the real wallet `id` if the user explicitly says `id=7`, `wallet id 7`, or equivalent.

## Available Operations

### 1. Create Wallet

When user asks to create a new wallet:

```bash
curl -s -X POST "${TEE_WALLET_API_URL}/api/wallets" \
  -H "Authorization: Bearer ${TEE_WALLET_API_KEY}" \
  -H "Content-Type: application/json" \
  -d '{"chain":"<ethereum|solana>","label":"<user description>"}'
```

- Ask user which chain (Ethereum or Solana) if not specified
- Ethereum wallets may take 1-2 minutes to create (ECDSA key generation)
- Solana wallets are created instantly
- After success, show:
  > ✅ **Wallet created**
  > **Address:** `{address}`
  > **Chain:** {chain}
  >
  > Next steps: fund this address to get started, or set an approval policy (Section 10) to protect large transfers.

### 2. List Wallets

```bash
curl -s "${TEE_WALLET_API_URL}/api/wallets" \
  -H "Authorization: Bearer ${TEE_WALLET_API_KEY}"
```

Present wallets in a clear user-facing list with:
- list index (`1`, `2`, `3`, ...)
- Label
- Chain
- Address
- Status

Do **not** show the raw wallet `id` by default in normal chat responses. Keep the real wallet `id`
internal and use it only for API calls or debugging.

Mark wallets with status `creating` as ⏳ and `error` as ❌.

### 3. Get Wallet Details

```bash
curl -s "${TEE_WALLET_API_URL}/api/wallets/<id>" \
  -H "Authorization: Bearer ${TEE_WALLET_API_KEY}"
```

### 4. Sign Message / Send Transaction

When user asks to sign or send a transaction:

**Before signing**, show the user a confirmation block and wait for explicit confirmation:

> 🔍 **Confirm Sign**
> **Wallet:** `{wallet_address}` ({chain})
> **Message (hex):** `{message}`
> **Context:** {tx_context summary or "raw message"}
>
> Confirm? (yes / no)

Only proceed after confirmation.

```bash
curl -s -X POST "${TEE_WALLET_API_URL}/api/wallets/<id>/sign" \
  -H "Authorization: Bearer ${TEE_WALLET_API_KEY}" \
  -H "Content-Type: application/json" \
  -d '{
    "message":"<hex-encoded message>",
    "encoding":"hex",
    "tx_context":{
      "type":"transfer",
      "from":"<sender address>",
      "to":"<recipient address>",
      "amount":"<amount>",
      "currency":"<ETH|SOL>",
      "memo":"<optional memo>"
    }
  }'
```

Always include `tx_context` with full transaction details — this is shown to the user during approval.

**If response has `"status":"signed"`**: show the signature to the user.

**If response has `"status":"pending_approval"`**: follow the **Approval Polling Flow** (Section 12).

### 5. Send Crypto (Transfer)

When user asks to send/transfer crypto, call the `/transfer` endpoint.
The **backend constructs the transaction, signs it via TEE, and broadcasts it** — no scripts needed.

**Before sending**, show the user a confirmation block and wait for explicit confirmation:

> 🔍 **Confirm Transfer**
> **From:** `{wallet_address}` ({chain})
> **To:** `{recipient}`
> **Amount:** {amount} {currency}
> **Memo:** {memo or "—"}
>
> Confirm? (yes / no)

Only proceed after confirmation.

**Optional pre-check** (recommended for ETH transfers > 0.01 ETH): query native balance first.
If `balance < amount + estimated_gas (0.0005 ETH buffer)`, warn the user before sending.

```bash
curl -s -X POST "${TEE_WALLET_API_URL}/api/wallets/<id>/transfer" \
  -H "Authorization: Bearer ${TEE_WALLET_API_KEY}" \
  -H "Content-Type: application/json" \
  -d '{
    "to": "<recipient_address>",
    "amount": "<amount>",
    "memo": "<optional memo>"
  }'
```

**If response has `"status":"completed"`**: show the user:
> ✅ **Transaction sent**
> **Hash:** `{tx_hash}`
> **Chain:** {chain} · **Amount:** {amount} {currency}
> **To:** `{to}`
> 🔗 {explorer_link}

Explorer links by chain:
- Ethereum mainnet: `https://etherscan.io/tx/{hash}`
- Sepolia: `https://sepolia.etherscan.io/tx/{hash}`
- Base / Base Sepolia: `https://sepolia.basescan.org/tx/{hash}`
- Solana mainnet: `https://solscan.io/tx/{hash}`
- Solana devnet: `https://solscan.io/tx/{hash}?cluster=devnet`

**If response has `"status":"pending_approval"`**: follow the **Approval Polling Flow** (Section 12).

### 6. ERC-20 Token Transfer

Use this when the user asks to send an ERC-20 token (e.g. USDC, WETH, USDT).

> ⚠️ **CRITICAL**: When sending ERC-20 tokens you MUST include the `token` field in the request body.
> Omitting `token` will send **native ETH** instead — a completely different transaction that costs
> real ETH and cannot be reversed. Always double-check that your curl `-d` payload contains `"token": {...}`.

**Step 1 — Ensure the contract is whitelisted** (see Section 7):
```bash
curl -s "${TEE_WALLET_API_URL}/api/wallets/<id>/contracts" \
  -H "Authorization: Bearer ${TEE_WALLET_API_KEY}"
```
If the contract is not in the list, you can propose adding it via API key (creates a pending approval — see Section 7):
```bash
curl -s -X POST "${TEE_WALLET_API_URL}/api/wallets/<id>/contracts" \
  -H "Authorization: Bearer ${TEE_WALLET_API_KEY}" \
  -H "Content-Type: application/json" \
  -d '{"contract_address":"<0x...>","symbol":"<SYMBOL>","decimals":<N>}'
```
Then follow the approval polling flow (Section 12, `contract_add` type). Alternatively, direct the user to add it immediately via Web UI (Passkey required):
> ⚠ The contract `0x…` is not yet whitelisted. Requesting approval to add it… (or open Web UI → Contracts tab → Add to Whitelist for instant approval)

**Step 2 — Show confirmation and wait:**

> 🔍 **Confirm ERC-20 Transfer**
> **Token:** {symbol} (`{contract}`)
> **From:** `{wallet_address}`
> **To:** `{recipient}`
> **Amount:** {amount} {symbol}
>
> Confirm? (yes / no)

**Step 3 — Call `/transfer` with the `token` field:**
```bash
curl -s -X POST "${TEE_WALLET_API_URL}/api/wallets/<id>/transfer" \
  -H "Authorization: Bearer ${TEE_WALLET_API_KEY}" \
  -H "Content-Type: application/json" \
  -d '{
    "to": "<recipient_address>",
    "amount": "<human-readable amount, e.g. 100>",
    "token": {
      "contract": "<contract_address_lowercase>",
      "symbol": "<e.g. USDC>",
      "decimals": <e.g. 6>
    }
  }'
```

The amount is **in token units** (e.g. `100` for 100 USDC — the backend converts to raw units).

**Response handling** is identical to native transfer (Section 5) — include explorer link on success.

**Common ERC-20 token parameters:**

Ethereum Mainnet:
| Token | Contract | Decimals |
|-------|----------|----------|
| USDC  | `0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48` | 6 |
| USDT  | `0xdac17f958d2ee523a2206206994597c13d831ec7` | 6 |
| WETH  | `0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2` | 18 |
| DAI   | `0x6b175474e89094c44da98b954eedeac495271d0f` | 18 |

Sepolia Testnet:
| Token | Contract | Decimals | Faucet |
|-------|----------|----------|--------|
| USDC  | `0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238` | 6 | https://faucet.circle.com |
| WETH  | `0xfFf9976782d46CC05630D1f6eBAb18b2324d6B14` | 18 | swap ETH→WETH on Uniswap |
| LINK  | `0x779877A7B0D9E8603169DdbD7836e478b4624789` | 18 | https://faucets.chain.link/sepolia |

Base Sepolia Testnet:
| Token | Contract | Decimals | Faucet |
|-------|----------|----------|--------|
| USDC  | `0x036CbD53842c5426634e7929541eC2318f3dCF7e` | 6 | https://faucet.circle.com |
| WETH  | `0x4200000000000000000000000000000000000006` | 18 | swap ETH→WETH on Uniswap |

### 7. Manage Contract Whitelist

The contract whitelist is a **security gate**: only pre-registered contracts can be called via `/transfer`. Removing entries requires **Passkey hardware authentication**. Adding can be done by either:
- **Passkey session** (Web UI): applied immediately
- **API key**: creates a pending approval (HTTP 202) that the Passkey owner must approve

**List whitelisted contracts** (API key works for reading):
```bash
curl -s "${TEE_WALLET_API_URL}/api/wallets/<id>/contracts" \
  -H "Authorization: Bearer ${TEE_WALLET_API_KEY}"
```

**Add a contract via API key** (creates pending approval):
```bash
curl -s -X POST "${TEE_WALLET_API_URL}/api/wallets/<id>/contracts" \
  -H "Authorization: Bearer ${TEE_WALLET_API_KEY}" \
  -H "Content-Type: application/json" \
  -d '{
    "contract_address": "<0x...>",
    "symbol": "<e.g. USDC>",
    "decimals": <e.g. 6>,
    "label": "<optional label>"
  }'
```

A 202 response means the request is pending approval:
```json
{ "success": true, "pending": true, "approval_id": 7, "message": "Contract whitelist request submitted for approval" }
```

After receiving a 202 response, tell the user:
> 📋 **Contract whitelist request submitted** (Approval ID: {approval_id})
> **Contract:** `{contract_address}` ({symbol})
>
> The wallet owner must approve this via the Web UI before it can be used for ERC-20 transfers.
> [**→ Approve Request**]({TEE_WALLET_API_URL}/#/approve/{approval_id})

Then poll `GET /api/approvals/{approval_id}` every 15 seconds until `status` is `approved` or `rejected` (same as Section 12). Once `approved`, the contract is whitelisted and ERC-20 transfers can proceed.

**Add a contract via Passkey** (Web UI, applied immediately):
> Web UI → Wallets → select wallet → Contracts tab → Add to Whitelist.
> Fields: contract address (0x…), symbol (e.g. USDC), decimals (e.g. 6), optional label.

**Remove a contract** (Passkey session only):
> Web UI → Wallets → wallet → Contracts tab → ✕ button next to the contract.

**Why removing requires Passkey but adding can be proposed by API key**: An API key can only *propose* adding — the human wallet owner with hardware security must still approve. Removal is always Passkey-only since it's a more sensitive operation (accidentally removing could block legitimate transfers).

### 8. Delete Wallet

```bash
curl -s -X DELETE "${TEE_WALLET_API_URL}/api/wallets/<id>" \
  -H "Authorization: Bearer ${TEE_WALLET_API_KEY}"
```

Always confirm with user before deleting.

### 9. Check Balance

When the user asks for a wallet's balance, **show both native and token balances together** in one response.

**Step 1 — Native balance:**
```bash
curl -s "${TEE_WALLET_API_URL}/api/wallets/<id>/balance" \
  -H "Authorization: Bearer ${TEE_WALLET_API_KEY}"
```

> ⚠️ `/balance` returns the wallet's **native gas token** only (ETH / SOL). Never present this as a token balance.

**Step 2 — Build the global token list** (for Ethereum wallets):

The whitelist controls *sending*, not *receiving*. Any wallet can hold tokens that aren't on its own whitelist. To avoid missing balances, collect the **union of whitelisted contracts across all wallets on the same chain**, then query every target wallet against that global list.

```bash
# 1. Fetch all wallets
curl -s "${TEE_WALLET_API_URL}/api/wallets" \
  -H "Authorization: Bearer ${TEE_WALLET_API_KEY}"

# 2. For each wallet id, fetch its contracts (run in parallel)
curl -s "${TEE_WALLET_API_URL}/api/wallets/<id>/contracts" \
  -H "Authorization: Bearer ${TEE_WALLET_API_KEY}"
```

Deduplicate by `contract_address` to get the global token list. Then for each token in the list, query the target wallet's on-chain balance (see Section 9.1).

> ⚠️ **Never skip this step because a wallet's own whitelist is empty.** The whitelist only gates sending — a wallet can hold any token. Always use the global list.

**Present all balances together:**
> 💼 **Wallet** `0xabcd…1234` (Ethereum)
> ├ ETH: **0.482 ETH**
> ├ USDC: **250.00 USDC**
> └ USDT: **100.00 USDT**

**After a transfer**: the balance reflects the latest confirmed block. Wait ~15 seconds before checking:
```bash
sleep 15 && curl -s "${TEE_WALLET_API_URL}/api/wallets/<id>/balance" \
  -H "Authorization: Bearer ${TEE_WALLET_API_KEY}"
```

### 9.1. Check ERC-20 Token Balances On-Chain (Batch)

For ERC-20 balances, query each token contract with `balanceOf(address)` via JSON-RPC `eth_call`.
Use the **batch script** below to query all tokens for a wallet in one go.

**Do this whenever the user asks for a token balance. Do not rely on `/balance`.**

```python
python3 - <<'PY'
import json, urllib.request, os

# --- Configure these ---
wallet = "<wallet_address>"
tokens = [
    # (contract_address_lowercase, symbol, decimals)
    # Fill from the global token list (union of all wallet whitelists)
    ("0x1c7d4b196cb0c7b01d743fbc6116a902379c7238", "USDC", 6),
    # add more as needed...
]
rpcs = [
    os.environ.get("ETH_RPC_URL", ""),
    "https://ethereum-sepolia-rpc.publicnode.com",
    "https://rpc.sepolia.org",
    "https://sepolia.gateway.tenderly.co",
]
rpcs = [r for r in rpcs if r]  # remove empty

def call_rpc(rpc, contract, wallet_addr):
    data = {
        "jsonrpc": "2.0", "id": 1, "method": "eth_call",
        "params": [{"to": contract,
                    "data": "0x70a08231000000000000000000000000" + wallet_addr[2:].lower()},
                   "latest"]
    }
    req = urllib.request.Request(
        rpc, data=json.dumps(data).encode(),
        headers={"Content-Type": "application/json", "User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=15) as r:
        return json.load(r)

for contract, symbol, decimals in tokens:
    raw = None
    for rpc in rpcs:
        try:
            resp = call_rpc(rpc, contract, wallet)
            raw = int(resp["result"], 16)
            break
        except Exception:
            continue
    if raw is None:
        print(f"{symbol}: RPC_ERROR")
    elif raw == 0:
        pass  # skip zero balances
    else:
        print(f"{symbol}: {raw / 10**decimals:.6f}".rstrip('0').rstrip('.'))
PY
```

Only print tokens with balance > 0 to keep output clean.

Fallback RPC strategy:
1. Try `ETH_RPC_URL` if configured
2. Retry against public endpoints for the same chain
3. Only report a balance once an RPC call succeeds
4. If all RPCs fail, say the chain query failed — do **not** guess

Public Sepolia fallbacks: `https://ethereum-sepolia-rpc.publicnode.com`, `https://rpc.sepolia.org`, `https://sepolia.gateway.tenderly.co`

### 10. Set Approval Policy

Each wallet can have one policy **per currency** (ETH, USDC, SOL, etc.).

```bash
curl -s -X PUT "${TEE_WALLET_API_URL}/api/wallets/<id>/policy" \
  -H "Authorization: Bearer ${TEE_WALLET_API_KEY}" \
  -H "Content-Type: application/json" \
  -d '{
    "threshold_amount": "<amount>",
    "currency": "<ETH|USDC|SOL|…>",
    "enabled": true,
    "daily_limit": "<optional: max total spend per UTC day>"
  }'
```

- `threshold_amount`: single transaction above this amount requires Passkey approval
- `daily_limit` (optional): cumulative spend per UTC calendar day; if this would be exceeded the transfer is **hard-blocked** (no approval path)
- Run the command once per currency to configure each policy independently

Ask user for the threshold amount if not specified. If they also want a daily cap, ask for `daily_limit`.

**When called with an API key**, the policy change is **not applied immediately** — it creates a pending approval request (HTTP 202) that the wallet owner must approve via Passkey:

```json
{ "success": true, "pending": true, "approval_id": 42, "message": "Policy change submitted for approval" }
```

After receiving a 202 response, tell the user:
> 🔐 **Policy change submitted** (Approval ID: {approval_id})
> **Currency:** {currency} · **New threshold:** {threshold_amount} {currency}
> **Daily limit:** {daily_limit or "—"}
>
> The wallet owner must approve this change via the Web UI before it takes effect.
> [**→ Approve Policy Change**]({TEE_WALLET_API_URL}/#/approve/{approval_id})

Then poll `GET /api/approvals/{approval_id}` every 15 seconds until `status` is `approved` or `rejected`:
- `approved` → "✅ Policy applied. Transfers above {threshold} {currency} now require Passkey approval."
- `rejected` → "🚫 Policy change rejected. No changes were made."

**When called with a Passkey session** (Web UI), the policy is applied immediately and returns HTTP 200.

### 11. View Pending Approvals

```bash
curl -s "${TEE_WALLET_API_URL}/api/approvals/pending" \
  -H "Authorization: Bearer ${TEE_WALLET_API_KEY}"
```

Show: wallet, amount, currency, created time, expiry, approval link.

### 12. Approval Polling Flow

Use this whenever:
- A `/sign` or `/transfer` response has `"status":"pending_approval"`, **or**
- A `PUT /policy` response returns HTTP 202 (`"pending": true`), **or**
- A `POST /contracts` response returns HTTP 202 (`"pending": true`)

**1. Immediately show the summary:**

For transfer/sign:
> 🔐 **Approval required** (ID: {approval_id})
> **From:** `{from}`  →  **To:** `{to}`
> **Amount:** {amount} {currency}
> **Memo:** {memo or "—"}
> **Expires in:** 30 minutes
> [**→ Approve with Passkey**]({TEE_WALLET_API_URL}/#/approve/{approval_id})

For policy change:
> 🔐 **Policy change pending approval** (ID: {approval_id})
> **Currency:** {currency} · **New threshold:** {threshold_amount}
> **Daily limit:** {daily_limit or "—"}
> [**→ Approve with Passkey**]({TEE_WALLET_API_URL}/#/approve/{approval_id})

**2. Poll every 15 seconds** until resolved or 25 minutes elapsed:

```bash
curl -s "${TEE_WALLET_API_URL}/api/approvals/<approval_id>" \
  -H "Authorization: Bearer ${TEE_WALLET_API_KEY}"
```

After each poll, show progress:
> ⏳ Waiting for approval… (~{N} min remaining)

**3. Handle result by `approval_type`:**

Transfer / sign (`approval_type` is `"transfer"` or `"sign"`):
- `"status":"approved"` with `"tx_hash"` → show success + explorer link (same format as Section 5)
- `"status":"approved"` without `tx_hash` → show signature (sign-only requests)

Policy change (`approval_type` is `"policy_change"`):
- `"status":"approved"` → "✅ Policy applied. {currency} transfers above {threshold} now require Passkey approval."

Contract whitelist (`approval_type` is `"contract_add"`):
- `"status":"approved"` → "✅ Contract `{contract_address}` ({symbol}) has been added to the whitelist. ERC-20 transfers using this contract are now available."

All types:
- `"status":"rejected"` → "🚫 Approval rejected. No action was taken."
- `"status":"expired"` → "⏰ Approval expired. Please try again."
- After 25 min with no result → stop polling: "⚠️ Approval is taking longer than expected. Please check the Web UI."

### 13. View Operation History (Audit Log)

Users can view a history of all their past operations.

```bash
curl -s "${TEE_WALLET_API_URL}/api/audit/logs?page=1&limit=20" \
  -H "Authorization: Bearer ${TEE_WALLET_API_KEY}"
```

Optional query parameters:
- `page` (default: 1), `limit` (default: 20, max: 100)
- `action` — filter by action type (see below)
- `wallet_id` — filter by wallet

**Action types:**

| Action | Description |
|--------|-------------|
| `login` | Passkey login |
| `wallet_create` | Wallet created |
| `wallet_delete` | Wallet deleted |
| `transfer` | Transfer sent or pending approval |
| `sign` | Message signed or pending approval |
| `policy_update` | Approval policy set or pending |
| `approval_approve` | Approval request approved |
| `approval_reject` | Approval request rejected |
| `contract_add` | Contract added to whitelist or pending approval |
| `apikey_generate` | API key generated |
| `apikey_revoke` | API key revoked |

**Present as a list:**
> 📋 **Operation History**
>
> • `{time}` — {action label} ({status}) · {auth_mode} · {details summary}
> • …

Show status as ✅ for `success`, ⏳ for `pending`, ❌ for `failed`.

## Error Handling

Map common API errors to user-friendly messages:

| Error contains | User-facing message |
|---|---|
| `insufficient funds` | ❌ Insufficient ETH balance. Check your balance (including ~0.0005 ETH for gas). |
| `daily spend limit exceeded` | ❌ Daily {currency} spend limit reached. Limit resets at UTC midnight. |
| `contract not whitelisted` | ❌ This token contract isn't whitelisted. Request approval via API key (`POST /contracts`) or open Web UI → Wallets → Contracts tab → Add to Whitelist. |
| `wallet is not ready` | ⏳ Wallet is still being created. Wait a moment and try again. |
| `invalid API key` | ❌ Invalid API key. Check `TEE_WALLET_API_KEY` in your environment. |
| `approval has expired` | ⏰ The approval window expired (30 min). Please initiate the transfer again. |
| `pending_approval` on policy | 🔐 Policy change is pending Passkey approval. Share the approval link with the wallet owner. |
| any other error | Show the raw error message and suggest checking the API URL and key. |

## Rules

1. Never display or ask for private keys — they don't exist outside TEE hardware
2. **Always confirm with user** before signing or transferring — use the standard confirmation block
3. When creating ETH wallets, tell the user it may take 1-2 minutes
4. Present addresses in their native format (0x... for ETH, base58 for Solana)
5. **Always use Smart Wallet Selection** — never ask for wallet ID directly
6. When showing balances, include the currency symbol and label (e.g. `ETH balance`, `USDC balance`)
7. Approval (approve/reject actions) can ONLY be done through the Web UI — each approval requires fresh hardware Passkey authentication at the moment of approval (not just a session token)
8. If an API call fails, map to a user-friendly error (see Error Handling above)
9. **ERC-20**: always verify the contract is whitelisted before sending; if not, propose adding it via API key (`POST /contracts`) or direct user to Web UI for instant approval
10. **ERC-20 amounts**: the `amount` field is in human-readable token units (e.g. `100` for 100 USDC), NOT raw wei
11. **ERC-20 `token` field is mandatory**: sending without `token` sends native ETH — always include `"token":{"contract":"...","symbol":"...","decimals":...}`
12. **Never confuse native balance with token balance**: `/balance` is for ETH/SOL only; use `eth_call balanceOf` for ERC-20
13. **Use RPC fallback for token checks**: retry multiple RPC endpoints before reporting unavailable
14. **Always include explorer link** after a successful transfer
15. **Poll with countdown**: when waiting for approval, show remaining time on each poll update
16. **Follow Smart Wallet Selection rules at all times**: refresh `/api/wallets` before account-wide views, never report balances for deleted wallets, hide raw wallet ids in normal UX, and interpret numeric references as list indices unless the user explicitly says `id=...` (see Smart Wallet Selection section for full details).
17. **Policy changes via API key always need approval**: `PUT /policy` with an API key returns 202 and creates a pending approval — always follow the Approval Polling Flow (Section 12) and share the approval link with the wallet owner.
18. **Contract whitelist proposals via API key**: `POST /contracts` with an API key returns 202 — follow the Approval Polling Flow (Section 12, `contract_add` type) and share the approval link. The passkey owner must approve before the contract can be used.
19. **Approve/reject is hardware-protected**: each approve or reject action requires a fresh hardware Passkey assertion at that moment — a stolen session token alone cannot approve. The Web UI handles this automatically.
20. **Audit log available**: users can check their operation history via `GET /api/audit/logs` (Section 13).
21. **Global token list for balances**: when checking balances, always collect the union of whitelisted contracts across all wallets on the same chain. Apply this global list when querying any wallet — the whitelist gates sending, not holding. Never skip token queries because a specific wallet's whitelist is empty.
