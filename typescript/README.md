# TEENet SDK for TypeScript

TypeScript/JavaScript SDK for TEENet cryptographic signing services.

## Installation

```bash
npm install @teenet/sdk
```

## Usage

```typescript
import { Client, Protocol, Curve } from '@teenet/sdk';

// Create client
const client = new Client('http://localhost:8089', {
  pendingWaitTimeout: 10000,  // max wait in sign() for voting completion
  debug: true,                // verbose sign/polling trace logs
});
client.setDefaultAppInstanceID('your-app-instance-id');

// Sign a message
const message = Buffer.from('Hello, TEENet!');
const result = await client.sign(message, 'my-key');

if (result.success) {
    console.log('Signature:', result.signature.toString('hex'));
}

// Verify a signature (only if signed)
if (result.success && result.signature.length > 0) {
    const valid = await client.verify(message, result.signature, 'my-key');
    console.log('Valid:', valid);
}

// Generate a new key
const keyResult = await client.generateECDSAKey(Curve.SECP256K1);
console.log('Key ID:', keyResult.publicKey.id);

// Sign with generated key
const signResult = await client.sign(message, keyResult.publicKey.name);

// Get API key
const apiKeyResult = await client.getAPIKey('my-api-key');
console.log('API Key:', apiKeyResult.apiKey);

// Sign with API secret
const hmacResult = await client.signWithAPISecret('my-secret', message);
console.log('HMAC Signature:', hmacResult.signature);

// Clean up
client.close();
```

### Sign Results

`sign()` is the single signing interface.
For voting apps, SDK waits internally and returns finalized signed/failed result.
`pendingWaitTimeout` controls the maximum wait time for voting completion.
Polling interval/backoff is managed internally by SDK.

```typescript
const result = await client.sign(message, 'my-key');
if (result.success) {
    console.log('Signature:', result.signature.toString('hex'));
} else {
    console.error('Sign failed:', result.error, result.errorCode);
}
```

`result.errorCode` values:

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

### Passkey Approval (New Flow)

```typescript
const getCredential = async (options: unknown) => {
  // Browser-side WebAuthn call (app responsibility)
  // example: navigator.credentials.get(options as CredentialRequestOptions)
  return {};
};

// 0) Passkey login (SDK orchestrates options + verify)
const loginVerify = await client.passkeyLoginWithCredential(getCredential);
if (!loginVerify.success) throw new Error(loginVerify.error || 'passkey login failed');
const approvalToken = String(loginVerify.data?.token || '');
if (!approvalToken) throw new Error('missing approval token');

// Optional: pending approvals for current passkey identity
const pending = await client.approvalPending(approvalToken);

// Optional: filter by app + key name
const filtered = await client.approvalPending(approvalToken, {
  applicationId: 42,
  publicKeyName: 'pk-alpha',
});

// 1) Init request
const init = await client.approvalRequestInit({
  app_instance_id: 'd38b86ff601b3ba5c5ed2ba526ffcbbc',
  payload: { to: '0x1234', amount: '1' }
}, approvalToken);
if (!init.success) throw new Error(init.error);
const requestId = Number(init.data?.request_id);

// 2) Confirm request (SDK orchestrates challenge + confirm)
const confirm = await client.approvalRequestConfirmWithCredential(requestId, getCredential, approvalToken);
const taskId = Number(confirm.data?.task_id);

// 3) Task action (SDK orchestrates challenge + action)
await client.approvalActionWithCredential(taskId, 'APPROVE', getCredential, approvalToken);
```

Notes:
- SDK can orchestrate request/response flow.
- WebAuthn execution (`navigator.credentials.create/get`) still runs in browser/app code.
- SDK does not own UI interaction.

## API

### Client

#### Constructor

```typescript
new Client(consensusURL: string, options?: ClientOptions)
```

Options:
- `requestTimeout`: Request timeout in milliseconds (default: 30000)
- `pendingWaitTimeout`: Max wait in `sign()` when voting is pending, milliseconds (default: 10000)
- `debug`: Enable verbose sign/polling trace logs (default: false)

#### Methods

| Method | Description |
|--------|-------------|
| `setDefaultAppInstanceID(appInstanceID)` | Set the default application instance ID |
| `getDefaultAppInstanceID()` | Get the current default App Instance ID |
| `sign(message, publicKeyName)` | Sign a message with bound key name |
| `getStatus(hash)` | Get voting status from consensus cache |
| `passkeyLoginOptions()` | Get passkey login options |
| `passkeyLoginVerify(loginSessionId, credential)` | Verify passkey login and return approval token |
| `approvalPending(approvalToken, filter?)` | Get pending approvals for current token identity, optionally filtered by app/key |
| `approvalRequestInit(payload, approvalToken)` | Init passkey approval request |
| `approvalRequestChallenge(requestId, approvalToken)` | Get request challenge |
| `approvalRequestConfirm(requestId, payload, approvalToken)` | Confirm request assertion |
| `approvalRequestConfirmWithCredential(requestId, getCredential, approvalToken)` | Challenge + WebAuthn + confirm in one SDK call |
| `approvalActionChallenge(taskId, approvalToken)` | Get action challenge |
| `approvalAction(taskId, payload, approvalToken)` | Submit approval action |
| `approvalActionWithCredential(taskId, action, getCredential, approvalToken)` | Challenge + WebAuthn + action in one SDK call |
| `passkeyLoginWithCredential(getCredential)` | Login options + WebAuthn + verify in one SDK call |
| `verify(message, signature, publicKeyName)` | Verify a signature with bound key name |
| `getPublicKeys()` | Get all bound public keys for default App Instance ID |
| `generateECDSAKey(curve)` | Generate ECDSA key |
| `generateSchnorrKey(curve)` | Generate Schnorr key |
| `getAPIKey(name)` | Get API key by name |
| `signWithAPISecret(name, message)` | Sign with API secret |
| `close()` | Close the client |

### Constants

```typescript
// Protocols
Protocol.ECDSA    // 'ecdsa'
Protocol.Schnorr  // 'schnorr'

// Curves
Curve.ED25519     // 'ed25519'
Curve.SECP256K1   // 'secp256k1'
Curve.SECP256R1   // 'secp256r1'
```

### Standalone Verification

```typescript
import { verifySignature, verifyHMACSHA256 } from '@teenet/sdk';

// Verify cryptographic signature
const valid = verifySignature(message, publicKey, signature, 'ecdsa', 'secp256k1');

// Verify HMAC-SHA256
const hmacValid = verifyHMACSHA256(message, secret, signature);
```

## Supported Algorithms

| Protocol | Curve | Description |
|----------|-------|-------------|
| Schnorr | ED25519 | Edwards curve EdDSA |
| ECDSA | SECP256K1 | Bitcoin/Ethereum (Keccak-256 for 65-byte sigs) |
| Schnorr | SECP256K1 | BIP-340 Schnorr |
| ECDSA | SECP256R1 | NIST P-256 |

## License

Copyright (c) 2025-2026 TEENet Technology (Hong Kong) Limited.
