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
const client = new Client('http://localhost:8089');
client.setDefaultAppID('your-app-id');

// Sign a message
const message = Buffer.from('Hello, TEENet!');
const result = await client.sign(message);

if (result.success) {
    console.log('Signature:', result.signature.toString('hex'));
}

// Verify a signature
const valid = await client.verify(message, result.signature);
console.log('Valid:', valid);

// Generate a new key
const keyResult = await client.generateECDSAKey(Curve.SECP256K1);
console.log('Key ID:', keyResult.publicKey.id);

// Sign with generated key
const pubKeyBytes = Buffer.from(keyResult.publicKey.keyData, 'hex');
const signResult = await client.sign(message, pubKeyBytes);

// Get API key
const apiKeyResult = await client.getAPIKey('my-api-key');
console.log('API Key:', apiKeyResult.apiKey);

// Sign with API secret
const hmacResult = await client.signWithAPISecret('my-secret', message);
console.log('HMAC Signature:', hmacResult.signature);

// Clean up
client.close();
```

## API

### Client

#### Constructor

```typescript
new Client(consensusURL: string, options?: ClientOptions)
```

Options:
- `requestTimeout`: Request timeout in milliseconds (default: 30000)
- `callbackTimeout`: Callback timeout in milliseconds (default: 60000)

#### Methods

| Method | Description |
|--------|-------------|
| `setDefaultAppID(appID)` | Set the default application ID |
| `getDefaultAppID()` | Get the current default App ID |
| `sign(message, publicKey?)` | Sign a message |
| `verify(message, signature)` | Verify a signature |
| `verifyWithPublicKey(message, signature, publicKey, protocol, curve)` | Verify with specific key |
| `getPublicKey()` | Get public key for default App ID |
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

Copyright (c) 2025 TEENet Technology (Hong Kong) Limited. All Rights Reserved.
