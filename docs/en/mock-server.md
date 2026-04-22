# Mock Server

The mock server simulates the TEENet signing service for local development and testing. It uses **real cryptographic signing** — the output is verifiable with the same code path as production — but runs without a TEE, without the TEE-DAO cluster, and without any external dependencies.

## Run it

```bash
cd mock-server
make build && make run
# listens on :8089
```

Or override the port:

```bash
MOCK_SERVER_PORT=9000 ./mock-server
```

## What's preconfigured

The mock ships with 8 ready-to-use app instances covering every supported protocol + curve combination, plus M-of-N voting and Passkey approval:

| App Instance ID | Protocol | Curve | Notes |
|---|---|---|---|
| `mock-app-id-01` | Schnorr | ED25519 | direct signing |
| `mock-app-id-02` | Schnorr (BIP-340) | SECP256K1 | direct signing |
| `mock-app-id-03` | ECDSA | SECP256K1 | direct signing |
| `mock-app-id-04` | ECDSA | SECP256R1 | direct signing |
| `mock-app-id-05` | ECDSA | SECP256K1 | 2-of-3 voting (voter 1) |
| `mock-app-id-06` | ECDSA | SECP256K1 | 2-of-3 voting (voter 2) |
| `mock-app-id-07` | ECDSA | SECP256K1 | 2-of-3 voting (voter 3) |
| `mock-app-id-08` | ECDSA | SECP256K1 | requires Passkey approval |

Point the SDK at `http://localhost:8089` and use any of the above as the `APP_INSTANCE_ID`. No key generation required — test keys are generated on startup under the key name `default`.

## Endpoints

```
GET  /api/health
GET  /api/publickeys/:app_instance_id
POST /api/submit-request
GET  /api/cache/:hash
POST /api/generate-key
GET  /api/apikey/:name
POST /api/apikey/:name/sign
```

The request/response shapes match the real signing service, so SDK code written against the mock works unchanged in production.

## Source

See [`mock-server/`](https://github.com/TEENet-io/teenet-sdk/tree/main/mock-server) in the repository — it's a small Gin application (~one file).
