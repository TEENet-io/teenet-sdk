# Mock Server

The mock server simulates the TEENet `app-comm-consensus` service for local development and testing. It uses **real cryptographic signing** — the output is verifiable with the same code path as production — but runs without a TEE, without the TEE-DAO cluster, and without any external dependencies.

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

The mock ships with ready-to-use app instances for every supported protocol + curve combination:

| App Instance ID | Protocol | Curve |
|---|---|---|
| `test-schnorr-ed25519` | Schnorr | ED25519 |
| `test-schnorr-secp256k1` | Schnorr (BIP-340) | SECP256K1 |
| `test-ecdsa-secp256k1` | ECDSA | SECP256K1 |
| `test-ecdsa-secp256r1` | ECDSA | SECP256R1 |

Point the SDK at `http://localhost:8089` and use any of the above as the `APP_INSTANCE_ID`. No key generation required — test keys are generated on startup.

## Endpoints

```
GET  /api/health
GET  /api/publickey/:app_instance_id
POST /api/submit-request
GET  /api/cache/:hash
POST /api/generate-key
GET  /api/apikey/:name
POST /api/apikey/:name/sign
```

The request/response shapes match the real `app-comm-consensus` service, so SDK code written against the mock works unchanged in production.

## Source

See [`mock-server/`](https://github.com/TEENet-io/teenet-sdk/tree/main/mock-server) in the repository — it's a small Gin application (~one file).
