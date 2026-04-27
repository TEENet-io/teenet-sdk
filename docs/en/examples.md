# Examples

Repository examples live under [`go/examples/`](https://github.com/TEENet-io/teenet-sdk/tree/main/go/examples) and [`typescript/examples/`](https://github.com/TEENet-io/teenet-sdk/tree/main/typescript/examples).

## By category

### Getting started

| Example | Language | What it shows |
|---|---|---|
| [`basic/simple`](https://github.com/TEENet-io/teenet-sdk/tree/main/go/examples/basic/simple) | Go | Minimal sign + verify CLI |
| [`basic/voting`](https://github.com/TEENet-io/teenet-sdk/tree/main/go/examples/basic/voting) | Go | Multi-party M-of-N voting flow |
| [`basic/forwarding`](https://github.com/TEENet-io/teenet-sdk/tree/main/go/examples/basic/forwarding) | Go | Cross-node request forwarding |
| [`generate-key`](https://github.com/TEENet-io/teenet-sdk/tree/main/go/examples/generate-key) | Go | Generate new threshold keys |
| [`typescript-test`](https://github.com/TEENet-io/teenet-sdk/tree/main/typescript/examples/typescript-test) | TypeScript | Integration test harness |

### API keys & HMAC

| Example | Language | What it shows |
|---|---|---|
| [`apikey`](https://github.com/TEENet-io/teenet-sdk/tree/main/go/examples/apikey) | Go | Store API secrets and sign HMAC payloads inside the TEE |

### Passkey approval

| Example | Language | What it shows |
|---|---|---|
| [`passkey-web-demo`](https://github.com/TEENet-io/teenet-sdk/tree/main/go/examples/passkey-web-demo) | Go + browser | WebAuthn-based approval of signing requests |

### Voting UI

| Example | Language | What it shows |
|---|---|---|
| [`voting-demo`](https://github.com/TEENet-io/teenet-sdk/tree/main/go/examples/voting-demo) | Go + browser | Interactive M-of-N voting dashboard |

### Real applications

| Example | Language | What it shows |
|---|---|---|
| [`teenet-wallet`](https://github.com/TEENet-io/teenet-wallet) | Go | A complete Passkey-protected crypto wallet built on the SDK (separate repo) |
| [`finance-console`](https://github.com/TEENet-io/finance-console) | Go | Finance dashboard sample (separate repo) |
| [`admin`](https://github.com/TEENet-io/teenet-sdk/tree/main/go/examples/admin) | Go | Invite passkey users, upsert permission policies, manage API keys |

## Running examples

Most examples expect either:

- a live TEENet service (`SERVICE_URL` + `APP_INSTANCE_ID` in env), **or**
- the [mock server](mock-server.md) running on `:8089`

Several examples include README files with specific setup steps.
