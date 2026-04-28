# Contributing to TEENet SDK

This project is in Developer Preview. APIs may still evolve, so keep changes
focused, document behavior clearly, and call out compatibility impact in pull
requests.

## Before You Start

- Open an issue first for large API changes, protocol behavior changes, or
  changes that affect both Go and TypeScript SDKs.
- Keep pull requests small enough to review. Split unrelated SDK, mock server,
  docs, and example changes into separate PRs when practical.
- Do not commit real keys, API secrets, passkey credentials, production app
  instance IDs, or private service URLs.
- Contributions are accepted under the project license, GPL-3.0. See
  [LICENSE](LICENSE).

## Repository Layout

| Path | Purpose |
|---|---|
| `go/` | Go SDK source, tests, and package README |
| `typescript/` | TypeScript SDK source, tests, and npm package metadata |
| `mock-server/` | Local TEENet mock service used for development and testing |
| `go/examples/` | Go examples and demo apps |
| `typescript/examples/` | TypeScript examples |
| `docs/` | Docsify documentation site, including English and Chinese docs |

## Prerequisites

- Go 1.24 or later
- Node.js 18 or later
- npm
- `make` for mock server helper targets
- `curl` and `jq` for the mock server smoke test target

## Local Development

There is no top-level build command. Work inside the module you are changing.

### Go SDK

```bash
cd go
go test ./...
```

Use `gofmt` on changed Go files before submitting.

### TypeScript SDK

```bash
cd typescript
npm ci
npm run build
npm test
```

Generated `typescript/dist/` output is ignored and should not be committed.

### Mock Server

```bash
cd mock-server
make gotest
make run
```

In another shell, smoke-test a running server:

```bash
cd mock-server
make test
```

The mock server listens on port `8089` by default and ships with test app
instances `mock-app-id-01` through `mock-app-id-08`. Use the key name `default`
unless a specific example says otherwise.

### Documentation

The docs site is static Docsify content. To preview it locally:

```bash
python3 -m http.server 3000 --directory docs
```

Then open `http://localhost:3000`.

When changing shared documentation, update both English and Chinese pages when
the same content exists in both locations. Before submitting docs changes,
verify that repository links point to paths that exist.

## Testing With the Mock Server

For local SDK examples, start the mock server and use:

```bash
export SERVICE_URL=http://localhost:8089
export APP_INSTANCE_ID=mock-app-id-01
```

Use `mock-app-id-01` for Schnorr/ED25519 direct signing. Other mock app
instances cover BIP-340 Schnorr, ECDSA curves, M-of-N voting, and Passkey
approval; see [mock-server/README.md](mock-server/README.md).

## Compatibility Expectations

- Keep the Go and TypeScript SDK behavior aligned when changing shared API
  concepts, response fields, error codes, protocols, or curves.
- Preserve stable error codes. If an error code changes or a new one is added,
  update SDK types, docs, and `docs/error-codes.contract.json`.
- Update README snippets, API docs, and examples when changing public behavior.
- For ECDSA signing behavior, keep the hashing responsibility explicit in docs:
  callers pass a 32-byte hash; Schnorr and EdDSA callers pass the raw message.

## Pull Request Checklist

Before opening a PR, check the items that apply:

- Go changes: `cd go && go test ./...`
- TypeScript changes: `cd typescript && npm ci && npm run build && npm test`
- Mock server changes: `cd mock-server && make gotest`
- Docs changes: preview the docs site locally and verify changed links
- Public API changes: update README, docs, examples, and package-level README
- Error code changes: update the error code contract file
- Generated files, local build artifacts, logs, and secrets are not included

## Security Issues

Do not open public issues for vulnerabilities or suspected key-handling
problems. Use GitHub private vulnerability reporting if it is enabled for the
repository, or contact the maintainers privately before publishing details.

