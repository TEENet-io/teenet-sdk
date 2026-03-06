# Passkey Web Demo (Go SDK)

This demo is the Go version of `typescript/examples/passkey-web-demo`.

- Backend: Go + `@teenet-sdk/go`
- Frontend: Browser page with WebAuthn (Passkey)
- Flow: sign(auto-init approval) -> login -> pending -> confirm -> action -> my requests/signature query

## 1) Setup

```bash
cd /home/sun/tee/teenet-sdk/go/examples
```

Required environment variables:

```bash
export CONSENSUS_URL=http://127.0.0.1:8089
export APP_INSTANCE_ID=<your-app-instance-id>
```

Optional:

```bash
export DEMO_HOST=127.0.0.1
export DEMO_PORT=18090
# Optional bootstrap token
# export APPROVAL_TOKEN=<token>
```

## 2) Run

```bash
go run ./passkey-web-demo
```

Expected logs:

```text
[go-passkey-web-demo] http://127.0.0.1:18090
[go-passkey-web-demo] CONSENSUS_URL=http://127.0.0.1:8089
[go-passkey-web-demo] APP_INSTANCE_ID=<your-app-instance-id>
```

Open in browser:

- `http://127.0.0.1:18090`

## 3) Notes

- This demo keeps approval token per browser session (`X-Demo-Session`/cookie).
- `app_instance_id` is injected from backend env `APP_INSTANCE_ID`.
- Initiator does not call approval init manually; the page submits `Sign` and backend auto-initiates approval.
- Query My Requests and Query Signature both proxy through consensus APIs.
- WebAuthn runs in browser; SDK orchestrates API calls only.
