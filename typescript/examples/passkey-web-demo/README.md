# Passkey Web Demo (SDK-backed)

This example is a runnable test app:

- Backend: Node + TypeScript using `@teenet/sdk`
- Frontend: Browser page running WebAuthn (Passkey) and calling backend APIs

Flow covered by this demo:

`Sign(auto-init approval) -> Passkey login -> pending -> request challenge/confirm -> task challenge/action -> my requests/signature query`

## 1. Setup

```bash
cd /home/sun/tee/teenet-sdk/typescript/examples/passkey-web-demo
npm install
```

Environment variables:

```bash
export SERVICE_URL=http://127.0.0.1:8089
export DEMO_HOST=127.0.0.1
export DEMO_PORT=18090
export APP_INSTANCE_ID=<your-app-instance-id>
# Optional: preset an approval token
# export APPROVAL_TOKEN=<token>
```

## 2. Start

```bash
npm run run
```

Expected logs:

```text
[passkey-web-demo] http://127.0.0.1:18090
[passkey-web-demo] SERVICE_URL=http://127.0.0.1:8089
[passkey-web-demo] APP_INSTANCE_ID=<your-app-instance-id>
```

Open:

- `http://127.0.0.1:18090`
- React UI: `http://127.0.0.1:18090/react.html`

## 3. Test Steps (button order)

1. `Passkey Login`
2. `Sign (Auto Init Approval)`
3. `Get Pending`
4. `Challenge + Confirm`
5. `Challenge + Action`
6. `Refresh My Requests` (initiator view)
7. `Query Signature` (query by `tx_id`, useful for initiator)

Each step result is shown in the `Result` panel, and each button also shows success/failure under it.

## 4. Notes

- `app-comm-consensus` must be running, and passkey/approval policy must be configured.
- Browser must support WebAuthn (localhost over HTTP usually works for local dev).
- `APP_INSTANCE_ID` is read from backend env (no manual input on page).
- Initiator does not call manual request init; backend uses SDK `sign(...)` and approval is auto-initialized by policy.

## 5. About SDK High-Level Helpers

In `@teenet/sdk`, these helpers are available:

- `passkeyLoginWithCredential(getCredential)`
- `approvalRequestConfirmWithCredential(requestId, getCredential, approvalToken)`
- `approvalActionWithCredential(taskId, action, getCredential, approvalToken)`

They orchestrate API sequence in SDK.  
WebAuthn itself (`navigator.credentials.get/create`) still runs in browser/app code.
