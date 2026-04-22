# Quick Start

Install the SDK, point it at a TEENet service URL, and sign your first message. Click **Go** or **TypeScript** below to switch language.

---

## 1. Install

<!-- tabs:start -->

#### **Go**

```bash
go get github.com/TEENet-io/teenet-sdk/go
```

#### **TypeScript**

```bash
npm install @teenet/sdk
```

<!-- tabs:end -->

---

## 2. Sign a message

Containers deployed by the TEENet App Lifecycle Manager already have `SERVICE_URL` and `APP_INSTANCE_ID` injected in the environment — the SDK picks them up automatically. For local development, pass the URL explicitly.

<!-- tabs:start -->

#### **Go**

```go
package main

import (
    "context"
    "fmt"
    "log"

    sdk "github.com/TEENet-io/teenet-sdk/go"
)

func main() {
    ctx := context.Background()

    // Reads SERVICE_URL and APP_INSTANCE_ID from env.
    client := sdk.NewClient()
    defer client.Close()

    // Local dev alternative:
    // client := sdk.NewClient("http://localhost:8089")
    // client.SetDefaultAppInstanceID("my-app-instance")

    result, err := client.Sign(ctx, []byte("hello, teenet"), "my-key")
    if err != nil || !result.Success {
        log.Fatalf("sign failed: %v %s", err, result.Error)
    }
    fmt.Printf("signature: %x\n", result.Signature)

    ok, _ := client.Verify(ctx, []byte("hello, teenet"), result.Signature, "my-key")
    fmt.Printf("valid: %v\n", ok)
}
```

#### **TypeScript**

```ts
import { Client } from '@teenet/sdk';

async function main() {
    // Reads SERVICE_URL and APP_INSTANCE_ID from process.env.
    const client = new Client();

    // Local dev alternative:
    // const client = new Client('http://localhost:8089');
    // client.setDefaultAppInstanceID('my-app-instance');

    const message = Buffer.from('hello, teenet');
    const result  = await client.sign(message, 'my-key');
    if (!result.success) throw new Error(`${result.error} (${result.errorCode})`);
    console.log('signature:', result.signature.toString('hex'));

    const ok = await client.verify(message, result.signature, 'my-key');
    console.log('valid:', ok);

    client.close();
}

main();
```

<!-- tabs:end -->

---

## 3. Run it locally with the mock server

The mock server simulates TEENet with real cryptographic signing — no real TEE, no network, perfect for unit tests and local dev.

```bash
cd mock-server
make build && make run
# listens on :8089 with pre-configured test keys
```

Point your client at `http://localhost:8089` and run the example above. The mock ships with 8 preconfigured app instances (`mock-app-id-01` through `mock-app-id-08`) covering every protocol/curve combination — all under the key name `default`. So to run the snippet above against the mock, set:

```bash
export SERVICE_URL=http://localhost:8089
export APP_INSTANCE_ID=mock-app-id-01   # Schnorr/ED25519, direct signing
```

and replace `"my-key"` in the snippet with `"default"`.

See [Mock Server](mock-server.md) for details.

---

## Next

- [**API Reference**](api.md) — full method surface for Go and TypeScript
- [**Examples**](examples.md) — end-to-end samples (voting UI, passkey web demo, wallets, etc.)
