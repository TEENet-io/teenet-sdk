# 快速上手

安装 SDK,指向 TEENet 服务地址,完成首次签名。点击下方 **Go** 或 **TypeScript** 切换语言。

---

## 1. 安装

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

## 2. 签名一条消息

由 TEENet App Lifecycle Manager 部署的容器已经在环境变量里注入了 `SERVICE_URL` 和 `APP_INSTANCE_ID` —— SDK 会自动读取。本地开发时,显式传 URL 即可。

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

    // 自动从环境变量读取 SERVICE_URL 和 APP_INSTANCE_ID。
    client := sdk.NewClient()
    defer client.Close()

    // 本地开发时:
    // client := sdk.NewClient("http://localhost:8089")
    // client.SetDefaultAppInstanceID("my-app-instance")

    result, err := client.Sign(ctx, []byte("hello, teenet"), "my-key")
    if err != nil || !result.Success {
        log.Fatalf("签名失败: %v %s", err, result.Error)
    }
    fmt.Printf("签名: %x\n", result.Signature)

    ok, _ := client.Verify(ctx, []byte("hello, teenet"), result.Signature, "my-key")
    fmt.Printf("校验结果: %v\n", ok)
}
```

#### **TypeScript**

```ts
import { Client } from '@teenet/sdk';

async function main() {
    // 自动从 process.env 读取 SERVICE_URL 和 APP_INSTANCE_ID。
    const client = new Client();

    // 本地开发时:
    // const client = new Client('http://localhost:8089');
    // client.setDefaultAppInstanceID('my-app-instance');

    const message = Buffer.from('hello, teenet');
    const result  = await client.sign(message, 'my-key');
    if (!result.success) throw new Error(`${result.error} (${result.errorCode})`);
    console.log('签名:', result.signature.toString('hex'));

    const ok = await client.verify(message, result.signature, 'my-key');
    console.log('校验结果:', ok);

    client.close();
}

main();
```

<!-- tabs:end -->

---

## 3. 用 Mock Server 本地跑

Mock Server 用真实密码学实现模拟 TEENet —— 没有真实 TEE、没有网络、适合单元测试和本地开发。

```bash
cd mock-server
make build && make run
# 监听 :8089,内置测试密钥
```

将客户端指向 `http://localhost:8089`,运行上面的示例即可。

详见 [Mock Server](zh/mock-server.md)。

---

## 下一步

- [**API 参考**](zh/api.md) —— Go 和 TypeScript 的完整方法集
- [**示例**](zh/examples.md) —— 端到端示例(投票 UI、Passkey Web 示例、钱包等)
