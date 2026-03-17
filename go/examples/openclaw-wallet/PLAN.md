# OpenClaw Wallet App — 部署在 TEE 网络上的钱包服务

## 项目概述

### 是什么

TEE Wallet 是一个部署在可信执行环境（TEE）mesh 网络中的多链加密钱包服务，专为 [OpenClaw](https://openclaw.ai/) AI 助手设计。它让 AI 助手能够以编程方式为用户管理链上资产——创建钱包、查询余额、构造并签名交易——同时通过 TEE 硬件技术确保私钥安全始终处于最高等级的保障之下。

支持链：**Ethereum（及 EVM 兼容链）**、**Solana**，后续可扩展 Bitcoin、Cosmos 等。

---

### 为什么要做

**Web3 操作体验的核心矛盾**：私钥/助记词的管理门槛极高，一旦泄露损失不可逆；而把私钥交给第三方托管，又意味着信任风险。两者之间一直缺少一个兼顾安全性与易用性的方案。

TEE Wallet 试图解决这个矛盾：

- **对用户**：不需要保存助记词，不需要安装浏览器插件，不需要手动管理 Gas。直接告诉 AI 助手"帮我把 0.5 ETH 转给 Alice"，剩下的事情交给系统。
- **对企业**：团队共管钱包，小额操作 AI 自动执行，大额操作强制人工审批，全程留有可查审计日志，合规成本大幅降低。
- **对开发者**：基于已有的 TEE-DAO 基础设施，通过 TEENet SDK 接入，无需重新设计密钥管理体系，快速构建安全可靠的链上应用。

---

### 核心安全理念：私钥永远不出硬件

这是本项目最根本的设计原则，也是区别于传统钱包方案的关键所在。

传统钱包（无论是软件钱包还是中心化托管）的共同问题是：私钥在某个时刻、某个地方是完整存在的，这意味着理论上存在被盗风险。

TEE Wallet 的方案完全不同：

1. **分布式密钥生成（DKG）**：用户创建钱包时，私钥从来不会以完整形式存在。TEE-DAO 集群中的多个节点各自生成一个密钥碎片，通过密码学协议共同确定公钥（即钱包地址），但没有任何一个节点持有完整私钥。

2. **阈值签名**：每次签名交易时，需要达到预设数量（阈值）的 TEE 节点共同参与计算，签名结果才能产生。即便攻击者控制了部分节点，也无法伪造签名。

3. **TEE 硬件隔离**：所有密钥碎片的存储和计算都发生在 TEE 安全硬件内，操作系统、云服务商、甚至平台运营方都无法访问这些数据。

4. **钱包应用零私钥**：运行在 TEE mesh 节点上的钱包 App 本身只持有公钥和链上地址，签名操作全部转发给 TEE-DAO 集群完成，即便钱包 App 容器被攻破，攻击者也拿不到任何私钥材料。

---

### 用户体验设计

整个系统针对两类场景设计了不同的交互方式：

**日常操作——AI 全程代劳**

用户通过 OpenClaw 聊天界面下达指令。AI 助手调用 API Key 完成钱包查询、余额查询、小额交易签名等操作，用户无需打开任何网页或安装任何工具。体验类似于"有一个懂区块链的私人助理帮你处理链上事务"。

**大额交易——Passkey 硬件审批**

当交易金额超过用户预设的阈值时，系统不会直接签名，而是：

1. AI 助手向用户展示完整的交易摘要（转账方、收款方、金额、备注）
2. 同时附上一个审批链接，提示用户在 Web 页面完成审批
3. 用户打开链接，使用 Passkey（手机指纹/面容/硬件密钥）完成身份验证并确认交易
4. 审批通过后，TEE 集群执行签名，AI 助手自动拿到签名结果并广播交易

Passkey 是 WebAuthn 标准的硬件认证方案，私钥存在用户的设备安全芯片中，无法被远程盗取，也无法被钓鱼网站骗走。**大额交易的最终控制权，始终在用户手中。**

---

### 适用场景

| 场景 | 价值 |
|------|------|
| **个人多链资产管理** | 告别助记词焦虑，AI 助手帮你管理 ETH、SOL 等多链资产，余额查询、转账一句话搞定 |
| **AI 代理自动化操作** | 设置定期转账、DeFi 策略执行、链上数据交互，AI 全自动完成，用户只需审批大额操作 |
| **团队共管钱包** | 日常小额支出 AI 自动处理，大额预算支出需要人工 Passkey 确认，天然满足财务合规要求 |
| **企业链上业务** | 合约调用、NFT 铸造、链上投票等场景，安全可审计，无需搭建独立的密钥管理基础设施 |

---

### 技术优势

- **基于现有 TEE 基础设施**：复用 TEE-DAO 分布式密钥管理集群和 TEENet SDK，无需从零构建密钥管理体系，安全性经过生产验证。
- **标准 REST API**：钱包服务对外暴露简洁的 HTTP API，任何 AI 助手或自动化脚本均可接入，不绑定特定技术栈。
- **轻量部署**：单个 Go 二进制 + SQLite，以 Docker 镜像方式部署到 TEE mesh 节点，资源占用极低，运维简单。
- **可扩展链支持**：链地址派生和余额查询模块按链独立实现，新增链支持只需扩展对应模块，不影响核心签名流程。
- **完整审计日志**：所有签名操作、审批记录均持久化存储，满足合规审计需求。

---

## Context

构建一个独立的 Go Web 应用，作为一个 Instance 部署在 UMS 的 TEE mesh 网络上。该应用通过 TEENet SDK 调用 app-comm-consensus 进行密钥生成和阈值签名，为 OpenClaw 用户提供多链钱包管理服务。

**私钥永远不出 TEE**——应用本身只持有公钥和地址，签名操作全部委托给 TEE-DAO 集群。

```
用户的 OpenClaw (本地)
  → HTTP → UMS proxy (/instance/{app_instance_id}/api/...)
      → Wallet App (TEE mesh 节点上的容器, :8080)
          → TEENet SDK → app-comm-consensus (:8089)
              → TEE-DAO (DKG / 阈值签名)
```

**位置**: `/home/sun/tee/teenet-sdk/go/examples/openclaw-wallet/`
**共享 go.mod**: `/home/sun/tee/teenet-sdk/go/examples/go.mod`（已有 `go-ethereum` 依赖）

---

## 详细方案

### 一、系统架构

整个系统由四层组成，每一层职责清晰、边界明确：

**第一层：用户终端（OpenClaw）**

用户通过 OpenClaw AI 助手下达自然语言指令。OpenClaw 内置 tee-wallet Skill 插件，负责将用户意图翻译成对钱包服务的 HTTP API 调用。用户无需了解区块链技术细节，所有链上操作由 AI 全权代理。

**第二层：UMS 代理层**

用户管理系统（UMS）作为反向代理，将外部请求转发至部署在 TEE mesh 节点上的钱包容器。所有流量通过 `/instance/{app_instance_id}/api/...` 路径路由，UMS 负责认证、限流和访问控制。

**第三层：钱包应用（本项目）**

一个轻量 Go Web 服务，运行在 TEE mesh 节点的 Docker 容器中，监听 8080 端口。负责处理业务逻辑：钱包管理、签名请求、审批策略判断、用户认证。本身不持有任何私钥材料，签名操作全部委托给下层。

**第四层：TEE 签名层**

由 app-comm-consensus 服务（每个 mesh 节点上运行）和 TEE-DAO 集群共同组成。钱包应用通过 TEENet SDK 向 app-comm-consensus 发起签名请求，后者协调 TEE-DAO 多节点完成阈值签名，返回签名结果。私钥碎片始终保存在 TEE 硬件内，全程不可见。

---

### 二、用户认证方案

本项目采用双轨认证设计，针对不同使用场景分别优化：

**轨道一：API Key 认证（面向 OpenClaw 日常操作）**

用户在 Web 页面完成 Passkey 注册后，可生成以 `ocw_` 开头的 API Key。该密钥配置到 OpenClaw 后，AI 助手在每次 API 调用时通过 HTTP Authorization 头携带。服务端对密钥做 SHA-256 哈希后查库验证，原始密钥仅在生成时展示一次，之后不再存储明文。API Key 支持多个并发，可单独吊销，适合长期自动化场景。

**轨道二：Passkey Session 认证（面向 Web UI 管理操作）**

Passkey 用户体系复用 UMS 已有的 WebAuthn 基础设施，无需重复建设。具体流程是：管理员通过 SDK 的邀请接口为用户生成注册链接，用户打开链接后使用设备的生物识别或硬件密钥完成 Passkey 凭证注册。后续登录时，服务端下发挑战（challenge），用户设备签名后提交验证，验证通过返回 session token。该 token 用于后续的管理操作和审批操作，有效期内免重复认证。

两种认证方式对下游业务处理器透明——无论哪种方式通过验证，都统一注入当前用户上下文，处理器无需区分。

**权限边界**

大额交易审批路由**只接受 Passkey session**，拒绝 API Key。这确保了即便 API Key 泄露，攻击者也无法通过编程方式批准大额转账，最终控制权始终由持有硬件 Passkey 的人掌握。

---

### 三、数据模型设计

本项目在本地 SQLite 数据库中维护四类核心数据，设计原则是只存必要信息，敏感数据不落库。

**用户表（User）**

记录每个用户的基本信息：用户名、对应的 UMS Passkey 用户 ID（用于关联 UMS 侧的凭证和审计记录）、API Key 的 SHA-256 哈希值（原始密钥不存储）、以及 API Key 的前缀（用于展示，方便用户识别）。一个用户可以有多个 API Key。

**钱包表（Wallet）**

记录每个钱包的链信息：所属用户、链名称（ethereum/solana）、TEE-DAO 分配的密钥名称（key name，是签名时的索引）、公钥原始数据（hex 格式）、派生出的链上地址、用户自定义标签、所用曲线和协议（secp256k1/ed25519，ecdsa/schnorr）、以及当前状态（creating/ready/error）。注意：没有任何私钥字段，私钥碎片在 TEE-DAO 侧管理。

**审批策略表（ApprovalPolicy）**

每个钱包可以绑定一条审批策略，记录：触发审批的金额阈值（字符串精度，避免浮点误差）、对应货币单位（ETH/SOL）、以及策略是否启用。策略与钱包一对一绑定。

**审批请求表（ApprovalRequest）**

每次触发审批时创建一条记录，包含：关联的钱包和用户、原始签名消息（hex）、完整的交易上下文（JSON 格式，含转账方、收款方、金额、货币、备注）、可选的 TxParams（链上广播参数，/transfer 路由使用）、当前状态（pending/approved/rejected/expired）、审批通过后填入的签名结果和交易哈希、审批人的 Passkey 用户 ID、创建时间和过期时间（默认 30 分钟后自动过期）。

**合约白名单表（AllowedContract）**

记录每个钱包被授权调用的 ERC-20 合约地址。包含：钱包 ID（外键）、合约地址（小写 hex，`0x` 开头）、代币符号（如 USDC）、精度（decimals，如 6）、可选标签、创建时间。对 (wallet_id, contract_address) 建有联合唯一索引，防止重复添加。只有 Passkey 认证可以写入此表——API Key 仅可读取，无法添加或删除，确保即便 API Key 泄露也无法授权恶意合约。

---

### 四、API 接口设计

接口按使用场景分为三组，权限要求各不相同。

**认证管理接口（Web UI 使用，Passkey 认证）**

- 邀请用户：管理员调用后，系统通过 SDK 向 UMS 发起邀请，返回注册链接
- Passkey 登录 challenge：返回 UMS 签发的 WebAuthn 挑战数据
- Passkey 登录验证：提交用户设备签名结果，验证通过后返回 session token
- 生成 API Key：在 Passkey session 下为当前用户生成新的 API Key，返回完整密钥（仅此一次）
- 查看 API Key 列表：返回当前用户的所有 API Key（只展示前缀，不展示原文）
- 吊销 API Key：删除指定 API Key

**钱包操作接口（API Key 或 Passkey，视路由而定）**

- 创建钱包：指定链名和标签，服务端调 SDK 生成密钥对，派生地址后入库（双认证）
- 列出/查看钱包：返回当前用户的钱包列表或单个钱包详情（双认证）
- 删除钱包：软删除钱包记录（双认证）
- 签名：原始消息签名，支持审批策略（双认证）
- Transfer：后端构造交易 + TEE 签名 + 广播上链；支持原生资产和 ERC-20（双认证）
- 获取公钥：返回钱包原始公钥（hex）（双认证）
- 查询余额：直接调链上 RPC，返回当前余额（双认证）
- 查看审批策略：返回当前策略配置（双认证）
- **设置审批策略：仅限 Passkey** — 绑定或更新金额阈值策略，API Key 无权操作

**合约白名单接口**

- 查看合约白名单：返回钱包的所有已授权合约（双认证）
- **添加合约：仅限 Passkey** — 将 ERC-20 合约地址加入白名单
- **删除合约：仅限 Passkey** — 从白名单移除合约

**审批接口（双认证，部分仅限 Passkey）**

- 查看待审批列表：API Key 和 Passkey 均可访问，返回当前用户名下所有 pending 状态的审批请求
- 查看审批详情：同上，用于 OpenClaw 轮询签名结果
- 审批通过：**仅限 Passkey session**，验证 Passkey 身份后执行签名并更新状态
- 审批拒绝：**仅限 Passkey session**，更新状态为 rejected

---

### 五、核心业务流程

#### 5.1 创建钱包

用户通过 OpenClaw 下达"创建一个以太坊钱包"的指令后，流程如下：

首先，服务端根据链名确定密钥类型——Ethereum 使用 ECDSA secp256k1，Solana 使用 Schnorr ed25519。然后通过 TEENet SDK 向 TEE-DAO 发起分布式密钥生成请求。TEE-DAO 集群内多个节点协同执行 DKG 协议，各自生成密钥碎片，共同确定公钥，整个过程在 TEE 硬件内完成。SDK 调用返回后，服务端拿到公钥（hex 格式）和 TEE-DAO 分配的密钥名称。

接下来进行地址派生：Ethereum 地址通过对公钥做 Keccak256 哈希取后 20 字节得到（EIP-55 校验和格式）；Solana 地址直接对 32 字节 Ed25519 公钥做 Base58 编码。最后将钱包信息写入数据库，状态设为 ready，返回给用户。

需要注意的是，ECDSA 密钥生成（DKG）是计算密集型操作，在 TEE 集群上通常需要 1-2 分钟，OpenClaw 会提前告知用户耐心等待；Schnorr 密钥生成秒级完成。

#### 5.2 签名与审批

签名请求由 OpenClaw 构造，携带待签名消息（hex 编码）和完整的交易上下文（转账方、收款方、金额、货币单位、备注等）。服务端收到后：

**判断是否需要审批**：查询该钱包是否绑定了审批策略，若有，则从 tx_context 中解析交易金额与阈值做比较（使用字符串精度的大数比较，避免浮点问题）。

**无审批（直接签名）**：调用 TEENet SDK 的 Sign 接口，传入消息字节和密钥名称，SDK 内部处理所有模式（直接签名或投票签名），返回签名结果。响应体包含签名（hex 格式）、钱包地址和链名。

**需要审批**：在本地数据库创建审批请求记录，保存完整 tx_context，状态设为 pending，并设置 30 分钟过期时间。返回给 OpenClaw 的响应包含审批 ID、完整交易摘要和审批 URL。OpenClaw 立即将这些信息展示给用户，引导其前往 Web UI 完成 Passkey 审批。

**审批后签名**：用户在 Web UI 完成 Passkey 身份验证后，服务端调用 Sign 接口执行签名，将签名结果写入审批记录，状态更新为 approved。OpenClaw 轮询到 approved 状态后，自动取出签名结果，继续后续的交易广播流程。

#### 5.3 链上余额查询

余额查询直接在应用层发起 RPC 调用，不经过 TEE 层。Ethereum 调用 `eth_getBalance` 接口，将返回的 Wei 转换为 ETH（18 位精度）；Solana 调用 `getBalance` 接口，将 Lamport 转换为 SOL（9 位精度）。RPC 节点地址通过环境变量配置，支持使用 Infura、Alchemy 或自建节点。

---

### 六、OpenClaw Skill 设计

Skill 是 OpenClaw 的插件机制，本项目提供 `tee-wallet` Skill，安装后 OpenClaw 即可理解并执行钱包相关指令。

**Skill 的工作方式**

Skill 由一个 SKILL.md 文件定义，描述 AI 应该如何处理特定类型的用户请求——包括识别意图、调用哪个 API、如何解读响应、以及遇到特殊情况（如需审批）时应该怎么处理。AI 根据这份说明书，自主决策并执行操作，整个过程对用户透明。

**转账辅助脚本**

当用户请求转账时，仅靠调 API 签名还不够——还需要在链上查询 nonce/gasPrice（ETH）或最新区块哈希（SOL），构造未签名交易，组装签名后广播。这些操作通过两个 Python 辅助脚本完成（eth_transfer.py 和 sol_transfer.py），AI 在需要时调用这些脚本，脚本负责与链直接交互，整个流程对用户完全透明。

**安装方式**

用户将 `tee-wallet/` 目录复制到 OpenClaw 的 skills 目录，配置 API URL 和 API Key 两个环境变量后即可使用。后续也可发布到 ClawHub 供其他用户一键安装。

---

### 七、部署方案

**容器化部署**

应用编译为单个无外部依赖的 Go 二进制文件，打包为 Docker 镜像，通过 UMS Dashboard 部署到 TEE mesh 节点。数据目录挂载到持久化存储（默认 `/data`），SQLite 数据库文件写入其中。

**关键环境变量**

部署时需配置以下环境变量：APP_INSTANCE_ID 由 UMS 在部署时自动注入，标识该实例；CONSENSUS_URL 指向当前节点的 app-comm-consensus 服务地址；DATA_DIR 指定数据持久化路径；ETH_RPC_URL 和 SOL_RPC_URL 分别配置两条链的 RPC 节点地址。

**访问路径**

部署完成后，外部通过 UMS 的代理路径 `/instance/{app_instance_id}/api/...` 访问钱包服务。OpenClaw Skill 配置的 API URL 即为该代理地址。

---

### 八、后续扩展方向

- **Bitcoin 支持**：添加 secp256k1 地址派生（P2PKH/P2WPKH 格式）和 PSBT 签名脚本
- **EVM 链扩展**：BSC、Polygon、Arbitrum 等 EVM 兼容链共用同一套 ETH 密钥和地址，只需更换 RPC URL
- **EIP-712 结构化签名**：支持 DeFi 协议的 permit 签名、多签钱包的消息签名等场景
- **ERC-20 代币转账**：添加代币合约调用辅助脚本
- **智能合约交互**：通用合约调用脚本，支持 ABI 编码
- **ClawHub 发布**：将 Skill 发布到 OpenClaw 官方插件市场，供所有用户一键安装

---

## 项目结构

```
openclaw-wallet/
├── main.go                      # Entry point: config, DB init, SDK init, route setup
├── handler/
│   ├── middleware.go             # API Key + Passkey session 双模认证中间件
│   ├── auth.go                  # Passkey 登录/注册 + API Key 管理
│   ├── wallet.go                # 钱包 CRUD + 签名 + ERC-20 转账 + 审批策略
│   ├── balance.go               # 链上余额查询
│   ├── approval.go              # 审批路由 (passkey-only approve/reject, 状态查询)
│   ├── contract.go              # 合约白名单 CRUD (写操作 Passkey-only)
│   ├── contract_test.go         # 合约白名单单测 (13 个测试)
│   ├── wallet_erc20_test.go     # ERC-20 转账路径单测 (5 个测试)
│   ├── wallet_policy_test.go    # 审批策略 CRUD 单测 (7 个测试)
│   ├── approval_test.go         # 审批请求路由单测 (9 个测试)
│   └── middleware_test.go       # 认证中间件单测 (7 个测试)
├── model/
│   ├── user.go                  # User model (passkey_user_id + hashed API key)
│   ├── wallet.go                # Wallet model (chain, address, key_name, public_key)
│   ├── policy.go                # ApprovalPolicy + ApprovalRequest models
│   └── contract.go              # AllowedContract model (合约白名单)
├── chain/
│   ├── address.go               # ETH EIP-55 地址派生 + SOL Base58 地址派生
│   ├── tx_eth.go                # ETH 交易构造 + 广播 + ERC-20 ABI 编码
│   ├── tx_eth_test.go           # ERC-20 ABI 编码单测 (10 个测试)
│   ├── address_test.go          # 地址派生 + Base58 单测 (11 个测试)
│   ├── tx_sol.go                # SOL 交易构造 + 广播
│   └── rpc.go                   # 链 RPC 调用 (余额查询)
├── frontend/
│   └── index.html               # Web UI: Passkey 注册/登录, API Key 管理, 钱包, 审批, 合约白名单
├── skill/
│   └── tee-wallet/
│       └── SKILL.md             # OpenClaw skill definition (含 ERC-20 和合约白名单章节)
├── Dockerfile
└── pack.sh                      # Build script
```

## 用户认证（API Key + Passkey 混合）

```
注册/管理 (Web UI + Passkey):
  用户访问 Web 页面 → 注册 Passkey → 登录 → 生成 API Key → 配置到 OpenClaw

日常操作 (OpenClaw + API Key):
  OpenClaw → API Key → 创建钱包、签名、查余额

大额审批 (Web UI + Passkey):
  签名超阈值 → 返回 pending_approval → 用户打开 Web → Passkey 认证 → 审批
```

**Passkey 复用已有系统**：
- 通过 SDK `InvitePasskeyUser()` 邀请用户 → 用户获得注册链接
- 用户在 Web 页面注册 passkey 凭证（WebAuthn `navigator.credentials.create()`）
- 登录通过 SDK `PasskeyLoginOptions()` + `PasskeyLoginVerify()` → 获得 session token
- 审批通过 passkey 认证确认

**注意**: Passkey 用户存储在 UMS 的 `passkey_users` 表中，通过 SDK admin bridge 管理，本应用只存 API Key 和 user mapping。

## 数据模型

### User (`model/user.go`)
```go
type User struct {
    ID             uint      `json:"id" gorm:"primaryKey"`
    Username       string    `json:"username" gorm:"uniqueIndex;not null"`
    PasskeyUserID  uint      `json:"passkey_user_id" gorm:"uniqueIndex"` // UMS PasskeyUser.ID
    APIKeyHash     *string   `json:"-" gorm:"uniqueIndex"`              // SHA-256, 可选
    APIPrefix      string    `json:"api_prefix" gorm:"size:16"`
    CreatedAt      time.Time `json:"created_at"`
}
```

### Wallet (`model/wallet.go`)
```go
type Wallet struct {
    ID        uint      `json:"id" gorm:"primaryKey"`
    UserID    uint      `json:"user_id" gorm:"not null;index"`
    Chain     string    `json:"chain" gorm:"size:20;not null"`        // "ethereum", "solana"
    KeyName   string    `json:"key_name" gorm:"not null;uniqueIndex"` // SDK 返回的 key name
    PublicKey string    `json:"public_key"`                           // hex 公钥
    Address   string    `json:"address" gorm:"size:100;index"`        // 链地址
    Label     string    `json:"label" gorm:"size:100"`
    Curve     string    `json:"curve"`                                // secp256k1, ed25519
    Protocol  string    `json:"protocol"`                             // ecdsa, schnorr
    Status    string    `json:"status" gorm:"default:'creating'"`     // creating, ready, error
    CreatedAt time.Time `json:"created_at"`
}
```

## API

### Passkey 认证路由（Web UI 用）

| Method | Path | 说明 |
|--------|------|------|
| `GET` | `/` | Web UI 前端页面 |
| `GET` | `/api/health` | 健康检查 |
| `POST` | `/api/auth/invite` | 邀请用户（管理员） |
| `GET` | `/api/auth/passkey/options` | Passkey 登录 challenge |
| `POST` | `/api/auth/passkey/verify` | Passkey 登录验证 → session token |
| `POST` | `/api/auth/apikey/generate` | 生成 API Key（需 passkey session） |
| `GET` | `/api/auth/apikey/list` | 查看 API Keys（需 passkey session） |
| `DELETE` | `/api/auth/apikey/:id` | 吊销 API Key（需 passkey session） |

### 钱包操作路由

| Method | Path | 认证 | 说明 |
|--------|------|------|------|
| `POST` | `/api/wallets` | 双认证 | 创建钱包 `{"chain":"ethereum","label":"..."}` |
| `GET` | `/api/wallets` | 双认证 | 列出用户钱包 |
| `GET` | `/api/wallets/:id` | 双认证 | 钱包详情 |
| `DELETE` | `/api/wallets/:id` | 双认证 | 删除钱包 |
| `POST` | `/api/wallets/:id/sign` | 双认证 | 原始签名（含审批策略判断） |
| `POST` | `/api/wallets/:id/transfer` | 双认证 | 后端构造+签名+广播（原生 & ERC-20） |
| `GET` | `/api/wallets/:id/pubkey` | 双认证 | 获取原始公钥 |
| `GET` | `/api/wallets/:id/balance` | 双认证 | 查询链上余额 |
| `GET` | `/api/wallets/:id/policy` | 双认证 | 查看审批策略 |
| `PUT` | `/api/wallets/:id/policy` | **仅 Passkey** | 设置审批策略 |
| `GET` | `/api/wallets/:id/contracts` | 双认证 | 查看合约白名单 |
| `POST` | `/api/wallets/:id/contracts` | **仅 Passkey** | 添加合约到白名单 |
| `DELETE` | `/api/wallets/:id/contracts/:cid` | **仅 Passkey** | 从白名单移除合约 |

### 审批路由

| Method | Path | 认证 | 说明 |
|--------|------|------|------|
| `GET` | `/api/approvals/pending` | 双认证 | 查看待审批列表（自动过期陈旧请求） |
| `GET` | `/api/approvals/:id` | 双认证 | 查看审批详情+状态（OpenClaw 轮询用） |
| `POST` | `/api/approvals/:id/approve` | **仅 Passkey** | 审批通过 → 执行 TEE 签名（+ 广播） |
| `POST` | `/api/approvals/:id/reject` | **仅 Passkey** | 审批拒绝 |

## 核心流程

### 启动 (`main.go`)
```go
client := sdk.NewClient(os.Getenv("CONSENSUS_URL"))  // default http://localhost:8089
client.SetDefaultAppIDFromEnv()                        // APP_INSTANCE_ID
db := initSQLite("/data/wallet.db")
r := gin.Default()
// register routes...
r.Run(":8080")
```

### 创建钱包 (`handler/wallet.go`)
1. 查 chain config: `"ethereum" → {ecdsa, secp256k1}`
2. 调 SDK: `sdkClient.GenerateECDSAKey("secp256k1")` 或 `GenerateSchnorrKey("ed25519")`
3. 地址派生: `chain.DeriveAddress("ethereum", pubkeyHex)`
4. 入库并返回

**注意**: ECDSA DKG 可能耗时 1-2 分钟。Schnorr 秒级完成。两种都用 SDK 同步调用（SDK 内部会等待），HTTP 请求设较长超时。

### 签名 + 审批流程 (`handler/wallet.go`)

签名请求携带**完整交易上下文**，方便审批时展示：
```json
POST /api/wallets/1/sign
{
  "message": "0xdeadbeef...",
  "encoding": "hex",
  "tx_context": {
    "type": "transfer",
    "from": "0x742d...2bD18",
    "to": "0xAb5801a7D398351b8bE11C439e05C5B3259aeC9B",
    "amount": "1.5",
    "currency": "ETH",
    "memo": "Payment for services"
  }
}
```

**直接签名响应**（金额 ≤ 阈值 或 无策略）:
```json
{
  "status": "signed",
  "signature": "0xabc123...",
  "wallet_address": "0x742d...2bD18",
  "chain": "ethereum"
}
```

**需审批响应**（金额 > 阈值）:
```json
{
  "status": "pending_approval",
  "approval_id": 123,
  "message": "Transfer 1.5 ETH from 0x742d...2bD18 to 0xAb58...eC9B requires approval",
  "tx_context": {
    "type": "transfer",
    "from": "0x742d...2bD18",
    "to": "0xAb5801a7D398351b8bE11C439e05C5B3259aeC9B",
    "amount": "1.5",
    "currency": "ETH",
    "memo": "Payment for services"
  },
  "threshold": "0.1",
  "approval_url": "https://your-ums/instance/{id}/#/approve/123"
}
```

**OpenClaw 收到 `pending_approval` 后直接通知用户**：
> 🔐 交易需要审批
> 从 0x742d...2bD18 转账 1.5 ETH 到 0xAb58...eC9B
> 备注: Payment for services
> 审批链接: https://.../#/approve/123
> 请在 Web 页面用 Passkey 确认此交易。

**流程**:
1. 查 wallet，验证属于当前用户
2. 检查是否有审批策略（`ApprovalPolicy`）
3. **金额 ≤ 阈值 或 无策略**: 直接调 `sdkClient.Sign()` → 返回签名
4. **金额 > 阈值**: 创建 `ApprovalRequest`（含完整 tx_context）→ 返回 pending + 审批链接
5. 用户在 Web UI 打开审批链接 → Passkey 认证 → 审批通过
6. 服务端调 `sdkClient.Sign()` → 签名存入 `ApprovalRequest.Signature`
7. OpenClaw 轮询 `GET /api/approvals/:id` 获取签名结果

### 审批策略 (`model/policy.go`)

```go
type ApprovalPolicy struct {
    ID              uint    `json:"id" gorm:"primaryKey"`
    WalletID        uint    `json:"wallet_id" gorm:"uniqueIndex;not null"`
    ThresholdAmount string  `json:"threshold_amount" gorm:"not null"`  // "0.1"
    Currency        string  `json:"currency" gorm:"not null"`          // "ETH", "SOL"
    Enabled         bool    `json:"enabled" gorm:"default:true"`
    CreatedAt       time.Time `json:"created_at"`
}

type ApprovalRequest struct {
    ID          uint      `json:"id" gorm:"primaryKey"`
    WalletID    uint      `json:"wallet_id" gorm:"not null;index"`
    UserID      uint      `json:"user_id" gorm:"not null"`
    Message     string    `json:"message"`         // 原始签名消息 hex
    TxContext   string    `json:"tx_context"`      // JSON: {type, from, to, amount, currency, memo}
    Status      string    `json:"status"`          // pending, approved, rejected, expired
    Signature   string    `json:"signature"`       // 审批通过后填入
    ApprovedBy  *uint     `json:"approved_by"`     // PasskeyUserID
    CreatedAt   time.Time `json:"created_at"`
    ExpiresAt   time.Time `json:"expires_at"`      // 超时自动过期 (默认 30 分钟)
}
```

**审批机制（Passkey 认证）**:

签名超阈值时：
1. 应用创建 `ApprovalRequest`（status=pending）
2. **通知用户**（见下方通知机制）
3. 用户打开 Web UI → passkey 认证 → 审批通过/拒绝
4. 审批通过后，应用调 `sdkClient.Sign()` 执行签名 → 结果存入 `ApprovalRequest.Signature`
5. OpenClaw 轮询获取签名结果

**审批必须通过 Passkey**:
Web UI 审批时，调 `navigator.credentials.get()` 获取 passkey credential，
服务端通过 SDK `PasskeyLoginVerify()` 验证身份后才允许审批操作。
纯 API Key 不能审批——确保只有持有硬件 passkey 的人才能批准大额交易。

### 通知机制

**主要方式：OpenClaw 直接通知用户**

OpenClaw 调签名 API 时，如果超阈值会收到 `pending_approval` 响应，
包含完整交易上下文（from、to、amount、memo）和审批链接。
OpenClaw 立即通过用户的消息渠道（WhatsApp/Telegram/Slack 等）展示交易详情并提醒审批。

不需要额外的轮询或推送——触发点就是签名调用本身。

OpenClaw 随后轮询 `GET /api/approvals/:id` 等待审批结果，
审批通过后自动拿到签名并告知用户。

### 余额查询 (`handler/balance.go`)

```
GET /api/wallets/:id/balance
→ {"chain":"ethereum","address":"0x...","balance":"1.234","currency":"ETH"}
```

**实现**: 应用层直接调链上 RPC，不走 TEE。

```go
func GetBalance(walletID uint) (*BalanceResult, error) {
    switch wallet.Chain {
    case "ethereum":
        // 调 eth_getBalance RPC
        // 支持配置的 RPC URL (Infura/Alchemy/自建节点)
        return queryETHBalance(wallet.Address, rpcURL)
    case "solana":
        // 调 getBalance RPC
        return querySOLBalance(wallet.Address, rpcURL)
    }
}
```

**环境变量**:
```
ETH_RPC_URL=https://mainnet.infura.io/v3/YOUR_KEY
SOL_RPC_URL=https://api.mainnet-beta.solana.com
```

### 地址派生 (`chain/address.go`)
- **Ethereum**: `ethcrypto.DecompressPubkey()` → `Keccak256(pub[1:])` → 后 20 字节 → `0x` + hex（用 go-ethereum，已在 go.mod 中）
- **Solana**: 32 字节 Ed25519 公钥 → Base58 编码（需加 `github.com/mr-tron/base58` 到 go.mod）

### 认证中间件 (`handler/middleware.go`)

**双模式认证**：
1. **API Key 模式**（OpenClaw 用）: `Authorization: Bearer ocw_xxx` → SHA-256 hash → 查 users 表
2. **Passkey session 模式**（Web UI 用）: `Authorization: Bearer ps_xxx` → 查 session 内存/cache

两种模式都 `c.Set("userID", user.ID)`，下游 handler 不感知差异。

审批路由额外支持 passkey session，确保大额交易审批必须通过 passkey 认证人。

## 链配置

```go
var Chains = map[string]ChainConfig{
    "ethereum": {Protocol: "ecdsa",   Curve: "secp256k1"},
    "solana":   {Protocol: "schnorr", Curve: "ed25519"},
}
```

## 关键复用

| 来源 | 用途 |
|------|------|
| `sdk.NewClient()` + `SetDefaultAppIDFromEnv()` | SDK 初始化模式 |
| `sdk.GenerateECDSAKey()` / `GenerateSchnorrKey()` | 钱包创建 |
| `sdk.Sign()` | 交易签名 |
| `sdk.GetPublicKeys()` | 查询已有密钥 |
| `ethcrypto` (go-ethereum) | ETH 地址派生（已在 examples/go.mod） |

## 环境变量

| 变量 | 说明 | 默认值 |
|------|------|--------|
| `APP_INSTANCE_ID` | 实例 ID（部署时自动设置） | — |
| `CONSENSUS_URL` | app-comm-consensus 地址 | `http://localhost:8089` |
| `HOST` | 监听地址 | `0.0.0.0` |
| `PORT` | 监听端口 | `8080` |
| `DATA_DIR` | SQLite 数据目录 | `/data` |
| `ETH_RPC_URL` | 以太坊 RPC（余额查询） | — |
| `SOL_RPC_URL` | Solana RPC（余额查询） | `https://api.mainnet-beta.solana.com` |

## 部署

1. UMS Dashboard 创建 Application + Instance
2. 部署 Docker 镜像到 mesh 节点
3. 通过 `/instance/{app_instance_id}/api/...` 访问

---

## OpenClaw Skill（插件）

**位置**: `/home/sun/tee/teenet-sdk/go/examples/openclaw-wallet/skill/`

OpenClaw skill 是一个 `SKILL.md` 文件，告诉 AI agent 如何调用钱包 API。不需要写代码——skill 指导 agent 用 `curl` 调 HTTP API。

### 目录结构

```
skill/
└── tee-wallet/
    ├── SKILL.md
    └── scripts/
        ├── eth_transfer.py    # ETH/EVM 转账 (web3.py)
        └── sol_transfer.py    # SOL 转账 (solders/solana-py)
```

### SKILL.md

```yaml
---
name: tee-wallet
description: "Manage crypto wallets secured by TEE. Use when user asks to create wallet, check balance, send crypto, sign messages, or manage crypto assets. Supports Ethereum and Solana."
metadata:
  openclaw:
    emoji: "🔐"
    requires:
      env:
        - TEE_WALLET_API_URL
        - TEE_WALLET_API_KEY
      anyBins:
        - python3
        - curl
    primaryEnv: TEE_WALLET_API_KEY
---

# TEE Wallet Skill

You manage crypto wallets backed by TEE (Trusted Execution Environment) hardware security.
Private keys are distributed across TEE nodes via threshold cryptography — they never exist
as a whole outside secure hardware.

## Configuration

- `TEE_WALLET_API_URL`: The wallet service URL (e.g. `https://ums.example.com/instance/abc123`)
- `TEE_WALLET_API_KEY`: Your API key (starts with `ocw_`)
- `ETH_RPC_URL`: Ethereum RPC endpoint (e.g. `https://mainnet.infura.io/v3/YOUR_KEY`)
- `SOL_RPC_URL`: Solana RPC endpoint (default: `https://api.mainnet-beta.solana.com`)

## Available Operations

### 1. Create Wallet

When user asks to create a new wallet:

```bash
curl -s -X POST "${TEE_WALLET_API_URL}/api/wallets" \
  -H "Authorization: Bearer ${TEE_WALLET_API_KEY}" \
  -H "Content-Type: application/json" \
  -d '{"chain":"<ethereum|solana>","label":"<user description>"}'
```

- Ask user which chain (Ethereum or Solana) if not specified
- Ethereum wallets may take 1-2 minutes to create (ECDSA key generation)
- Solana wallets are created instantly
- Show the wallet address to the user when complete

### 2. List Wallets

```bash
curl -s "${TEE_WALLET_API_URL}/api/wallets" \
  -H "Authorization: Bearer ${TEE_WALLET_API_KEY}"
```

Present wallets in a clear table: ID, Chain, Address, Label.

### 3. Get Wallet Details

```bash
curl -s "${TEE_WALLET_API_URL}/api/wallets/<id>" \
  -H "Authorization: Bearer ${TEE_WALLET_API_KEY}"
```

### 4. Sign Message / Send Transaction

When user asks to sign or send a transaction:

```bash
curl -s -X POST "${TEE_WALLET_API_URL}/api/wallets/<id>/sign" \
  -H "Authorization: Bearer ${TEE_WALLET_API_KEY}" \
  -H "Content-Type: application/json" \
  -d '{
    "message":"<hex-encoded message>",
    "encoding":"hex",
    "tx_context":{
      "type":"transfer",
      "from":"<sender address>",
      "to":"<recipient address>",
      "amount":"<amount>",
      "currency":"<ETH|SOL>",
      "memo":"<optional memo>"
    }
  }'
```

Always include `tx_context` with full transaction details — this is shown to the user during approval.

**If response has `"status":"signed"`**: show the signature to the user.

**If response has `"status":"pending_approval"`**: the transaction exceeds the approval threshold.
Immediately notify the user with a clear summary:

> 🔐 **Transaction requires approval**
> **From:** 0x742d...2bD18
> **To:** 0xAb58...eC9B
> **Amount:** 1.5 ETH
> **Memo:** Payment for services
> **Approval link:** {approval_url from response}
> Please open the link and approve with your Passkey.

Then poll for the result:
```bash
curl -s "${TEE_WALLET_API_URL}/api/approvals/<approval_id>" \
  -H "Authorization: Bearer ${TEE_WALLET_API_KEY}"
```
When status becomes "approved", show the signature. When "rejected" or "expired", inform the user.

### 5. Send Crypto (Transfer)

When user asks to send/transfer crypto, use the helper scripts. These construct the transaction
locally, sign via the wallet API, and broadcast to the blockchain.

**Ethereum/EVM transfer:**
```bash
python3 "$(dirname "$0")/../scripts/eth_transfer.py" \
  --api-url "${TEE_WALLET_API_URL}" \
  --api-key "${TEE_WALLET_API_KEY}" \
  --wallet-id <id> \
  --to <recipient_address> \
  --amount <amount_in_eth> \
  --rpc-url "${ETH_RPC_URL}"
```

**Solana transfer:**
```bash
python3 "$(dirname "$0")/../scripts/sol_transfer.py" \
  --api-url "${TEE_WALLET_API_URL}" \
  --api-key "${TEE_WALLET_API_KEY}" \
  --wallet-id <id> \
  --to <recipient_address> \
  --amount <amount_in_sol> \
  --rpc-url "${SOL_RPC_URL}"
```

The scripts will:
1. Query nonce/gas (ETH) or recent blockhash (SOL) from the chain
2. Construct an unsigned transaction
3. Call the wallet API `/sign` endpoint (which may return `pending_approval` for large amounts)
4. If approved, assemble the signed transaction and broadcast
5. Return the transaction hash

If the script outputs `PENDING_APPROVAL:{"approval_id":123,...}`, follow the approval flow in step 4 above.

Always confirm with the user before sending: show them the recipient, amount, and estimated gas fee.

**Prerequisites**: `pip install web3` (Ethereum) or `pip install solders` (Solana). If not installed,
ask the user to install first.

### 6. Delete Wallet

```bash
curl -s -X DELETE "${TEE_WALLET_API_URL}/api/wallets/<id>" \
  -H "Authorization: Bearer ${TEE_WALLET_API_KEY}"
```

- Always confirm with user before deleting

### 6. Check Balance

```bash
curl -s "${TEE_WALLET_API_URL}/api/wallets/<id>/balance" \
  -H "Authorization: Bearer ${TEE_WALLET_API_KEY}"
```

Display balance with currency symbol (e.g., "1.234 ETH", "50.5 SOL").

### 7. Set Approval Policy

When user wants to require approval for large transactions:

```bash
curl -s -X PUT "${TEE_WALLET_API_URL}/api/wallets/<id>/policy" \
  -H "Authorization: Bearer ${TEE_WALLET_API_KEY}" \
  -H "Content-Type: application/json" \
  -d '{"threshold_amount":"<amount>","currency":"<ETH|SOL>","enabled":true}'
```

Ask user for the threshold amount if not specified.

### 8. View Pending Approvals

```bash
curl -s "${TEE_WALLET_API_URL}/api/approvals/pending" \
  -H "Authorization: Bearer ${TEE_WALLET_API_KEY}"
```

Show: wallet, amount, currency, message hash, created time.

### 9. Poll Approval Status

After a sign request returns `pending_approval`, poll until resolved:

```bash
curl -s "${TEE_WALLET_API_URL}/api/approvals/<approval_id>" \
  -H "Authorization: Bearer ${TEE_WALLET_API_KEY}"
```

- `"status":"pending"` → still waiting, tell user to approve via Web UI
- `"status":"approved"` → show the signature from the `signature` field
- `"status":"rejected"` → inform user the transaction was rejected
- `"status":"expired"` → inform user the approval expired (30 min timeout)

Note: Approving/rejecting can ONLY be done via the Web UI with Passkey — not via API key.

## Rules

1. Never display or ask for private keys — they don't exist outside TEE hardware
2. Always confirm with user before signing or deleting
3. When creating ETH wallets, tell the user it may take 1-2 minutes
4. Present addresses in their native format (0x... for ETH, base58 for Solana)
5. **When sign returns `pending_approval`**, immediately show the user a clear transaction summary (from, to, amount, currency, memo) and the approval link. Tell them to open it in a browser and approve with their Passkey
6. When showing balances, include the currency symbol
7. Approval can ONLY be done through the Web UI with Passkey hardware authentication — never through the CLI or API key
8. If an API call fails, show the error message and suggest the user check their API URL and key
```

### 安装方式

用户将 `tee-wallet/` 目录复制到 `~/.openclaw/workspace/skills/` 即可，或者发布到 ClawHub。

配置环境变量：
```bash
# ~/.openclaw/openclaw.json 或 env
TEE_WALLET_API_URL=https://your-ums/instance/your-app-instance-id
TEE_WALLET_API_KEY=ocw_xxxxxxxxxxxxxxxx
```

### 使用示例

用户对 OpenClaw 说：
- "帮我创建一个以太坊钱包"
- "我有哪些钱包？"
- "用钱包 1 签名这条消息: hello world"
- "显示我的 Solana 钱包地址"

---

## ERC-20 代币转账与合约白名单

### 背景与安全设计

ERC-20 转账需要在以太坊上调用合约的 `transfer(address,uint256)` 方法，而非发送原生 ETH。为防止泄露的 API Key 被用于调用恶意合约（如授权攻击者无限转账），本系统引入**合约白名单**作为安全门禁：

- 只有 Passkey 认证的用户可以向白名单添加或删除合约
- API Key 只能读取白名单、发起 ERC-20 转账（调用已白名单合约）
- Transfer 端点在发起 ERC-20 调用前必须验证合约已在白名单中，否则返回 403

这确保了即使 API Key 完全泄露，攻击者也无法绕过人工审核向任意合约转账。

### 技术实现

**ABI 编码**（`chain/tx_eth.go`）：

ERC-20 的 `transfer` 和 `approve` 方法使用手动 ABI 编码，避免引入 ABI JSON 解析依赖：
```go
// selector = keccak256("transfer(address,uint256)")[:4]
// calldata = selector + pad32(toAddr) + pad32(amount)
func EncodeERC20Transfer(toAddr string, amount *big.Int) []byte
func EncodeERC20Approve(spenderAddr string, amount *big.Int) []byte
```

**合约调用交易**（`chain/tx_eth.go`）：

`BuildETHContractCallTx` 查询 nonce/gasPrice/chainID，通过 `eth_estimateGas` 估算 gas（+20% 缓冲），构造 `LegacyTx`（value=0，data=calldata）。`ETHTxParams` 新增 `Data string` 字段（`omitempty`，向后兼容）。

**转账路由扩展**（`handler/wallet.go`）：

`TransferRequest` 新增可选 `Token *TokenParams` 字段：
```go
type TokenParams struct {
    Contract string `json:"contract"` // ERC-20 合约地址（小写 hex）
    Decimals int    `json:"decimals"` // 精度，如 USDC=6
    Symbol   string `json:"symbol"`   // 代币符号，如 "USDC"
}
```

当 `Token != nil` 时：
1. 查询 AllowedContract 表验证合约已授权 → 403 如未找到
2. 将人类可读金额（如 "100"）乘以 10^decimals 得到原始单位
3. 调用 `EncodeERC20Transfer` 编码 calldata
4. 调用 `BuildETHContractCallTx` 构造零值合约调用交易
5. 检查审批策略（对比 amount 与 policy.ThresholdAmount，当 policy.Currency == token.Symbol）
6. 签名 + 广播，或创建待审批请求

**常用 ERC-20 合约参数**：

| 代币 | 合约地址（主网） | Decimals |
|------|----------------|----------|
| USDC | `0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48` | 6 |
| USDT | `0xdac17f958d2ee523a2206206994597c13d831ec7` | 6 |
| WETH | `0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2` | 18 |
| DAI  | `0x6b175474e89094c44da98b954eedeac495271d0f` | 18 |

---

## 单测覆盖

| 测试文件 | 测试数 | 覆盖内容 |
|----------|--------|----------|
| `chain/tx_eth_test.go` | 10 | ERC-20 ABI 编码（selector、padding、大数、零值） |
| `chain/address_test.go` | 11 | ETH/SOL 地址派生、Base58 编码/解码、边界情况 |
| `handler/contract_test.go` | 13 | 合约白名单 CRUD（成功、重复、权限隔离、格式校验） |
| `handler/wallet_erc20_test.go` | 5 | ERC-20 转账（未授权→403、已授权+无RPC→502、原生跳过白名单、无效金额、钱包未就绪） |
| `handler/wallet_policy_test.go` | 7 | 审批策略设置/查询（upsert、无策略→null、权限隔离） |
| `handler/approval_test.go` | 9 | 审批请求（列表、自动过期、用户隔离、详情、越权→403） |
| `handler/middleware_test.go` | 7 | 认证中间件（API Key、Passkey session、过期、无凭证、PasskeyOnly） |

---

## 后续扩展

- Bitcoin 地址派生 + 转账脚本
- EIP-191 / EIP-712 签名（结构化数据签名）
- ✅ ERC-20 代币转账（已完成）
- ✅ 合约白名单安全门禁（已完成）
- 智能合约通用交互（ABI 解析 + 任意方法调用）
- 发布到 ClawHub

---

## 验证

```bash
# 注册
curl -X POST http://localhost:8080/api/register \
  -H "Content-Type: application/json" \
  -d '{"username":"alice"}'

# 创建 Solana 钱包
curl -X POST http://localhost:8080/api/wallets \
  -H "Authorization: Bearer ocw_xxx" \
  -H "Content-Type: application/json" \
  -d '{"chain":"solana","label":"My SOL"}'

# 签名
curl -X POST http://localhost:8080/api/wallets/1/sign \
  -H "Authorization: Bearer ocw_xxx" \
  -H "Content-Type: application/json" \
  -d '{"message":"0xdeadbeef","encoding":"hex"}'
```
