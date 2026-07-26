# C17 Connector Template SDK 与 Mock Lab

当前工程状态：`IMPLEMENTED / SELF_VERIFIED`

当前范围：`P1_SYNTHETIC_ONLY / C0_DISABLED`

## 冻结验收

1. Canonical Connector Envelope 以 F03/P0 v1 契约为结构基线并锁定其精确文件
   SHA；C17 另外施加深度、节点数和时间规范化安全约束，不宣称完整实现通用
   JSON Schema `format` 校验器。
2. 只提供审批/协同、ERP/业务、BI 三类厂商无关只读 Template。
3. Mock Lab 只含固定三个 Synthetic Tenant，每个 Tenant 覆盖三类 Template。
4. SDK 只接受由 `createC17CredentialBroker` 调用冻结 C16 工厂创建并登记的
   Broker；每次调用都通过 C16 短期能力重新确认 Tenant、operation、call 和
   audience。该 C17 工厂只接受固定合成时间字符串，不接受调用方提供的
   clock、ID factory 或其他可执行 Hook。C17 Broker 在把 scope 或 capability
   交给 C16 前先做有界惰性校验，非法签发输入返回 `INVALID_INPUT`，非法验证
   或撤权输入返回 `DENIED`。
5. SDK 只接受服务端 Synthetic Tenant 上下文，`connectorStage` 固定为
   `C0_DISABLED`；上下文和 capability 在任何字段读取前先做有界惰性校验。
6. SDK 在 `C0_DISABLED` 只接受由固定 `createC17MockLab` 工厂登记的对象；
   任意注入 Adapter 在初始化时拒绝。Mock Lab 只接受构造时固定的合成
   `observedAt` 字符串，不接受执行时钟回调；无网络 seam、无企业端点、
   无企业凭据、无真实副作用。
7. 超时、能力过期、撤权、Tenant 混淆、授权绕过、Schema 注入和重放全部失败关闭。
8. 能力内容不进入 Adapter 参数、结果、错误或 Mock Lab 快照。
9. Template、Fixture 和 Adapter 结果均按封闭 Schema 校验，额外字段失败关闭。
   Template、SDK、Mock Lab 配置、Canonical Envelope、运行上下文、
   capability、Broker 参数、Catalog 校验值和 Mock 调用参数中的访问器或
   Proxy 会在读取前拒绝，不执行 getter 或 Proxy trap。
10. P0—P2 源码和 Fixture 不包含真实企业地址、真实凭据、企业网络或 Connector Instance。
11. 本工作包不创建数据库、迁移、生产连接或真实字段映射。
12. 通过只证明 P1 合成机制，不证明任何 Target Enterprise 已接入。
13. 三个 Synthetic Tenant × 三类 Template 均走完 SDK、C16 capability 和
    Mock Lab 的九条完整调用路径。

## 调用链

```text
C16 已确认的 ToolCall
→ C17 SDK 校验 Canonical Envelope
→ C16 短期能力校验 Tenant / operation / call / audience
→ 能力立即消费和撤销
→ C0_DISABLED Mock Lab
→ 封闭结果 Schema、请求字段回绑和内容哈希校验
→ Canonical RESULT Envelope
```

能力只提供给 SDK 的第三个私有参数。Adapter SPI 只收到：

```text
tenantId
tenantKind = SYNTHETIC
operationId
parameters
requestedAsOf
```

它收不到 capability、企业端点、任意 URL、SQL、命令或字段映射。

## 公开接口

```text
validateConnectorEnvelope(envelope)
createC17CredentialBroker(observedAt)
createC17ConnectorSdk(...).execute(serverContext, envelope, capability)
createC17MockLab({ ..., observedAt }).execute(call)
```

## 三类 Template

| 类别 | operationId | C16 audience | 模式 |
|---|---|---|---|
| 审批/协同 | `synthetic.approval.status.get` | `c16-c0-approval` | `READ_ONLY` |
| ERP/业务 | `synthetic.erp.order.get` | `c16-c0-erp` | `READ_ONLY` |
| BI/分析 | `synthetic.bi.metric.get` | `c16-c0-bi` | `READ_ONLY` |

Template 文档和九条 Fixture 都固定 SHA-256。结构仍然合法但内容被本地替换时，
SDK 和 Mock Lab 同样拒绝启动。

## 上游契约与 C17 安全 Profile

依赖闭包同时锁定两类不同证据：

- F03 验收证据：
  `implementation/p0/evidence/f03-evidence.v1.json`，
  `sha256:64aac8860a9b397860015542338ca90b2a8bd2e9381e56e53fa2ffb1dc01bcda`；
- Canonical Connector Envelope 原始文件：
  `implementation/p0/connector-envelope.v1.json`，
  `sha256:3cf839e3ec5782e17c3bed8f7e6cfd30bd025044f8e69a43977e04476679a3a1`。

前者证明 F03 冻结验收记录，后者锁定 C17 实际读取的上游契约字节；两者不能互相
替代。C17 测试会重新计算 Envelope 文件 SHA。

C17 接受 F03 `format: date-time` 中本阶段实际支持的 RFC 3339 表达，包括无毫秒
`Z` 和带时区偏移的时间。所有非空时间在验证后统一规范化为 UTC 毫秒形式
`YYYY-MM-DDTHH:mm:ss.sssZ`。`content_hash` 只对规范化业务 `data` 计算，不包含
`as_of` 或 `observed_at`，因此等价时间写法不会改变业务内容哈希。

为避免恶意深层 JSON 导致递归栈溢出，C17 Profile 将 Envelope、Template 和
Fixture 的 JSON 值限制为最多 64 层、10,000 个节点。超限请求稳定返回
`INVALID_ENVELOPE`，超限配置稳定返回 `INVALID_CONFIGURATION`，且不会调用
Adapter。这是 C17 的资源安全收窄，不是对 F03 上游 Schema 能力的扩张。

## 失败关闭

| 情况 | 结果 |
|---|---|
| capability 缺失、伪造、过期或撤权 | `DENIED`，Adapter 未调用 |
| capability 或 Broker 验证/撤权参数含访问器/Proxy | `DENIED`，读取计数保持 `0` |
| Broker 签发 scope 含访问器/Proxy | `INVALID_INPUT`，读取计数保持 `0` |
| 服务端上下文含嵌套访问器/Proxy | `SYNTHETIC_BOUNDARY_VIOLATION` |
| `C0_DISABLED` 注入非固定 Capability Broker | 初始化返回 `INVALID_CONFIGURATION` |
| capability Tenant、operation、call 或 audience 不匹配 | `DENIED` |
| capability 再次使用 | `REPLAY_REJECTED` |
| `C0_DISABLED` 注入非固定 Mock Lab Adapter | 初始化返回 `INVALID_CONFIGURATION` |
| 配置、Template、Envelope、Schema 值或 Mock 参数含访问器/Proxy | 读取前失败关闭，执行计数保持 `0` |
| URL/端点形状参数、额外字段或 unsafe key | `INVALID_REQUEST` 或 `INVALID_ENVELOPE` |
| Adapter 超时或抛错 | `UNAVAILABLE`，内部错误不透传 |
| Adapter 多字段、内容哈希错误或结果与请求不一致 | `INVALID_ADAPTER_RESULT` |
| 使用其他 Tenant 的虚构 lookup | `SYNTHETIC_RECORD_NOT_FOUND` |

## 文件

| 文件 | 用途 |
|---|---|
| `connector-templates.v1.json` | 三类固定只读 Template |
| `synthetic-connector-fixtures.v1.json` | 三 Tenant × 三 Template 的九条 Mock |
| `compatibility-matrix.v1.json` | F03、F04、C16 契约绑定 |
| `verification-matrix.v1.json` | 验收断言到测试的映射 |
| `lib/c17-connector-sdk.mjs` | Canonical Envelope validator 与 SDK |
| `lib/c17-mock-lab.mjs` | C0_DISABLED、零网络 Mock Lab |
| `lib/c17-time.mjs` | RFC 3339 接受与 UTC 毫秒规范化 |

没有 PostgreSQL、迁移、连接池、真实端点、真实凭据或生产 Connector。
Mock Lab 的有限 `faultMode` 只用于本地超时、抛错和畸形结果失败关闭测试，
不会开放任意 Adapter、网络或外部副作用。

## 验证

```text
sh scripts/run-c17-tests.sh
npx --no-install eslint \
  lib/c17-connector-sdk.mjs \
  lib/c17-mock-lab.mjs \
  lib/c17-time.mjs \
  tests/c17-contract.test.mjs \
  tests/c17-connector-sdk.test.mjs \
  tests/c17-mock-lab.test.mjs \
  tests/c17-source-boundary.test.mjs
```

`SELF_VERIFIED` 只表示本地源码测试通过。独立复核、Source Freeze、G1、P2 和
P3 企业接入仍需后续单独证据与 Product Owner 决定。

## 当前限制

- capability 消费记录是单进程内存状态，只验证当前 P1 Mock 运行；跨进程和
  重启后的幂等与重放防护仍由 C16 持久化调用账本和后续 P3 连接器负责。
- 超时验证只证明 SDK 会停止等待并返回封闭错误；因为 C0 没有网络或真实
  副作用，它不构成真实协议取消、事务回滚或供应商幂等证明。
- 尚未验证任何厂商协议、认证方式、速率限制、字段映射、网络策略、容量、
  高可用、灾难恢复或真实业务效果。
