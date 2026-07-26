# C02 Tenant 管理与治理门户

当前工程状态：`IMPLEMENTED / EVIDENCE_CANDIDATE`

当前范围：`P1_SYNTHETIC_ONLY / C0_DISABLED`

## 冻结边界

C02 是可替换的薄管理壳和身份 BFF，不拥有 Tenant、身份、授权、知识、
Skill、Artifact、审计、配额、指标或 Connector 状态真相。

```text
薄管理壳
→ C02 BFF
→ 每次请求由真实 C06 MANAGE PEP 重鉴权
→ 高风险写入由可信确认服务消费一次性、未过期的确认记录
→ Product Core 窄 read / mutate Port
→ 封闭视图或带 C18 审计引用的提交回执
```

浏览器不能直接访问 Product Core。界面不保存角色或权限矩阵，只显示 BFF
返回的 `allowedActions`。绕过界面直接调用 BFF，仍会经过相同 C06 鉴权。

## 管理范围

- Tenant 配置；
- Principal / Role 投影；
- 知识和 Skill 发布状态；
- 配额；
- 正式 Artifact；
- 只读审计；
- Connector Stage；
- 可观测状态。

私人会话、私人记忆和审计修改没有 API operation。所有七类 P1 管理写操作
统一视为高风险，必须携带期望版本、幂等键、冻结候选哈希、绑定同一操作和
资源的二次确认，以及至少一条证据引用。调用者能够自行重算的 SHA-256
不能证明确认存在；BFF 必须从可信确认服务消费一个绑定 Tenant、人员、
操作、资源、版本和候选的未过期单次确认，并把消费证据交给 Core。缺记录、
重放、过期或绑定不一致都在 Core 前失败关闭。Core 提交成功后必须返回 C18
引用且保留可信确认消费证据，否则 BFF 拒绝结果。

## 资源与制品

`resourceId` 使用与 C06 兼容的稳定不透明 ID，例如
`c02-tenant-config-general`。候选、确认、审计和上游证据继续使用带命名空间的
引用；两者不能混用。

| 文件 | 用途 |
|---|---|
| `management-use-cases.v1.json` | 九读、七写和三项禁止操作 |
| `management-api.openapi.v1.json` | 管理读写 API |
| `management-shell.contract.v1.json` | 可替换薄管理壳 |
| `dependency-bindings.v1.json` | C03/C04/C05/C06/C07/C13/C18/C19 精确绑定 |
| `verification-matrix.v1.json` | P1 验收断言 |

## 验证

```text
node --test \
  tests/c02-contract.test.mjs \
  tests/c02-c06-authorizer.test.mjs \
  tests/c02-c06-integration.test.mjs \
  tests/c02-governance-shell.test.mjs \
  tests/c02-tenant-governance-bff.test.mjs
```

## P1 不证明

- 不连接任何 Target Enterprise、真实 IdP、企业系统或真实 Connector；
- 不包含 React Admin 生产包；当前可执行薄壳只冻结可替换接口和权限边界；
- Core Port 的跨模块三 Tenant 真实组合验收属于 G1，而不是单个 C02 单测；
- P1 单元边界只校验 C18 引用命名空间与消费证据保留；记录存在、Tenant
  归属和不可变性必须在 G1 通过真实 C18 组合接口回读；
- 不证明生产容量、HA、灾备、真实管理流程或企业权限配置正确。

这些限制不改变 C02 的核心验收：UI 不是授权边界，直接 API 仍会失败关闭，
业务管理员不能修改历史审计，也不能读取员工私人会话或记忆。
