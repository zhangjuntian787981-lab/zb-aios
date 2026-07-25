# C05 Stable Principal 与委托链

P1 数据边界：`SYNTHETIC_ONLY`

P1 工程验证状态：`IMPLEMENTED / VERIFIED（SYNTHETIC_ONLY）`

生产验证状态：`NOT_VERIFIED`

本文冻结并验证 C05 的 P1 合成领域与接口边界，但不构成真实企业接入或生产
部署证据。C05 只使用 F02/C04 的 Synthetic Fixture；不接收目标企业身份、
组织、账号、地址或凭据。OA、U9、BI 及全部企业 Connector 继续保持 `C0`。

## 冻结决策

1. Stable Principal 是一个 Tenant 内的稳定安全身份，不是邮箱、姓名、工号、
   门户用户 ID、OIDC subject 或全局人员主数据。
2. 一个 Principal 只代表一个 Human membership incarnation，或一个 Agent /
   Service workload incarnation。Tenant、`principal_id` 和类型永久不可改变；
   永久停用后的返聘或 workload 重建必须创建新 Principal。
3. C04 Identity Account 只证明账号经过认证和 Provisioning。C05 通过显式
   IdentityLink 把它关联到 Human Principal，不依据邮箱、姓名、工号或 Claims
   自动关联。
4. 一个 Human Principal 可在受控 IdP 迁移期间同时拥有多个 ACTIVE
   IdentityLink；同一个 Identity Account 同时最多关联一个 Principal。
5. Agent 和 Service Principal 不绑定 Human Identity Account，也不能成为
   Human Subject 或作 HumanDecision。
6. Action Delegation 只表达 Human Subject 到即时 Workload Actor 的身份来源链。
   它不授予业务权限、不扩大原权限，也不替代 C06 授权或 C15 HumanDecision。
7. C05 的最小运行结果是受委托 Agent / Service 动作的 Action Identity
   Context 身份元组；本工作包不保存 ActionAttribution、业务动作历史或完整
   跨模块审计。C08 保存业务状态，C18 保存不可覆盖业务证据。
8. C05 不签发或轮换 Agent / Service workload 凭据；P1 只接受受信的合成
   server context，生产候选凭据、密钥和工作负载身份属于 O02。

ID 使用 UUIDv7，并固定前缀：

- Principal：`prn_`；
- IdentityLink：`lnk_`；
- Action Delegation：`dlg_`。

这些 ID 都是 Tenant 内的安全标识，不能从邮箱、名称、角色或外部账号字段推导。

## 三个 Core 入口

`createStablePrincipalRegistry(...)` 只暴露三个入口：

- `execute(context, command)`：唯一写入口，按 command kind 重新检查调用能力、
  Synthetic 边界、Tenant、版本和幂等性；
- `resolveActionIdentity(serverContext, request)`：服务端先通过 C04 重新解析
  Session，再恢复 Principal、IdentityLink 和可选委托链，返回身份元组；
- `snapshot(context, query)`：返回字段白名单治理视图，不返回邮箱、姓名、
  OIDC subject、directory object、原始 Session Token、凭据或完整 Claims。

`resolveActionIdentity` 的请求只包含：

```text
sessionToken
expectedTenantId
delegationId
```

`delegationId` 必须是委托链的叶子 Delegation ID。Tenant、Human Subject 和
Workload Actor 不能由浏览器或模型直接指定。

返回的 Action Identity Context 是最小身份元组：

```text
tenantId
tenantKind
identityAccountId
identityLinkId
sessionId
humanSubject {
  principalId
  principalType = HUMAN
  lifecycleVersion
  securityEpoch
}
workloadActor {
  principalId
  principalType = AGENT | SERVICE
  lifecycleVersion
  securityEpoch
}
purposeRef
delegationChain[] {
  delegationId
  delegatorPrincipalId
  delegatePrincipalId
  purposeRef
  lifecycleVersion
  expiresAt
}
trustSource
authorizationStatus
```

当前 resolver 只接受受委托的 AGENT 或 SERVICE Workload Actor，不提供直接
Human action context。`authorizationStatus` 固定为 `NOT_EVALUATED`；身份
解析成功不表示任何读取、运行、管理、Tool、Sandbox 或业务动作已经获准。

## 八类命令

`execute` 只接受：

1. `CREATE_SYNTHETIC_PRINCIPAL`
   - 从冻结的 Synthetic 来源创建 HUMAN、AGENT 或 SERVICE Principal；
   - 类型、Tenant 和来源 incarnation 创建后不可改变。
2. `LINK_IDENTITY_ACCOUNT`
   - 将同 Tenant 的 C04 Identity Account 显式关联到 HUMAN Principal；
   - 不读取或比较邮箱、姓名、显示名、工号或 Group / Role。
3. `RETIRE_IDENTITY_LINK`
   - 将 ACTIVE IdentityLink 永久退役；
   - 不删除历史关联，也不能把 RETIRED Link 恢复为 ACTIVE。
4. `REASSIGN_IDENTITY_ACCOUNT`
   - 原子退休错误的旧 Link，并为同一 Identity Account 创建指向另一个 HUMAN
     Principal 的新 Link；
   - `reasonRef` 必须命中冻结的纠错目录；目录哈希绑定 profile、来源 Principal
     和目标 Principal，事件同时记录纠错引用与映射哈希；
   - 这是面向未来解析的关联纠错，不是 Principal merge，也不改写历史身份。
5. `CHANGE_PRINCIPAL_STATE`
   - 按单调版本改变 Principal 生命周期；
   - 旧版本、乱序、同版本异内容或对终态的恢复请求全部失败关闭。
6. `SYNC_IDENTITY_ACCOUNT`
   - 只接受 opaque `identityAccountId`；
   - Core 必须服务端重读 C04 当前账号状态，不能相信命令携带的邮箱、subject、
     Tenant、状态或 Principal。
7. `CREATE_DELEGATION`
   - 创建 Human Subject 到 Agent / Service，或 Agent / Service 到 Agent /
     Service 的一跳委托；
   - 固定 Human Subject、delegator、delegate、可选 parent、`expiresAt` 和
     `purposeRef`。
8. `REVOKE_DELEGATION`
   - 永久撤销一条委托；
   - 任何解析都重新检查整条父链，父链撤销或到期会使叶子失效。

所有命令都需要独立的调用能力。C05 的模块调用能力只控制谁能维护身份记录，
不能作为业务资源授权。

## 状态机与不可变量

Principal：

```text
ACTIVE ↔ SUSPENDED → DEACTIVATED
```

- `DEACTIVATED` 是当前 Principal incarnation 的永久吸收态；
- HUMAN Principal 的永久停用不同于一个 C04 Identity Account 的
  `TERMINATED`。单个账号停用不能在存在其他有效 Link 时误杀稳定 Principal；
- 每次 Principal 状态变化都推进单调 `securityEpoch`；每次动作重新读取当前
  状态、Link 和委托所固定的安全代次。已返回的身份元组只适用于当前动作，
  不是调用方可缓存复用的凭据；
- Principal 墓碑保留，ID 不释放、不复用。

IdentityLink：

```text
ACTIVE ↔ SUSPENDED → RETIRED
```

- 一个 Identity Account 同时只能有一个当前 Link（ACTIVE 或 SUSPENDED）；
- 一个 HUMAN Principal 可拥有多个 ACTIVE Link；
- C04 Account 暂停会使 Link 进入 SUSPENDED；更高的有效 C04 revision 可使同一
  Link 恢复 ACTIVE，但 RETIRED 永不可恢复；
- Link 的 Tenant、Identity Account 和历史 Principal 绑定不可就地修改；
- `REASSIGN_IDENTITY_ACCOUNT` 通过“退役旧 Link + 新建 Link”留下完整历史。

Action Delegation：

```text
ACTIVE → REVOKED
```

- 到期由可信时钟派生；到期或 REVOKED 后不可恢复；
- 根跳必须是 `HUMAN → AGENT|SERVICE`；
- 子跳的 delegator 必须等于父跳的 delegate，delegate 仍只能是 AGENT 或
  SERVICE；
- 整条链使用同一个不可变 `purposeRef`；解析结果返回该目的标签，C06 必须再
  将它与受信业务请求和策略绑定，浏览器不能据此自授权限；
- 子跳的 `expiresAt` 不得晚于父跳；
- 根 Human Subject、全部 Principal 和 Delegation 必须属于同一 Tenant；
- 禁止 self delegation、重复 Principal、环、断链和跨 Tenant parent；
- 委托链最多八跳；`resolveActionIdentity` 从叶子反向恢复并检查整条链；
- 最终 delegate 必须等于受信 server context 中的即时 workload actor，不能
  使用客户端提交的 Actor。

当前 Delegation ID 不是一次性业务执行 Token，也不是幂等键。在到期前，只要
整条链仍为 ACTIVE 且各 Principal 的安全代次仍匹配，它可以再次用于身份解析。
C05 只验证其身份来源、目的引用、状态、到期和结构；它不据此允许或执行业务
动作。业务动作的哈希绑定、重复副作用防护、幂等 Commit、Readback 和不可覆盖
审计分别属于 C15、C16 和 C18。

## 邮箱碰撞与关联纠错

C05 的安全关联表不需要邮箱字段或邮箱唯一索引。以下情况都不得触发自动
merge：

- 两个 Identity Account 使用完全相同的邮箱；
- 邮箱只存在大小写差异；
- 邮箱 alias、转发地址或共享邮箱相同；
- 离职后邮箱被另一个人回收；
- 姓名、显示名或工号看起来相同；
- IdP Group / Role 或门户用户 ID 相同。

若两个 Identity Account 确属同一 Human incarnation，只能由冻结的
Synthetic 关联依据通过 `LINK_IDENTITY_ACCOUNT` 显式连接。错误关联使用
`REASSIGN_IDENTITY_ACCOUNT` 修正；不得合并两个 Principal，不得重写已产生
的历史引用。

## IdP 迁移顺序

稳定 Broker 后的上游 IdP 或账号迁移使用：

```text
1. C04 Provision 新 Identity Account
2. LINK_IDENTITY_ACCOUNT 显式连接到原 Human Principal
3. 重新签发 Delegation，用新账号完成 Session 和 Action Identity 验证
4. RETIRE_IDENTITY_LINK 退役旧 Link
5. 再次重新签发 Delegation，并用新账号完成最终验证
6. C04 再暂停或终止旧 Identity Account
```

先添加并验证新 Link，再退役旧 Link，避免把迁移窗口误判成永久离职。Link
新增和退役都会推进 Human Principal 的 `securityEpoch` 并撤销旧 Delegation。
因此步骤 3 和步骤 5 都必须使用新签发的 Delegation；新请求还必须重新从 C04
Session 解析，调用方不得复用先前动作返回的身份元组。

当前 C04 每个 Tenant 只有一个平台面对的 `provider_connection_id`，并由
稳定 Broker 屏蔽 OIDC / SAML 上游差异。因此 C05 可以验证：

- 邮箱、subject 或外部目录账号变化但 Principal ID 不变；
- 同一稳定 Broker 下，新旧 Identity Account 迁移到同一 Principal；
- 多 Link 重叠、退役和纠错。

当前证据不能证明两个平台级 Provider Connection 在同一 Tenant 中并行，也
不能证明更换平台 issuer 后的真实双 IdP 切换。若 P3 需要该形态，必须先扩展
C04、重新验证多 Provider 生命周期与登录路由，再做 C05 真实迁移验收；不能
用 C05 单元测试代替。

## 停用传播

每次 `resolveActionIdentity` 必须在返回前重新验证：

```text
C03 Tenant 可准入
C04 Session 有效
C04 Identity Account 有效
C05 IdentityLink = ACTIVE
C05 Human Subject Principal = ACTIVE
整条 Delegation ACTIVE 且未到期
每个 Agent / Service Principal = ACTIVE
叶子 delegate = 受信 Workload Actor
```

- C03 暂停、删除或拒绝准入时立即失败，不等待 C05 异步传播；
- C04 Account 暂停或终止后，该 Account 的 Link 不能继续解析；
- 一个 Human 仍有其他有效 Link 时，可通过新 Session 继续解析；每个新动作
  都重新生成身份元组，先前动作的元组不能作为凭据复用；
- Principal SUSPENDED / DEACTIVATED、任一链上 Actor 停用、父 Delegation
  撤销或到期都会使叶子解析失败；
- 旧 revision、乱序 ACTIVE 和事件重放都不能恢复终态。

历史引用和墓碑保留；停用只阻止当前和未来解析，不删除或改写过去证据。

## 与其他工作包的边界

### C03 Tenant Registry

- C03 是 Tenant 生命周期和新请求准入真相源；
- C05 不创建、恢复或删除 Tenant，也不把 Synthetic Tenant 升级为企业 Tenant；
- 所有 Principal、Link 和 Delegation 必须与同一 C03 Tenant 绑定；
- Tenant 停用先由 C03 Gate 立即阻断，C05 投影不能取代该 Gate。
- PostgreSQL 在创建 Principal、IdentityLink、Delegation 或恢复 ACTIVE 状态
  的触发器中锁定并重查 C03 Tenant；即使 Tenant 在应用层 preflight 后暂停，
  写入也会整体回滚。

### C04 身份联邦

- C04 认证账号、处理 Session、MFA、Provisioning、账号状态和撤销；
- C05 只消费 C04 返回的 opaque Identity Account / Session 结果，不保存密码、
  Token、完整 Claims、OIDC subject 或 directory object；
- C04 Group / Role 不直接成为 Principal 类型、委托或业务权限；
- `SYNC_IDENTITY_ACCOUNT` 必须由服务端回读 C04，不能把调用方提交状态当真。

### C06 统一授权

C05 不实现：

- Group、Role、资源关系或 Allow / Deny；
- OpenFGA、SpiceDB、OPA、PEP SDK 或授权模型版本；
- read、retrieve、download、manage、Tool 或 Sandbox 决策；
- 通过 Delegation、Agent、Service、Prompt、Skill 或 MCP 继承权限；
- HumanDecision 资格和正式业务批准。

C05 成功只表示“当前动作中的 Tenant、Human Subject、Workload Actor 和
Delegation 身份链可以被可信恢复”。C06 必须使用该服务端身份元组重新执行
业务授权，并保留自己的策略版本和决策证据。

### C08、C18 与 O02

- C08 后续持久化 Case、Run 和业务动作状态；
- C18 后续持久化不可覆盖的 Action、授权、Tool、结果和来源链证据；
- O02 后续负责生产候选的 Secret、工作负载凭据、轮换和撤销；
- C05 可以产生自己的领域事件、幂等回执和 Outbox，但不能把这些描述为完整
  业务审计、ActionAttribution 或生产 workload identity。

## P1 验收边界

C05 只有在冻结实现和证据至少证明以下事项后，才能从 `NOT_VERIFIED` 变更：

- 外部账号、邮箱或显示资料变化时 `principal_id` 保持不变；
- 同邮箱、同名、同工号和回收邮箱不自动 merge；
- 同 Identity Account 并发关联只有一个 ACTIVE owner；
- IdP 迁移顺序、Link 退役和原子 reassignment 正确；
- Human、Agent、Service 类型矩阵和终态不可恢复；
- Human → Agent / Service 多跳身份元组正确；
- 环、断链、超八跳、跨 Tenant、过期、撤销和 Actor 冒充全部拒绝；
- C03 暂停、C04 Account 停用及 Principal / Actor 停用即时阻断解析；
- 返回始终为 `authorizationStatus=NOT_EVALUATED`；
- 真实 PostgreSQL 的唯一约束、事务争用、失败回滚和最小权限通过；
- 全部测试数据为 Synthetic Fixture，OA、U9、BI 和 Connector 保持 `C0`。

即使上述 P1 合成验证通过，生产状态仍保持 `NOT_VERIFIED`，直到 P3 使用目标
企业正式授权的 Onboarding Package 验证真实账号关联、IdP 迁移、停用 SLA、
运行权限与企业审计边界。

治理 `snapshot` 在 P1 只以小规模 Synthetic Fixture 验证，尚未提供生产分页或
大租户导出证明；生产容量状态因此仍为 `NOT_VERIFIED`。动作解析路径已按叶子
Delegation 使用最多八跳的递归读取，不扫描整个 Tenant 的 Principal 或
Delegation 集合。

## 冻结验证

- 完整构建与单元/契约回归：`npm test`；
- 静态检查：`npm run lint`；
- C05 定向 Core、OpenAPI、目录与 PostgreSQL 契约回归：55 项；
- 一次性本地 PostgreSQL 17.10 Core 集成：13 项；
- 一次性本地 PostgreSQL 17.10 运行角色隔离：1 项；
- 证据文件：`c05-verification-evidence.v1.json`。

同一 Identity Account 的不同 owner 争用由真实 PostgreSQL 唯一索引并发测试
直接证明；Core 的错误 owner 命令会先被冻结身份目录拒绝，因此该数据库争用
测试不冒充“两个合法业务命令都可进入写事务”。真实企业目录、账号迁移、
大租户分页、容量、备份恢复和高可用仍留到 P3 或生产发布验收。
