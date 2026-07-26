# C06 OpenFGA 官方资料核验

核验日期：2026-07-26
范围：只使用 OpenFGA 官方文档和 `openfga/*` 官方 GitHub 仓库。本文是 C06
选型与接口研究笔记，不是已部署、已集成或生产就绪证据。

## 版本结论

- OpenFGA Server 当前 GitHub 最新稳定版是 `v1.18.1`，2026-06-29 发布，
  release commit 为 `69efbd9`。官方同时发布 checksum、SBOM 和
  in-toto provenance；Darwin arm64 压缩包在该 release 页面公开的
  SHA-256 为
  `d667620fcf54d5343fae374c60e1ac0af98defd5e44d93ca9af52866a2881f94`。
  C06 应固定版本和制品摘要，不能使用 `latest`。
  来源：https://github.com/openfga/openfga/releases/tag/v1.18.1
- 官方 JavaScript SDK 当前稳定版是 `v0.9.6`；`v0.9.7-beta.1` 是预发布版，
  不应作为 C06 默认基线。`v0.9.6` 的发布说明包含 BatchCheck 正确传递
  authorization model ID 等修复。
  来源：https://github.com/openfga/js-sdk/releases/tag/v0.9.6
  和 https://github.com/openfga/js-sdk/releases

以上版本只表示 2026-07-26 的官方发布快照。进入实现或升级时仍需重新核验
release、许可证、制品摘要和安全公告。

## 模型与原生 API

1. OpenFGA Store 保存 authorization models 与 relationship tuples。
   `POST /stores/{store_id}/authorization-models` 每次写入都会产生新的
   `authorization_model_id`。
   来源：https://openfga.dev/docs/getting-started/configure-model
2. Authorization Model 是不可修改、不可删除的；每次写入形成新版本。
   `ReadAuthorizationModels` 可列出版本。官方强烈建议 Check、ListObjects、
   ListUsers、Expand 和 Write 显式携带 `authorization_model_id`；省略时会使用
   Store 中最后创建的模型。生产配置应同时固定 Store ID 和 Model ID。
   来源：https://openfga.dev/docs/getting-started/immutable-models
3. `POST /stores/{store_id}/write` 增删 tuple；同一请求内的 writes 与 deletes
   是一个事务，全部成功或全部失败。默认一个请求写入和删除合计最多 100 个
   唯一 tuple，并应显式携带 `authorization_model_id`。
   来源：https://openfga.dev/docs/getting-started/update-tuples
4. `POST /stores/{store_id}/check` 对一个
   `user + relation + object` 返回 `allowed`。如果 relation 在模型中存在但没有
   命中关系，结果为 `false`；relation 未定义会返回 400，而不是 Deny。
   C06 Facade 因此必须把无效模型、协议错误、超时和 PDP 不可用与普通 Deny
   分开记录，并对受保护路径失败关闭。
   来源：https://openfga.dev/docs/getting-started/perform-check
5. BatchCheck 通过唯一 `correlation_id` 关联结果；官方服务默认单批最多
   50 项，SDK 可拆批。C06 不应因拆批而丢失原始决策顺序、模型 ID 或逐项结果。
   来源：https://openfga.dev/docs/getting-started/perform-check
6. `POST /stores/{store_id}/list-objects` 返回某 subject 对某 relation 可访问的
   object 集合；其性能随模型复杂度、tuple 数量以及交并差关系显著变化。
   C06 可把它用于授权前置过滤，但不能把客户端列表或门户隐藏结果当授权真相；
   最终资源操作仍须经过服务端 PEP。
   来源：https://openfga.dev/docs/getting-started/perform-list-objects
7. `GET /stores/{store_id}/changes` 按发生顺序返回 tuple write/delete 变化，
   使用 continuation token 增量读取。它不包含 authorization model 更新或
   assertions 更新，因此不是完整的策略发布日志或历史决策日志。
   来源：https://openfga.dev/docs/interacting/read-tuple-changes

## 一致性、撤权与回放

- 查询默认 `MINIMIZE_LATENCY`，可能使用缓存；tuple 刚变更后立即 Check，
  默认模式可能尚未看到该变化。`HIGHER_CONSISTENCY` 跳过缓存直读数据库，但
  以延迟和吞吐为代价。C06 应至少在撤权后的确认、管理、高敏 Tool、Sandbox
  和其他需要 read-after-write 的路径使用更高一致性，并把一致性模式记入
  决策证据。
  来源：https://openfga.dev/docs/interacting/consistency
- 固定旧 `authorization_model_id` 可以重跑旧模型，也可通过旧/新模型双查做
  shadow comparison，再切换配置；模型变更本身是新版本，回滚是把受控配置
  指回已验证的旧 Model ID。
  来源：https://openfga.dev/docs/getting-started/immutable-models
  和 https://openfga.dev/docs/modeling/migrating/migrating-models
- 但固定 Model ID **不等于精确重放历史决定**：Check 仍会读取执行时可见的
  tuple 状态；而 ReadChanges 又不含模型和 assertion 变化。C06 若要证明
  “当时为什么 Allow/Deny”，必须额外保存不可变 decision input/result、
  Store ID、Model ID、tuple 变化截止点或等价的可重建授权数据版本、请求哈希
  与时间。P1 可用 Synthetic Fixture 重建隔离 Store 做回放；最终不可覆盖的
  跨模块证据仍由 C18 承担。
  依据：https://openfga.dev/docs/interacting/read-tuple-changes
  和 https://openfga.dev/docs/getting-started/immutable-models
- C06 的 P1 实现为每个 Policy Release 使用独立 Store，运行端口只暴露
  Read/Check；投影、激活、回滚、实时决策和历史回放前都会读回指定 Model 与
  Store 全部 Tuple 并核对冻结哈希。任何已发生的漂移会失败关闭，但这仍不证明
  生产写凭据已经撤销，也不消除拥有 OpenFGA 管理权限的并发外部写入风险；生产
  凭据、网络边界和不可变证据由后续阶段单独验收。

## Agent、目的范围与 C05 分工

- 官方建议把 Agent 作为一等 principal，并继续以最小范围授予资源关系；同时
  明确指出 Agent 的一般权限不能替代 task-scoped authorization。
  来源：https://openfga.dev/docs/modeling/agents/agents-as-principals
- 官方 task-based 指南建议同时做用户授权和 task/agent 授权，而不是因为 Agent
  代表用户就继承用户全部权限。C06 可据此把 C05 恢复出的 Human Subject、
  Workload Actor 和 `purposeRef` 分别纳入服务端合取判定；C05 只证明来源链，
  C06 才决定某主体、Actor 与目的范围能否对指定资源执行指定动作。
  来源：https://openfga.dev/docs/modeling/agents/task-based-authorization
- Contextual tuples 只在单次请求中生效且不持久化。若 C06 使用它们，必须由
  服务端从可信资源与任务状态构造，不能接受浏览器、Prompt、Skill 或 MCP
  直接提交。
  来源：https://openfga.dev/docs/interacting/contextual-tuples

## AuthZEN 边界

OpenFGA 的 AuthZEN API 当前仍标记为 Experimental，必须显式启用。官方建议
普通应用集成使用原生 API，只在 API/MCP Gateway 或 IdP 等 AuthZEN-compatible
产品集成时采用 AuthZEN；AuthZEN 本身没有定义 OpenFGA 的 Write/Read 接口，
不能单独完成完整 OpenFGA 集成。C06 因而可以让自建 Facade 的请求/响应外形
接近 AuthZEN，但 P1 不应依赖 OpenFGA 的实验性 AuthZEN endpoint 作为唯一
实现。

来源：https://openfga.dev/docs/interacting/authzen

## 对 C06 的最小工程约束

1. 固定 OpenFGA Server `v1.18.1` 与校验摘要；如用 JS SDK，固定稳定版
   `v0.9.6`，不使用 beta 或浮动标签。
2. 每个 Check、ListObjects、BatchCheck 和 Write 都必须显式传 Store ID 与
   `authorization_model_id`；Facade 不允许客户端覆盖二者。
3. C06 每次从 C05 服务端 resolver 取得当前 Action Identity Context，不能
   接收客户端自报的 Tenant、Human、Actor、Delegation 或授权结论。
4. 对 Human Subject、Workload Actor 和 server-bound purpose scope 执行合取
   判定；任何一项 Deny、错误、缺失或不一致均为 closed decision。
5. 关系变更、模型发布与决策证据分开记录；模型切换先以冻结 Allow/Deny 集对
   旧/新 Model ID 双查，再显式发布；回滚只切回已验证旧 ID。
6. 所有实现与测试仅使用 Synthetic Tenant、Stable Principal 和虚构资源。
   OA、U9、BI 与全部企业 Connector 继续保持 `C0`。
