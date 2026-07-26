# C12 Agent 编排与任务路由

当前工程状态：`IMPLEMENTED / VERIFIED`

当前范围：`P1_SYNTHETIC_ONLY`

## 冻结边界

C12 只拥有显式任务图和节点编排，不拥有 Tenant、身份、授权、业务状态、
知识、模型、工具、HumanDecision 或不可变审计真相。

```text
C06 每次操作鉴权
→ C12 Checkpoint Port（P1 仅内存）
→ CLASSIFY
→ HARD_GATES
→ C11 RETRIEVE（证据引用与摘要）
→ C16 TOOL（逐调用重鉴权、参数确认与回执）
→ C14 DRAFT（绑定原始输入 + C11 证据 + C16 结果）
→ VALIDATE
→ INDEPENDENT_REVIEW
→ HUMAN_GATE
→ COMPLETE
```

C08 在 P1 只作为 Run Ledger 契约依赖：它拥有 Case、Thread、Run、Artifact、
ToolCall 和 Outbox 总账，不拥有 C12 的节点状态或 Checkpoint。真实
`C08 → C12 → C08` 运行闭环留给 G1 跨模块验收。

三个冻结 Synthetic Tenant 各有一个任务。任务、输入、数据分类、风险、预算、
Skill、知识、模型任务和 Tool operation 都由服务端 Catalog 固定；请求不能
选择模型、Provider、Tool、权限、批准、数据分类或预算。

## 验收标准

1. 公开接口只有 `start`、`advance`、`resumeWithHumanDecision` 和 `inspect`。
2. 每次接口调用都先经 C06-compatible Authorizer；模型输出不能生成授权或
   HumanDecision。
3. 图固定为九个节点，不允许自由多 Agent 对话、动态节点、任意代码、任意
   URL、任意 SQL 或客户端自选 Tool。
4. 每次 `advance` 最多完成一个节点。节点输入、输出和 effect key 都由
   SHA-256 固定；NodeRecord 保存实际元数据 Binding 和 Binding 摘要。
   外部 Port 必须使用稳定 effect key 幂等执行。
5. 知识只经 C11-compatible Port，模型只经 C14-compatible Port，工具只经
   C16-compatible Port。C11 的非空 EvidenceRef 和 C16 的结果/授权/确认回执
   必须进入 DRAFT 的冻结上下文；C12 不直接访问知识库、Provider 或 Connector。
6. `HARD_GATES` 在任何检索、模型或工具调用前执行。权限、风险、数据分类或
   预算拒绝均为终态，模型没有覆盖权。
7. DRAFT 与 INDEPENDENT_REVIEW 两次模型调用的 Token、费用，以及 Tool
   次数都累计到同一 Catalog 预算；复核输入携带当前预算状态，复核用量进入
   NodeRecord，任何累计超限都不会提交 Checkpoint。
8. 规则校验或独立复核失败会终止任务，不能进入人工门或完成态。草稿模型
   与复核模型均绑定 C14 的服务端冻结身份；同模型引用或同模型摘要在调用
   Reviewer 前拒绝，且不相信 Reviewer 自报的“独立”布尔值。
9. 所有 P1 任务必须停在 `WAITING_FOR_HUMAN`。只有绑定同一 Task、当前状态
   哈希和 `productionReusable=false` 的专用 Synthetic HumanDecision 才能恢复。
10. C16 Tool 调用收到可信服务端上下文、短时 Session、委托、关联 ID、
    Human/Workload 主体、冻结参数和 effect key，并必须返回 operation-specific
    重鉴权证据；通用 `C12_ADVANCE` 授权不能代替 C16 授权。
11. Checkpoint Port 使用期望版本、命令幂等键和请求哈希；服务重建、ACK
    丢失和并发旧版本不会双提交或跳过节点。若下游成功后、Checkpoint 前崩溃，
    重试可能再次调用 Port，但 effect key 保持相同，Port 必须幂等去重。
    START、ADVANCE、RESUME 的相同并发命令必须折叠为一个新结果和一个
    receipt replay。每张回执必须绑定 Tenant、Human/Workload 主体、Task、
    operation、幂等键、请求哈希、结果版本和结果状态哈希；单独伪造 replay
    标志或返回状态必须失败关闭。非 replay 返回还必须精确匹配本次预计算
    后置状态。
12. Checkpoint 只保存引用、摘要、版本、计数、状态和证据，不保存 Prompt、
    文件正文、模型输入输出、Tool 参数、凭据或 Session Token。
13. `node-io.v1.schema.json` 冻结各 Authority Port 的输入/输出和 TaskState；
    `dependency-bindings.v1.json` 将 C06/C08/C11/C13/C14/C16 的真实冻结
    制品哈希绑定到契约；C06/C11/C13/C14/C16 进入任务 Catalog，C08 明确为
    `CONTRACT_ONLY`。C13 是 C12 的额外直接 Skill 内容依赖，不能替代 C08。

## P1 不证明

- 不连接企业资料、OA、U9、BI、邮件、网盘或真实身份源；
- 不运行真实模型、真实 Connector、任意代码或网络调用；
- 不把内存 Checkpoint Port 当作生产持久化；P1 未实现生产持久化 Adapter；
- 不把 C08 契约哈希绑定写成运行集成；真实 C08 Run Ledger 闭环由 G1 验收；
- 内存快照的普通 SHA-256 只发现结构、状态机和 Catalog 漂移；它不是签名或
  恶意存储改写证明，生产可信恢复仍由 C08/C18 与后续运行基础设施承担；
- 不证明生产容量、HA、备份、容灾、长稳或真实业务效果；
- 不允许 P1 Synthetic HumanDecision 迁移到 P3。

## 验证

```text
node --test tests/c12-contract.test.mjs tests/c12-agent-orchestrator.test.mjs
npx eslint lib/agent-orchestrator.mjs tests/c12-contract.test.mjs tests/c12-agent-orchestrator.test.mjs
```

通过只表示冻结 P1 Synthetic 范围成立，生产与企业接入仍为
`NOT_VERIFIED / P3_REQUIRED`。
