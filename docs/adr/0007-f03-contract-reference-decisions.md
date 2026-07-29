# ADR 0007: F03 契约与托管兼容性参考决定

- 状态：Candidate
- 日期：2026-07-30
- 范围：F03 / P0-B07 合成契约、破坏性变更检测和托管 CI
- 审查模式：RETROSPECTIVE_BACKFILL
- 数据边界：P0_SYNTHETIC_ONLY

## 决定

基于 `implementation/p0/f03/p0-b07-official-reference-research.v1.md`
中固定的官方来源、版本、许可证、安全和退出边界，F03 采用以下参考：

- JSON Schema 2020-12：`ADOPT`，作为三个 Canonical Schema 的方言。
- OpenAPI 3.1.2：`ADOPT`，作为六份最小 HTTP 契约的格式。矩阵中的
  OpenAPI 3.1.1 不会被静默替换；当前实现准确固定 3.1.2。
- CloudEvents 1.0.2 Core + JSON Format：`ADOPT`，只约束当前 JSON
  event envelope。
- RFC 9457：`ADOPT`，约束 Problem Details 的公开字段和安全边界。
- Ajv 8.20.0：`ADOPT`，只在可信、Git 冻结的 Schema 上使用
  `Ajv2020` 严格验证。
- ajv-formats 2.1.1：`ADOPT`，只启用当前冻结 Schema 使用的格式；
  不假设所有 format 都能抵御 ReDoS。
- GitHub Actions：`ADOPT`，仅使用 `pull_request`、只读 contents 权限、
  固定 Runner、无缓存和不可变 Action SHA。
- actions/checkout v4.4.0：`ADOPT`，固定 commit
  `11d5960a326750d5838078e36cf38b85af677262`，并关闭凭据持久化。
- actions/setup-node v4.4.0：`ADOPT`，固定 commit
  `49933ea5288caeca8642d1e84afbd3f7d6820020`，运行 Node 24。

当前 eight-category mutation strategy 采用本项目 `ADAPT` 实施方式：
路径、操作、响应、属性、必填、类型、枚举和引用的变化均按失败关闭处理。
`ADAPT` 不是正式 Reference Review Receipt 决定；后续 Receipt 对相应官方
标准使用 `ADOPT`，并把这八类规则记录为项目自己的兼容策略。

## 推迟与不适用

- CloudEvents HTTP Binding：`DEFER`。只有 F03 开始冻结 HTTP 级
  CloudEvent 传输映射时才重新审查。
- Pact JS：`DEFER`。只有出现跨团队契约协商或需要 Broker 生命周期时才
  进行 PoC。
- WireMock：`NOT_APPLICABLE`。当前纯 Node 静态兼容门不调用外部 HTTP
  服务，不引入 JVM、standalone server 或容器化服务虚拟化。
- Schemathesis：`DEFER`。只有范围扩展到属性生成或广泛 OpenAPI fuzzing
  时才进行 PoC。
- Testcontainers for Node.js：`NOT_APPLICABLE`。当前 F03 是无外部服务
  依赖的纯 Node 合成 loopback；它不能被用来冒充真实 Adapter 验证。

## 比较与边界

现有 Node 契约实验室比立即引入 Pact、WireMock、Schemathesis 或
Testcontainers 更小，并已直接覆盖当前八类验收。外部工具在触发条件出现前
不会进入依赖锁。

JSON Schema、OpenAPI、CloudEvents、RFC 9457 和 Ajv 均不定义本项目完整的
API 向后兼容算法。`validateOpenApiContract` 只是项目级最小结构检查，
`findBreakingChanges` 也只承诺已冻结类别；它们不能被描述为完整 OAS
合规验证或所有 breaking change 的穷举。

GitHub Actions 只负责托管执行和证据采集，兼容逻辑必须继续能以普通 Node
命令运行。退出 GitHub Actions 时，可以把同一命令迁到其他托管 CI，不得把
算法绑定到 GitHub 专有 API。不得使用 `pull_request_target` 执行 PR 代码，
不得使用 floating Action tag，也不得把 secrets 暴露给不可信 PR。

## 治理效力

This ADR does not claim production adoption.

This ADR does not close P0-B07.

This ADR does not create D1, Gate, Profile, or start-authorization state.

本 ADR 和研究文件只是后续正式 Reference Catalog、Policy、Receipt、
Bundle 与 Freeze Attestation 的输入。正式回填仍须在新的 Profile Core 和
Execution Baseline 固定后，按 ADR 0006 追加冻结；本 ADR 不改变历史
P0/P1、G0/G1、Manifest 或 O02/O03 状态。
