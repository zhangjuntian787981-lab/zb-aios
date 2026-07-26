# C19 可观测、用量、配额与成本

当前工程状态：`IMPLEMENTED / EVIDENCE_CANDIDATE`

当前范围：`P1_SYNTHETIC_ONLY`

生产状态：`NOT_VERIFIED`

## 冻结验收

1. 只接受 W3C Trace Context `version 00`。Trace ID、Span ID、Flags 和
   Tracestate 逐项验证；零 ID、非小写十六进制、重复 Tracestate Key、
   非法 Flags 和未知 Header 均失败关闭。
2. 一个冻结的 Northstar 集成测试真实调用 C14、C16、C18 的公开接口，并由
   C19 wrapper 构造父子 Span：

   ```text
   C14 model.route
   → C16 tool.execute
   → C18 audit.append
   → C19 usage.settle
   ```

3. Trace、Span 和 Log 只保存封闭元数据。Metric Label 固定为
   `module / operation / signal_type / status / error_code`，不允许 Tenant、
   Principal、Task、Trace、资源或 Meter Key 成为高基数标签。
4. Prompt、输入输出、文件、Tool 参数、Cookie、Token、密码、API Key 和
   Credential 不进入遥测接口或数据表。数据库没有任意 JSON 或正文列。
5. 三个固定 Synthetic Tenant 使用一份带版本的费率卡。每个用量计划绑定
   Task、模型/Tool/沙箱资源、单位、最高数量、来源证据和 C18 审计证据。
6. Tenant 与 C05 解析出的 Principal 配额同时预留最大成本，再用冻结
   Receipt 结算实际数量。失败链把所有仍为 `RESERVED` 的金额幂等转为
   `RELEASED`；Meter Key 唯一，并发预留通过数据库原子更新，不会超卖。
7. `usage_ledger` 只追加。成本报告按 Tenant、Task、Model、Tool 和 Sandbox
   对账 Booked、Supplier 与 Variance。不同单位的数量不做无意义相加。
8. 四张 PostgreSQL 表均有 Tenant Key、`ENABLE RLS` 和 `FORCE RLS`。
   Writer、Reader、Scope 使用三个独立连接池；连接若有错误角色、传递角色、
   高权限属性或任何额外 `aios_*` 能力即拒绝启动。

## 公开接口

```text
recordSignal(serverContext, request)
telemetryReport(serverContext, range)
reserve(serverContext, request)
release(serverContext, request)
settle(serverContext, request)
costVarianceReport(serverContext, range)
quotaStatus(serverContext)
createC19SyntheticUpstreamEmitter(...).run(serverContext, request)
```

调用者不能传入 Principal、费率、数量、成本、资源类型或 Metric Label。
服务端从 C03 ACTIVE Tenant、C05 身份解析、冻结 Catalog 和 C07 签名
Tenant Scope 解析这些信息。

Memory Store 和 PostgreSQL Store 实现同一个 Store seam。Memory Store
用于快速合成测试；生产形态必须使用 PostgreSQL Store，不能把单进程状态
当成分布式配额或正式账本。

## PostgreSQL

固定迁移：

```text
0033_observability_usage.sql
0034_observability_runtime_roles.sql
```

表：

| 表 | 用途 | 变更规则 |
|---|---|---|
| `telemetry_signal` | Metadata-only Trace/Span/Log | 只追加 |
| `quota_account` | 期间限额、预留、已消费 | 原子受约束更新 |
| `quota_reservation` | 费率与计划绑定、一次结算或释放 | 只允许 RESERVED → SETTLED/RELEASED |
| `usage_ledger` | 配额和结算事件 | 只追加 |

`aios_c19_writer` 是只能由 C19 Store 持有的可信内部角色，不是员工或管理员
账号。数据库触发器会阻止提高既有限额、重置已消费金额、篡改 Reservation
绑定或重复写入同一 Reservation/Event；应用凭据仍必须由部署层保管和轮换。

角色：

| 角色 | 允许 | 禁止 |
|---|---|---|
| `aios_c19_writer` | 写遥测/账本，预留和结算 | 删除历史、跨 Tenant、相邻模块表 |
| `aios_c19_reader` | 按签名 Tenant Scope 只读报告 | 任何写入 |
| `aios_c07_scope_runtime` | 只签发 C07 短期事务 Scope | 读取 C19 数据 |
| `aios_c19_owner` | 迁移所有者 | 不能作为应用连接池 |

## OpenTelemetry、Prometheus、Jaeger 与 Grafana 边界

本包冻结：

- W3C Trace 和 OTel 发射字段合同；
- Prometheus 低基数 Recording/Alert Rules；
- 可导入 Grafana 的合成 Dashboard；
- 可被 Jaeger/Tempo 使用的 Trace 主链字段；
- SLO 草案。

本包没有声称已部署 Collector、Prometheus、Jaeger、Grafana 或告警通知。
镜像固定、Helm/Compose、环境配置、网络、认证、HA、备份与升级回滚由 O04
打包部署；生产容量与长稳验证由 O06 完成。SLO 目前是
`DRAFT_NOT_APPROVED`，接入真实企业前还必须由 Product Owner 冻结。

这里的 C14、C16、C18 Span 是 C19 wrapper 在公开接口边界记录的 Span，
不是上游模块内部原生 OTel。`quotaStatus()` 的配额阈值与拒绝判断已实际
执行测试；Prometheus 规则只完成结构与低基数字段检查，尚未通过 `promtool`
或真实规则引擎加载，也没有通知通道。

## 依赖边界

- C03：每次写入或报告前重新确认 Synthetic Tenant 为 ACTIVE。
- C05：只通过不透明 `identityContextRef` 解析 Principal，调用者不能注入。
- C14：真实公开 `route()` 输出的 Token、费率与 Supplier Cost 绑定结算。
- C16：真实公开 `confirm()/execute()` 的 Receipt Hash 绑定结算。
- C18：真实公开 `append()` 输出投影必须在两笔结算前匹配冻结证据。

当前只冻结一个 Northstar 端到端运行，且没有修改 C14、C16 或 C18。
每次运行先验证 C14 的完整冻结 Artifact 列表、C16/C18 Source Manifest 和
C19 Catalog，再允许产生副作用。三项输出投影全部匹配后才结算；任一漂移
均失败关闭并释放仍预留的 Tenant/Principal 配额。

`synthetic-trace-evidence.v1.json` 与包含 Sandbox 的
`synthetic-cost-variance-report.v1.json` 是独立的服务级静态合同 Fixture，
不是上述真实 emitter 运行的捕获结果。C18 目前也是冻结 Bundle，不是根据
当次 C14/C16 输出动态生成的审计包。因此本包仍为 `EVIDENCE_CANDIDATE`，
等待最终 Source Commit 和验证证据文件冻结。

## P1 限制

- 只有三个 Synthetic Tenant、合成 Task、合成 Receipt 和合成成本。
- 没有企业资料、员工、真实模型账单、云账单、企业系统、端点或凭据。
- 没有 OA、U9、BI 或其他 Connector。
- 没有生产 Collector、Trace Backend、Dashboard 服务或通知通道。
- Principal 与 Tenant 双配额、阈值及拒绝规则已在 P1 合成范围验证，但没有
  生产部署、通知或值班闭环。
- 部分失败链在 P1 只记录 `ERROR + QUOTA_RELEASED`。由于上游全是 C0
  deterministic mock，本阶段不声称失败用量或 Supplier Cost 完整；接入真实
  账单前必须增加动态 Failed-Usage Receipt 与对应 C18 Failure Evidence。
- 没有 HA、备份恢复、容量、72 小时长稳或真实成本正确性证明。
- 只有一个冻结的端到端 Tenant Fixture；另外两个 Tenant 只用于服务级配额、
  隔离与对账测试。
- 本结果不批准 G1，不进入 P2，也不允许 P3 企业接入。

## 验证

```text
sh scripts/run-c19-tests.sh
```

脚本的 PostgreSQL 测试会创建一次性 PostgreSQL 17 集群，禁用 TCP，仅使用
临时 Unix Socket。测试结束后删除临时集群。
