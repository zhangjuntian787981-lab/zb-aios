# C06 OpenFGA 原生适配器

范围：`P1_SYNTHETIC_ONLY`

生产验证状态：`NOT_VERIFIED`

本目录固定 OpenFGA Server `v1.18.1` 的 Darwin arm64 官方发布制品和
SHA-256。真实验收使用临时内存 Store、Synthetic Principal 与虚构资源；OA、
U9、BI 及全部 Enterprise Connector 保持 `C0`。

## 最小接口

`createOpenFgaPdp({ baseUrl, storeId?, fetchImpl?, timeoutMs? })` 返回六个方法：

- `provisionStore({ name })`：仅在工厂未绑定 `storeId` 时创建并永久绑定一个
  Store；
- `publishModel(model)`：向已绑定 Store 发布原生 OpenFGA 1.1 JSON 模型并
  返回不可变 `authorizationModelId`；
- `writeTuples({ authorizationModelId, tupleKeys })`：向已绑定 Store 和显式
  Model ID 一次写入 1–100 条关系；请求体固定为
  `writes.tuple_keys`，不接受 Store、Model 或原生 `writes` 覆写；
- `readAuthorizationModel({ authorizationModelId })`：按固定 Store/Model ID
  读回实际模型，严格归一化 OpenFGA 的空默认字段；
- `readAllTuples({ authorizationModelId })`：以 `HIGHER_CONSISTENCY` 分页读回
  Release 专属 Store 的全部持久 Tuple；畸形、重复分页、条件 Tuple 或超过
  P1 上限都会失败关闭；
- `check({ authorizationModelId, tupleKey, trustedContextualTuples? })`：
  每次显式固定 Store ID 和 Model ID，并固定使用
  `HIGHER_CONSISTENCY`。

`check` 不接受 `storeId`、`modelId` 或普通 `contextualTuples` 字段。调用者只能
通过命名为 `trustedContextualTuples` 的内部参数传入由服务端构造的临时关系；
浏览器、Prompt、Skill、MCP 参数或其他外部 JSON 不得直接映射到该参数。

实时授权使用 `createOpenFgaRuntimePdp(...)`。该端口只暴露
`readAuthorizationModel`、`readAllTuples` 和 `check`，不暴露创建 Store、发布
Model 或写 Tuple 的方法。投影 Worker 才使用完整写端口；生产环境中的独立凭据
与网络隔离仍属于后续验收边界。

旧/新模型切换通过受控调用者显式选择已经发布并验证的
`authorizationModelId` 完成。适配器不会默认为 Store 中“最新模型”，也不会
允许请求体覆盖已绑定 Store。

真实策略关系必须先通过 `writeTuples` 持久写入。未传
`trustedContextualTuples` 时，`check` 完全不发送 `contextual_tuples` 字段；
P1 真实集成验收正是以这种方式验证 Human、Actor 与 Purpose 三项。

## 策略投影验证器

`createOpenFgaPolicyVerifier(...)` 提供两个入口：

- `evaluateProjection(candidate)`：投影 Worker 写入 Model 和 Tuple 后，生成
  冻结报告；
- `verifyPolicyRelease(release)`：`RECORD_POLICY_PROJECTION`、激活和回滚前重新
  运行同一组 Check，并逐项比较已保存报告。

Principal 映射只能来自注入的受信 `resolvePrincipalIds`，不能由命令或请求体
提交。验证器先读回指定 Model ID 的实际模型并做规范化精确比较，再分页读回
Release 专属 Store 的全部 Tuple。它使用 Core 的唯一
`hashSyntheticPolicyTuples` 算法，对实际 Tuple Key 规范排序后计算
Tenant-specific `tupleBundleSha256`，并与受信映射生成的期望集合做精确核对；
它与 catalog 中固定模板语义的 `policyBundleSha256` 以及规范化
`modelSha256` 是三个不同事实，不能互相代替。

每个 Policy Release 对六个 surface 各运行五项真实 Check：

1. Human 正例；
2. workload Actor 正例；
3. Purpose 正例；
4. 未授权 Human 负例；
5. 错误 Purpose 负例。

因此每次投影、激活、回滚、实时决策或历史回放前都重跑完整投影核对与 30 项
检查。确定性 `fixtureReportSha256` 同时绑定
template、Policy Model Hash、Store ID、Model ID、实际 Tuple Bundle Hash、
`HIGHER_CONSISTENCY` 和 30 个有序结果。任一响应的 Store、Model、一致性或
布尔结果畸形都会失败关闭；报告 Hash 被替换时，Policy Release 不能进入
`READY`。

## 错误边界

适配器只抛以下稳定错误码，错误消息不拼接 URL、响应正文、Tuple 或凭据：

- `OPENFGA_CONFIGURATION_INVALID`
- `OPENFGA_INVALID_INPUT`
- `OPENFGA_STORE_NOT_BOUND`
- `OPENFGA_STORE_ALREADY_BOUND`
- `OPENFGA_TIMEOUT`
- `OPENFGA_UNAVAILABLE`
- `OPENFGA_REQUEST_REJECTED`
- `OPENFGA_INVALID_RESPONSE`

普通 `allowed: false` 是有效 Deny；超时、不可达、非成功 HTTP 或畸形响应是
PDP 错误。上层 PEP 对所有 PDP 错误必须失败关闭，不能把它们改写成 Allow。

## 验证

单元测试：

```sh
node --test \
  tests/openfga-pdp.test.mjs \
  tests/openfga-policy-verifier.test.mjs
```

真实临时 OpenFGA：

```sh
sh scripts/run-c06-openfga-tests.sh
```

脚本只支持当前锁定的 Darwin arm64 制品。它通过 HTTPS 下载固定归档，先校验
SHA-256，再启动无持久化的本地 OpenFGA；结束时停止进程并清理临时目录。测试
验证两个隔离 Store 创建、仓库 C06 模型发布、Synthetic Policy Tuple 持久
写入、Model/完整 Tuple 读回、30 项报告重放、Facade 的
Stage/Projection/Activation、V1/V2 切换与 Rollback、报告篡改拦截、额外
Tuple/替换 Model/激活后漂移拦截，以及 PDP 不可达时失败关闭。

该结果不证明生产认证、投影写凭据撤销、网络隔离、TLS、持久化数据库、HA、
备份恢复、容量、升级或真实企业权限模型；这些仍需后续生产阶段验收。
