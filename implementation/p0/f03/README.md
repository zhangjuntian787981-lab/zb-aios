# F03 API、事件、Schema 与兼容实验室

本目录冻结 P0 的最小跨模块契约，供合成集成测试使用。它不是 P1 产品实现，也不连接任何真实企业。

## 冻结内容

- `schemas/`：Canonical TaskEnvelope、RFC 9457 Problem Details、CloudEvents 1.0 JSON 外壳。
- `contracts/`：Portal、Core、Model、Tool、Connector、Audit 六个最小 OpenAPI 3.1.2 契约。
- `samples/`：仅使用 `SYNTHETIC` 数据的合法样例和确定性 Mock 响应。
- `negative/`：结构错误、错误体泄密和破坏性 OpenAPI 变更负例。
- `compatibility-matrix.v1.json`：消费者、提供者、操作和可接受版本范围。
- `deprecation-matrix.v1.json`：90 天最短通知期和只允许主版本承载破坏性变更的规则。

## 两条不可越过的边界

1. **Schema 合法不等于授权成功。** Mock 固定返回 `authorization_status=NOT_EVALUATED`；生产调用仍需服务端从已验证会话重建 Tenant/Principal 并执行授权。
2. **Mock 成功不等于企业接入。** Mock 固定返回 `connection_status=MOCK_ONLY` 和 `synthetic=true`；这里没有 Connector Instance、企业地址、凭据或网络访问。

`scripts/f03-contract-lab.mjs` 提供纯函数结构校验、确定性 Mock 响应和破坏性变更检查。它不启动监听端口，因此不会被误当成生产服务。

## 本地验证

```bash
node --test tests/f03-contract-lab.test.mjs
node scripts/f03-contract-lab.mjs
```

通过只证明这组冻结契约、样例、Mock 和负例在本地一致，不证明身份、授权、企业连接、真实组件集成或生产就绪。
