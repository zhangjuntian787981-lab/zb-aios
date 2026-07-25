# F02：Synthetic Fixture Factory 与零企业数据门

本目录只包含固定种子生成的虚构测试数据，不读取脱敏真实数据、企业资料或环境秘密。

## 固定输入与输出

- `seed-catalog.v1.json`：唯一允许的三个固定种子，域名全部使用 `.example`。
- `fixture.schema.json`：Synthetic Tenant、用户、组织、知识、权限、流程、指标和 Connector 响应的 Schema。
- `generated/`：由固定种子生成的三个 Tenant；每条数据记录均含 `watermark: "SYNTHETIC"`。
- `fixture-inventory.v1.json`：每个 Tenant 的记录数和内容哈希。

## 两个独立门

1. `protected-surface-policy.v1.json` 检查 Product Core、Fixtures、评测真值、运行库和发布包中的凭据、未水印记录、禁止企业标识与 Public Context 标记。
2. `public-context-registry/` 保存公开外部信息的来源、时间和内容哈希；Containment 校验要求它位于产品包之外，并检查登记条目未进入产品包。

`negative/` 是只用于证明阻断能力的三类负例，不得复制到产品包。`reports/` 是固定输入下的报告样例。

扫描通过只说明没有命中已配置的指标，**不等于证明不存在企业数据**。进入发布门前仍需人工来源复核和独立隔离检查。

## 本地验证

```bash
node scripts/f02-fixtures.mjs refresh-evidence
node scripts/f02-fixtures.mjs scan implementation/p0/f02/generated
node --test tests/f02-fixtures.test.mjs
npx eslint scripts/f02-fixtures.mjs tests/f02-fixtures.test.mjs
```
