# P0-B07 / F03-AC06 开工前官方参考研究 v1

- 查询日期：2026-07-30
- 查询范围：仅官方标准正文、官方仓库、官方发布、官方安全资料
- 本地实现基线：`96ccc8fd375cf895285c42971b76863184b320b0`
- 本地实现 Tree：`708fc19391882e24180602ad17f16d0356d7aa5e`
- 状态：`RESEARCH_INPUT_ONLY`
- 治理效力：`NONE`
- 数据边界：`P0_SYNTHETIC_ONLY`

## 1. 结论

P0-B07 的目标是证明路径、操作、响应、属性、必填、类型、枚举和引用等破坏性变更会被真实托管 CI 阻断。

官方资料支持固定契约的语法、验证语义、事件外壳、错误对象和 CI 安全边界，但没有任何一个被审查标准替本项目定义完整的“向后兼容”算法。因此推荐：

1. 建议后续正式采用 JSON Schema 2020-12、OpenAPI 3.1.2、CloudEvents 1.0.2 Core/JSON、RFC 9457；
2. 建议后续正式采用 Ajv 8.20.0 与 ajv-formats 2.1.1，限定为冻结、可信 Schema 的构建期和测试期校验；
3. 将当前八类 breaking mutation 作为项目自己的兼容策略，而不是宣称它是 OpenAPI 或 JSON Schema 的规范结论；
4. 复用已审查的 GitHub Actions 安全模式及精确 SHA，但为 F03 增加明确执行兼容测试的托管 CI 步骤；
5. 取得一条真实托管 CI 正向成功运行和一条只含 Synthetic mutation 的失败运行后，才可补足 P0-B07；
6. 当前本地测试和 P0-B04 的 F02 托管运行不能冒充 P0-B07 的 F03 托管阻断证据。

## 2. 决定总表

| 候选 | 固定版本 | 治理决定建议 | 实施方式 | 主要边界 |
|---|---|---|---|---|
| JSON Schema | Draft 2020-12 | `ADOPT` | 直接作为三个 Canonical Schema 的方言 | 不定义 API 演进兼容性 |
| OpenAPI | 3.1.2 | `ADOPT` | 直接作为六类最小 HTTP 契约格式 | 不定义完整 breaking-change 算法 |
| CloudEvents | 1.0.2 Core + JSON Format | `ADOPT` | 约束当前 JSON 事件外壳 | HTTP Binding 暂不作为当前外壳的必需实现 |
| CloudEvents HTTP Binding | 1.0.2 | `DEFER` | 等 F03 引入传输映射时重审 | 当前只冻结 JSON envelope |
| RFC 9457 | July 2023 | `ADOPT` | 固定 Problem Details 字段和安全边界 | 错误格式不替代授权和业务错误分类 |
| Ajv | 8.20.0 | `ADOPT` | `Ajv2020`、`strict: true`、固定可信 Schema | 不接受不可信 Schema；生产不得默认 `allErrors: true` |
| ajv-formats | 2.1.1 | `ADOPT`（受限） | 只启用当前需要的格式；评估正则风险 | 所有内置 format 均不能被假设为抗 ReDoS |
| GitHub Actions | 官方托管服务，文档快照见下文 | `ADOPT` | `pull_request`、最小权限、固定 Action SHA | 不使用 `pull_request_target` 执行 PR 代码 |
| actions/checkout | v4.4.0 / `11d5960…` | `ADOPT` | 精确 SHA，`persist-credentials: false` | 仓库策略尚未强制所有 Action 固定 SHA |
| actions/setup-node | v4.4.0 / `49933ea…` | `ADOPT` | 精确 SHA，Node 24，无 npm cache | 当前 Action 元数据仍目标 Node 20，由 runner 强制 Node 24 |
| Pact JS | 17.0.1 / `b58ec048…` | `DEFER` | 等出现独立部署的消费者/提供者契约生命周期时重审 | 不能替代当前静态 old/new Schema 兼容门 |
| WireMock | 3.13.2 / `88587aa1…` | `NOT_APPLICABLE` | 当前不引入 JVM/容器化 HTTP 服务虚拟化 | F03 当前不依赖外部 HTTP 服务 |
| Schemathesis | 4.24.3 / `613ce317…` | `DEFER` | 等出现可运行 API 的属性测试范围时重审 | 不能替代静态 breaking mutation 判定；会增加 Python 工具链 |
| Testcontainers for Node.js | 12.0.4 / tag `42866612…` | `NOT_APPLICABLE` | 当前纯 Node 契约测试不启动外部依赖 | npm `gitHead` 与 release tag 来源存在待澄清差异 |
| 当前八类 mutation 策略 | `f03-breaking-mutation-cases.v1` | `ADAPT` | 项目策略映射到官方契约对象 | 不是任何外部标准的原生兼容结论 |

说明：正式 Reference Review Receipt 的决定枚举目前只有 `ADOPT`、`REJECT`、`DEFER`、`NOT_APPLICABLE`。表中的 `ADAPT` 只描述本项目的实施方式；正式 Receipt 应把对应官方标准记为 `ADOPT`，并把本地 mutation 规则记录为采用后的项目策略。

## 3. 当前实现事实

### 3.1 已存在

- `implementation/p0/f03/schemas/*.json` 使用 `https://json-schema.org/draft/2020-12/schema`；
- 六个契约声明 OpenAPI `3.1.2`；
- CloudEvent 和 RFC 9457 Problem Details 均有冻结 Schema；
- `package.json` 精确锁定：
  - `ajv` `8.20.0`；
  - `ajv-formats` `2.1.1`；
- `package-lock.json` 精确锁定：
  - Ajv tarball integrity：`sha512-Thbli+OlOj+iMPYFBVBfJ3OmCAnaSyNn4M1vz9T6Gka5Jt9ba/HIR56joy65tY6kx/FCF5VXNB819Y7/GUrBGA==`；
  - ajv-formats tarball integrity：`sha512-Wx0Kx52hxE7C18hkMEggYlEifqWZtYaRgouJor+WMdPnQyEK13vgEWyVNup7SoeeoLMsr4kf5h6dOW11I15MUA==`；
- `scripts/f03-contract-lab.mjs` 使用 `Ajv2020`，配置 `strict: true`、`validateFormats: true`；
- `implementation/p0/f03/breaking-mutation-cases.v1.json` 已冻结八类 mutation：
  - `PATH_REMOVED`；
  - `OPERATION_REMOVED`；
  - `RESPONSE_REMOVED`；
  - `PROPERTY_REMOVED`；
  - `REQUIRED_PROPERTY_ADDED`；
  - `TYPE_CHANGED`；
  - `ENUM_VALUE_REMOVED`；
  - `REFERENCE_CHANGED`。

### 3.2 仍缺

- 当前 F03 补证明确记录 `PARTIAL_EXTERNAL_CI_PENDING`；
- 已有本地 CLI 的退出码测试，但没有一条由 F03 mutation 触发的真实托管 CI 失败回执；
- 当前 F02 workflow 的 `npm run build` 不等于明确运行 `tests/f03-contract-lab.test.mjs`，不能仅凭 F02 的正负运行推断 F03 mutation 已在托管 CI 执行；
- 当前没有 GitHub Ruleset/branch protection 的可用证明；这不影响证明“CI 会失败”，但影响未来证明“失败检查必然阻止合并”；
- CloudEvents HTTP Binding 尚未成为当前 F03 JSON envelope 的运行依赖；
- 目前未冻结正式 P0-B07 Reference Review Receipt、Bundle 或 Freeze Attestation。

## 4. 官方参考详表

### 4.1 JSON Schema Draft 2020-12

**固定来源**

- 权威发布页：[Draft 2020-12](https://json-schema.org/draft/2020-12)
- Core：[JSON Schema Core](https://json-schema.org/draft/2020-12/json-schema-core.html)
- Validation：[JSON Schema Validation](https://json-schema.org/draft/2020-12/json-schema-validation.html)
- Release Notes：[2020-12 Release Notes](https://json-schema.org/draft/2020-12/release-notes)
- 官方仓库 `2020-12` 分支查询快照 commit：[`601a66c8b0f25246bf0e1fb488c5b5f030a79b72`](https://github.com/json-schema-org/json-schema-spec/tree/601a66c8b0f25246bf0e1fb488c5b5f030a79b72)
- 官方发布时间：2022-06-16
- 规范标识：`draft-bhutton-json-schema-01`、`draft-bhutton-json-schema-validation-01`

官方仓库没有为 Draft 2020-12 提供 GitHub Release 或同名不可变 tag。因此正式 Receipt 应把 `https://json-schema.org/draft/2020-12/` 的版本化 URI作为规范权威，将上述 commit 仅作为查询日的官方源码快照，不得把活动分支名本身当成不可变制品。

**实际阅读范围**

- Core：数据模型、Schema dialect/vocabulary、标识与 `$ref`/`$dynamicRef`；
- Validation：`type`、数值、字符串、数组、对象、`required`、`enum`、`format`；
- Release Notes：`prefixItems`/`items`、动态引用和 format vocabulary 的 2020-12 变化。

**许可证**

- 官方仓库声明可在 BSD 3-Clause 或 Academic Free License 3.0 中择一；
- 固定许可证来源：[official LICENSE](https://github.com/json-schema-org/json-schema-spec/blob/0c46441fe869d670a01eb489cf075e7bd7ca0235/LICENSE)。

**适用结论**

`ADOPT`。当前 Schema 已明确声明 2020-12；Ajv 必须使用 `Ajv2020`。规范定义关键词语义，但没有定义 OpenAPI 路径、响应和跨版本兼容政策。

### 4.2 OpenAPI Specification 3.1.2

**固定来源**

- 权威 HTML：[OpenAPI Specification 3.1.2](https://spec.openapis.org/oas/v3.1.2.html)
- 官方 tag：[`3.1.2`](https://github.com/OAI/OpenAPI-Specification/releases/tag/3.1.2)
- tag commit：[`82603363df271c104c8f527f0fe641ea67da93fd`](https://github.com/OAI/OpenAPI-Specification/blob/82603363df271c104c8f527f0fe641ea67da93fd/versions/3.1.2.md)
- commit 时间：2025-09-19T15:38:24Z

**实际阅读范围**

- Definitions；
- OpenAPI Description Structure 与 Parsing Documents；
- Paths Object；
- Path Item Object；
- Operation Object；
- Responses Object 与 Response Object；
- Reference Object；
- Schema Object；
- Security Requirement Object。

3.1.2 明确继承 JSON Schema Draft 2020-12 的解析要求，并定义自己的 OAS dialect。Schema Object 是 Draft 2020-12 的超集，不能假设普通 JSON Schema validator 会理解所有 OAS base vocabulary 关键词。

**许可证**

- Apache License 2.0；
- 固定许可证来源：[LICENSE at 3.1.2 commit](https://github.com/OAI/OpenAPI-Specification/blob/82603363df271c104c8f527f0fe641ea67da93fd/LICENSE)。

**适用结论**

`ADOPT`。它定义比较对象的语义，但不提供完整 breaking-change 分类。八类 mutation 必须继续标记为项目兼容策略。

### 4.3 CloudEvents 1.0.2

**固定来源**

- 官方 tag：[`v1.0.2`](https://github.com/cloudevents/spec/tree/v1.0.2)
- tag commit：[`fc1f6f31f5f011a72183f1bcea20c987cb683ade`](https://github.com/cloudevents/spec/tree/fc1f6f31f5f011a72183f1bcea20c987cb683ade)
- Core：[cloudevents/spec.md](https://github.com/cloudevents/spec/blob/fc1f6f31f5f011a72183f1bcea20c987cb683ade/cloudevents/spec.md)
- JSON Format：[json-format.md](https://github.com/cloudevents/spec/blob/fc1f6f31f5f011a72183f1bcea20c987cb683ade/cloudevents/formats/json-format.md)
- HTTP Binding：[http-protocol-binding.md](https://github.com/cloudevents/spec/blob/fc1f6f31f5f011a72183f1bcea20c987cb683ade/cloudevents/bindings/http-protocol-binding.md)
- commit 时间：2025-08-19T19:51:46Z

该官方版本只有 tag，没有对应 GitHub Release 对象；应固定 tag commit，而不是写成一个不存在的 Release。

**实际阅读范围**

- Core：Context Attributes、Event Data、Size Limits、Privacy & Security；
- JSON Format：Attributes、Envelope、`data`/`data_base64`、batch；
- HTTP Binding：Content Modes、HTTP Message Mapping、Security。

**许可证**

- Apache License 2.0；
- 固定许可证来源：[LICENSE at v1.0.2 commit](https://github.com/cloudevents/spec/blob/fc1f6f31f5f011a72183f1bcea20c987cb683ade/LICENSE)。

**适用结论**

- Core + JSON Format：`ADOPT`；
- HTTP Binding：`DEFER`，触发条件为 F03 开始冻结 HTTP 级 CloudEvent 传输映射。当前只冻结 JSON envelope，不应虚构已实现 binary/structured HTTP mode。

### 4.4 RFC 9457 Problem Details

**固定来源**

- 权威 HTML：[RFC 9457](https://www.rfc-editor.org/rfc/rfc9457.html)
- 权威文本：[RFC 9457 TXT](https://www.rfc-editor.org/rfc/rfc9457.txt)
- 发布：2023-07
- 状态：Standards Track；obsoletes RFC 7807

**实际阅读范围**

- §3 Problem Details JSON Object；
- §3.1 成员 `type`、`status`、`title`、`detail`、`instance`；
- §3.2 Extension Members；
- §4 Defining New Problem Types；
- §5 Security Considerations。

**许可证**

- RFC 文本受 [IETF Trust Legal Provisions 5.0](https://trustee.ietf.org/documents/trust-legal-provisions/tlp-5/) 约束；
- 它不是一个可简单写成 MIT/Apache 的软件包许可证；
- 若抽取 RFC 中明确标记的 Code Components，需遵守 TLP 的 Revised BSD 条款及通知要求；
- 当前项目只实现字段语义并引用 RFC，不复制规范全文。

**适用结论**

`ADOPT`。Problem Details 只规范错误表达，不证明授权正确，也不允许返回堆栈、秘密、内部路径或敏感 `detail`。

### 4.5 Ajv 8.20.0

**固定来源**

- 官方 Release：[`v8.20.0`](https://github.com/ajv-validator/ajv/releases/tag/v8.20.0)
- tag commit：[`0fba0b8e649909613cfce0999b149cd08f4a4987`](https://github.com/ajv-validator/ajv/tree/0fba0b8e649909613cfce0999b149cd08f4a4987)
- 发布时间：2026-04-24T13:24:27Z
- 官方文档：
  - [JSON Schema versions](https://ajv.js.org/json-schema.html)
  - [Strict mode](https://ajv.js.org/strict-mode.html)
  - [Options](https://ajv.js.org/options)
  - [Security considerations](https://ajv.js.org/security.html)
  - [Standalone validation code](https://ajv.js.org/standalone.html)

**实际阅读范围**

- Draft 2020-12 必须使用独立 `Ajv2020` class；
- 2020-12 不能与旧 Draft 在同一 Ajv instance 混用；
- Strict mode 对未知或被忽略关键词失败关闭；
- `validateFormats`、`allErrors` 和代码生成安全边界；
- 不可信 Schema、深度、慢验证、正则 ReDoS、CSP 和 standalone code。

**许可证**

- MIT；
- 固定许可证来源：[LICENSE at v8.20.0 commit](https://github.com/ajv-validator/ajv/blob/0fba0b8e649909613cfce0999b149cd08f4a4987/LICENSE)。

**适用结论**

`ADOPT`。当前 `Ajv2020({ strict: true, validateFormats: true })` 与官方方向一致。当前 `allErrors: true` 只允许用于可信、冻结 Schema 的构建和测试；不得无审查迁移到生产不可信输入路径。

### 4.6 ajv-formats 2.1.1

**固定来源**

- 官方 Release：[`v2.1.1`](https://github.com/ajv-validator/ajv-formats/releases/tag/v2.1.1)
- annotated tag object：`3ffaf922c91069b353958b034d85a8b5aeb1e9a2`
- peeled commit：[`c1cb46cad79f984020a9a0ef569e9c091ce24400`](https://github.com/ajv-validator/ajv-formats/tree/c1cb46cad79f984020a9a0ef569e9c091ce24400)
- 发布时间：2021-08-14T09:47:52Z
- 官方 README：[Usage、Formats、Options、Tests、License](https://github.com/ajv-validator/ajv-formats/blob/c1cb46cad79f984020a9a0ef569e9c091ce24400/README.md)

**实际阅读范围**

- format 清单；
- 默认 `full` 与 `fast` 模式；
- `fast` 会简化 date/time/URI/email 等校验；
- peer dependency `ajv ^8.0.0`；
- 未知 format 与 strict mode 的关系；
- Ajv 安全文档对 ajv-formats 正则和 ReDoS 的警告。

**许可证**

- MIT；
- 固定许可证来源：[LICENSE at v2.1.1 commit](https://github.com/ajv-validator/ajv-formats/blob/c1cb46cad79f984020a9a0ef569e9c091ce24400/LICENSE)。

**适用结论**

`ADOPT`，但必须限制：

1. Schema 必须是 Git 冻结且可信的；
2. 只启用 F03 实际需要的 format；
3. 对字符串增加合理的长度上限；
4. 若未来校验攻击者可控数据，必须单独评估每个 format、`fast` 模式或自定义实现；
5. 不能宣称插件自带 format 均抗 ReDoS。

### 4.7 GitHub Actions、checkout 与 setup-node

**固定官方文档**

- GitHub Docs 查询快照 commit：[`6f69b5126a8616e7fab257af61999e8f9416250d`](https://github.com/github/docs/tree/6f69b5126a8616e7fab257af61999e8f9416250d)
- [Workflow syntax](https://github.com/github/docs/blob/6f69b5126a8616e7fab257af61999e8f9416250d/content/actions/reference/workflows-and-actions/workflow-syntax.md)
- [Secure use reference](https://github.com/github/docs/blob/6f69b5126a8616e7fab257af61999e8f9416250d/content/actions/reference/security/secure-use.md)
- [Actions organization policy](https://github.com/github/docs/blob/6f69b5126a8616e7fab257af61999e8f9416250d/content/organizations/managing-organization-settings/disabling-or-limiting-github-actions-for-your-organization.md)

**实际阅读范围**

- `pull_request` 与 `pull_request_target`；
- `permissions` 和未声明权限降为 `none`；
- fork PR 的 token 限制；
- 精确完整 commit SHA 是 Action 不可变引用的官方推荐；
- organization/repository 可要求 SHA pin，但当前仓库尚未证明启用该策略。

**actions/checkout**

- Release：[`v4.4.0`](https://github.com/actions/checkout/releases/tag/v4.4.0)
- commit：[`11d5960a326750d5838078e36cf38b85af677262`](https://github.com/actions/checkout/tree/11d5960a326750d5838078e36cf38b85af677262)
- 发布时间：2026-07-20T15:36:10Z
- License：MIT
- 采用配置：`persist-credentials: false`

**actions/setup-node**

- Release：[`v4.4.0`](https://github.com/actions/setup-node/releases/tag/v4.4.0)
- commit：[`49933ea5288caeca8642d1e84afbd3f7d6820020`](https://github.com/actions/setup-node/tree/49933ea5288caeca8642d1e84afbd3f7d6820020)
- 发布时间：2025-04-14T02:55:06Z
- License：MIT
- 采用配置：Node 24；不启用 npm cache

**适用结论**

`ADOPT` 以下最小模式：

```yaml
on:
  pull_request:

permissions:
  contents: read

jobs:
  f03-compatibility:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262
        with:
          persist-credentials: false
      - uses: actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020
        with:
          node-version: "24"
      - run: npm ci --ignore-scripts --no-audit --no-fund
      - run: node --test tests/f03-contract-lab.test.mjs
```

这是研究建议，不是已写入 workflow 的实现。

明确 `REJECT`：

- 使用 `pull_request_target` checkout 并执行 PR 代码；
- 使用 floating tag 代替完整 commit SHA；
- 持久化 checkout 凭据；
- 把未经验证的 fork PR secrets 暴露给测试；
- 仅运行 `npm run build` 却宣称 F03 mutation 测试已经执行。

### 4.8 Pact JS 17.0.1

**固定来源**

- 官方仓库：[pact-foundation/pact-js](https://github.com/pact-foundation/pact-js)
- 官方 Release：[`v17.0.1`](https://github.com/pact-foundation/pact-js/releases/tag/v17.0.1)
- annotated tag object：`cbe2552414587c671f81b0bac1998a5fd7155fc9`
- peeled commit：[`b58ec048b47974d7f416f5da0843c41b616ee8b6`](https://github.com/pact-foundation/pact-js/tree/b58ec048b47974d7f416f5da0843c41b616ee8b6)
- 发布时间：2026-07-01T12:13:42Z
- 官方实现指南：[Pact JS](https://docs.pact.io/implementation_guides/javascript/readme)
- 官方消费者测试说明：[Consumer tests](https://docs.pact.io/implementation_guides/javascript/docs/consumer)
- 官方提供者验证说明：[Provider verification](https://docs.pact.io/implementation_guides/javascript/docs/provider)
- npm 包：[`@pact-foundation/pact@17.0.1`](https://www.npmjs.com/package/@pact-foundation/pact/v/17.0.1)
- npm tarball integrity：`sha512-Gnzy9fMK0Wu6UB8u0fYcso5fiEZk+Tu2lG9zR5DoJiwWBanb/9/pOmRrBWtOHn5EdgvEvzIF1huB39sZIc27Rw==`
- npm `gitHead`：`b58ec048b47974d7f416f5da0843c41b616ee8b6`
- Node 要求：`>=22`

**实际阅读范围**

- consumer-driven contract 的生成和匹配；
- provider verification；
- Pact Broker/契约发布的可选生命周期；
- 原生 FFI 依赖和预构建二进制；
- 安装分析与退出机制。

官方说明安装过程可能通过 Scarf 收集匿名分析；可设置 `PACT_DO_NOT_TRACK=1` 或 `SCARF_ANALYTICS=false` 禁用。若以后采用，CI 和受控构建环境必须显式禁用不需要的遥测，并审查原生二进制来源。

**许可证**

- MIT；
- 固定许可证来源：[LICENSE at v17.0.1 commit](https://github.com/pact-foundation/pact-js/blob/b58ec048b47974d7f416f5da0843c41b616ee8b6/LICENSE)。

**适用结论**

`DEFER`。Pact JS 解决的是消费者与提供者之间的契约生成、交换和提供者验证；P0-B07 当前需要证明冻结 old/new Schema 的八类 breaking mutation 会被托管 CI 阻断。它不能替代当前静态兼容门，且会引入 FFI、契约发布及可选 Broker 运维。

重新审查触发条件：

1. 出现独立部署、独立版本演进的真实消费者和提供者；
2. 明确 Pact Broker 或等价契约分发/保留责任；
3. 完成无企业真实数据的 Synthetic PoC；
4. 冻结 Node、npm integrity、FFI 来源、遥测关闭和退出路径。

### 4.9 WireMock 3.13.2

**固定来源**

- 官方仓库：[wiremock/wiremock](https://github.com/wiremock/wiremock)
- 官方 Release：[`3.13.2`](https://github.com/wiremock/wiremock/releases/tag/3.13.2)
- tag commit：[`88587aa13b4899da080538e1b21bec0da105491e`](https://github.com/wiremock/wiremock/tree/88587aa13b4899da080538e1b21bec0da105491e)
- 发布时间：2025-11-14T14:39:57Z
- 官方安装说明：[Download and Installation](https://wiremock.org/docs/download-and-installation/)
- 官方 Stubbing：[Stubbing](https://wiremock.org/docs/stubbing/)
- 官方请求匹配：[Request Matching](https://wiremock.org/docs/request-matching/)
- 官方 standalone JAR：[Running as a Standalone Process](https://wiremock.org/docs/standalone/java-jar/)
- Java source compatibility：11

**实际阅读范围**

- standalone JAR 和容器运行；
- HTTP response stubbing；
- request matching；
- 代理、录制和服务虚拟化边界；
- JVM 运行要求。

**许可证**

- Apache License 2.0；
- 固定许可证来源：[LICENSE at 3.13.2 commit](https://github.com/wiremock/wiremock/blob/88587aa13b4899da080538e1b21bec0da105491e/LICENSE)。

**适用结论**

`NOT_APPLICABLE`。当前 F03/P0-B07 是纯 Node、冻结契约和 Synthetic mutation 的静态兼容性验证，不调用外部 HTTP 服务，也不需要 JVM、standalone server 或容器化服务虚拟化。此结论不是否定 WireMock 的能力；若未来工作包需要模拟真实 HTTP 依赖，应在对应工作包重新识别候选，而不是让它阻断本次 P0-B07。

### 4.10 Schemathesis 4.24.3

**固定来源**

- 官方仓库：[schemathesis/schemathesis](https://github.com/schemathesis/schemathesis)
- 官方 Release：[`v4.24.3`](https://github.com/schemathesis/schemathesis/releases/tag/v4.24.3)
- annotated tag object：`636146b5b8e339e15305c0b92f5a7a15da36cd2d`
- peeled commit：[`613ce31793d999a1ed43f2b8b8529d14a60710e8`](https://github.com/schemathesis/schemathesis/tree/613ce31793d999a1ed43f2b8b8529d14a60710e8)
- 发布时间：2026-07-25T22:54:19Z
- 官方文档：[Schemathesis documentation](https://schemathesis.readthedocs.io/en/stable/)
- 官方快速开始：[Quick start](https://schemathesis.readthedocs.io/en/stable/quick-start/)
- 官方检查说明：[Checks](https://schemathesis.readthedocs.io/en/stable/reference/checks/)
- 官方 CI/CD 指南：[CI/CD](https://schemathesis.readthedocs.io/en/stable/guides/cicd/)
- PyPI：[`schemathesis==4.24.3`](https://pypi.org/project/schemathesis/4.24.3/)
- Python 要求：`>=3.10`

**实际阅读范围**

- 从 OpenAPI Schema 生成 property-based API cases；
- OpenAPI 2.0、3.0、3.1 和 3.2 支持范围；
- response schema、status code 和 content-type 等检查；
- CLI 和 CI/CD 执行；
- Python 工具链边界。

**许可证**

- MIT；
- 固定许可证来源：[LICENSE at v4.24.3 commit](https://github.com/schemathesis/schemathesis/blob/613ce31793d999a1ed43f2b8b8529d14a60710e8/LICENSE)。

**适用结论**

`DEFER`。Schemathesis 适合对可运行 API 做 property-based runtime conformance/fuzz testing，但不能替代 P0-B07 对 old/new 契约进行的静态 breaking-change 判定。当前引入它还会增加 Python 运行时和依赖锁，而本次验收没有可运行 provider 这一前置条件。

重新审查触发条件：

1. F03 获得明确的 loopback 或隔离 provider；
2. 定义运行时属性测试的失败分类和资源上限；
3. 冻结 Python、wheel/sdist、依赖和网络边界；
4. PoC 证明其结果是静态兼容门的补充而非替代。

### 4.11 Testcontainers for Node.js 12.0.4

**固定来源**

- 官方仓库：[testcontainers/testcontainers-node](https://github.com/testcontainers/testcontainers-node)
- 官方 Release：[`v12.0.4`](https://github.com/testcontainers/testcontainers-node/releases/tag/v12.0.4)
- tag commit：[`42866612cf2f35790f09066912b6e8f14243b98e`](https://github.com/testcontainers/testcontainers-node/tree/42866612cf2f35790f09066912b6e8f14243b98e)
- 发布时间：2026-06-29T11:52:28Z
- 官方安装说明：[Install](https://node.testcontainers.org/quickstart/install/)
- 官方使用说明：[Usage](https://node.testcontainers.org/quickstart/usage/)
- 官方等待策略：[Wait strategies](https://node.testcontainers.org/features/wait-strategies/)
- npm 包：[`testcontainers@12.0.4`](https://www.npmjs.com/package/testcontainers/v/12.0.4)
- npm tarball integrity：`sha512-QIR/8xF1+F/26cIM+9B4yyxNTbKJxAv3hygZyhPRgZ8Q2AhlPZjDdpXRuk16V37X4bgJRI3hXFhoEICMBA7Adg==`
- npm `gitHead`：`0414d5b3dbb586d7448973207cb318e688c42922`

官方 Release tag 指向 `42866612cf2f35790f09066912b6e8f14243b98e`，但 npm 元数据的 `gitHead` 是 `0414d5b3dbb586d7448973207cb318e688c42922`；且 tag 源码中的 `packages/testcontainers/package.json` 版本仍显示 `12.0.3`。在采用前必须由官方可验证材料解释这一来源差异，不能把 tag、npm tarball 和 `gitHead` 自动视为同一准确字节。

**实际阅读范围**

- 支持的容器运行时；
- GenericContainer 生命周期；
- 镜像拉取、端口映射、等待策略和清理；
- 本地与 CI 的容器运行前置条件。

**许可证**

- MIT；
- 固定许可证来源：[LICENSE at v12.0.4 tag commit](https://github.com/testcontainers/testcontainers-node/blob/42866612cf2f35790f09066912b6e8f14243b98e/LICENSE)。

**适用结论**

`NOT_APPLICABLE`。当前 F03/P0-B07 的契约兼容测试不需要数据库、消息系统或其他容器化依赖；引入 Testcontainers 会增加 daemon、镜像供应链、网络、缓存、清理和 runner 权限，而不会提高静态 mutation 判定的正确性。

若未来 F03 或其他工作包确需容器化依赖，必须重新审查并至少：

1. 先消除 release tag、npm `gitHead` 和包版本的来源歧义；
2. 固定 npm tarball integrity 和容器镜像 digest；
3. 定义 runner、网络、资源、缓存、cleanup 与故障恢复边界；
4. 完成隔离 PoC，再决定是否 `ADOPT`。

## 5. 八类 mutation 与官方对象的映射

| 项目 mutation | 官方语义来源 | 本项目判定 |
|---|---|---|
| `PATH_REMOVED` | OAS Paths Object | 已发布路径消失，项目判为 breaking |
| `OPERATION_REMOVED` | OAS Path Item / Operation Object | 已发布 HTTP operation 消失，项目判为 breaking |
| `RESPONSE_REMOVED` | OAS Responses Object | 已发布响应状态消失，项目判为 breaking |
| `PROPERTY_REMOVED` | JSON Schema properties / OAS Schema Object | 已发布属性消失，项目判为 breaking |
| `REQUIRED_PROPERTY_ADDED` | JSON Schema `required` | 新增请求必填项，项目判为 breaking |
| `TYPE_CHANGED` | JSON Schema `type` | 精确类型改变，项目判为 breaking |
| `ENUM_VALUE_REMOVED` | JSON Schema `enum` | 删除既有可用枚举值，项目判为 breaking |
| `REFERENCE_CHANGED` | JSON Schema/OAS `$ref` | 引用目标改变，项目保守判为 breaking |

这些判定是本项目的 fail-closed 策略。规范允许的变化不自动等于兼容，规范没有禁止的变化也不自动等于安全。

## 6. P0-B07 最小闭合路径

1. 保持上述标准和实现版本逐字固定；
2. 为 F03 托管 CI 明确运行 `tests/f03-contract-lab.test.mjs` 或等价专用命令；
3. 正向 PR：
   - 八类冻结 mutation 测试全部通过；
   - runner、workflow、Action SHA、head commit、job ID、日志摘要全部冻结；
4. 负向 PR：
   - 只引入一个 Synthetic breaking mutation；
   - F03 兼容门以稳定错误码失败；
   - CI job 必须 failure、进程非零退出；
   - PR 不得合并，负向分支不得进入发布；
5. 回读 GitHub Actions run/job 元数据并冻结原始日志 SHA-256；
6. 生成 P0-B07 追加式证据，但不修改历史 F03/G0/G1 状态；
7. 后续单独扩展 Reference Catalog/Policy，生成正式 `RETROSPECTIVE_BACKFILL` Receipt、Bundle 和 Freeze Attestation。

## 7. 许可证、运维和退出

| 参考 | 许可证/法律边界 | 再分发与退出建议 |
|---|---|---|
| JSON Schema | BSD-3-Clause 或 AFL-3.0 | 只引用规范并保留来源；若复制规范内容，选择并遵守一种许可证 |
| OpenAPI | Apache-2.0 | 保留许可证和 NOTICE 要求；本项目只实现规范 |
| CloudEvents | Apache-2.0 | 保留许可证和 NOTICE 要求；HTTP binding 未采用前不写成已实现 |
| RFC 9457 | IETF TLP 5.0 | 引用 RFC；抽取 Code Components 时遵守 Revised BSD 通知 |
| Ajv | MIT | 保留 MIT notice；版本升级需重跑 Schema 正负例 |
| ajv-formats | MIT | 保留 MIT notice；升级或 format 集合变化需重做 ReDoS 评估 |
| checkout/setup-node | MIT | 固定 SHA；升级先验证官方 tag/commit，再跑托管正负例 |
| Pact JS | MIT | 当前 `DEFER`；若采用，固定 npm integrity/FFI，禁用不需要的安装遥测并定义 Broker 退出 |
| WireMock | Apache-2.0 | 当前 `NOT_APPLICABLE`；不得为本次纯 Node 静态门额外引入 JVM/容器 |
| Schemathesis | MIT | 当前 `DEFER`；若采用，固定 Python 制品并把运行时属性测试与静态兼容门分开 |
| Testcontainers for Node.js | MIT | 当前 `NOT_APPLICABLE`；采用前先解决 tag/npm 来源差异并固定镜像 digest |
| GitHub Actions 服务 | GitHub 服务条款与官方文档 | 保留可迁移的 Node 测试命令；退出时可迁到其他托管 CI |

退出原则：兼容性判定逻辑应保持普通 Node 命令可执行，GitHub Actions 只做托管执行和证据采集，不能把算法锁死在 GitHub 专有 API 中。

## 8. 未知、限制和不得宣称

- `UNKNOWN`：当前没有正式 P0-B07 Reference Review Receipt、Bundle 和 Freeze Attestation；
- `UNKNOWN`：当前私有仓库套餐下无法证明 Ruleset/branch protection 已强制 required check；
- `NOT_PROVED`：尚未取得 F03 mutation 的真实托管 CI 正负回执；
- `NOT_PROVED`：未测试 fork PR 的 F03 行为；
- `DEFERRED`：CloudEvents HTTP Binding；
- `DEFERRED`：Pact JS，等待真实消费者/提供者契约生命周期和 Broker/退出责任；
- `DEFERRED`：Schemathesis，等待可运行 API 和属性测试范围；
- `NOT_APPLICABLE`：WireMock 与 Testcontainers for Node.js 不属于当前纯 Node 静态兼容门的必要依赖；
- `UNKNOWN`：Testcontainers for Node.js `v12.0.4` release tag、npm `gitHead` 与 tag 源码包版本之间的来源差异尚无充分官方解释；
- 不得宣称 JSON Schema、OpenAPI 或 Ajv 自动提供了完整 API 兼容性保证；
- 不得把本地 PASS、普通 commit、P0-B04 的 F02 run 或本研究文件解释为 P0-B07 已闭合；
- 不得把 Synthetic 契约测试解释为真实企业系统接入或生产就绪；
- 不得把 GitHub Actions 成功解释为 G0/G1、Profile 或工作包状态变化。

## 9. 本研究采用与未采用

采用：

- 上述固定官方规范、官方软件版本、官方 Action commit；
- 版本化 URI、tag commit、软件 tarball integrity 和托管 CI 原始 run/job/log 作为后续证据链输入；
- 项目自己的八类 fail-closed mutation 策略。

未采用：

- 第三方兼容性工具或博客；
- Pact JS、WireMock、Schemathesis 或 Testcontainers for Node.js 的当前实际依赖引入；
- floating Action tag；
- `pull_request_target` 执行 PR 代码；
- 未经 PoC 的 CloudEvents HTTP Binding；
- 把任何候选写成生产采用；
- 任何真实企业数据、凭据或连接。

本研究只为后续 Reference Review Receipt 和 P0-B07 实施提供输入，不创建第二套状态真相，不修改 Manifest、D1、Gate、Profile、P0/P1 工作包状态或 O02/O03 授权。
