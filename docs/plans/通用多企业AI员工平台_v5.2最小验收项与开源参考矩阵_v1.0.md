# 通用多企业 AI 员工平台：v5.2 最小验收项与开源参考矩阵

- 文档版本：v1.0
- 整理日期：2026-07-27
- 输入方案：`docs/plans/通用多企业AI员工平台_完备工程级方案_v5.2.md`
- 输入方案 SHA-256：`4561e29937b0f6315c882e74959cbc990bf84413732e8c91e542600b259f2fa8`
- 工作包定义基线：`implementation/governance/work-package-manifest.v1.json`
- Manifest v1.0 SHA-256：`e1dd21cab94ae4febbeef2ad4a14b72999270e49940fc2a50a7a3aea073cdc4d`
- 研究边界：只采用官方仓库、官方规范和标准组织资料
- 文档性质：候选验收分解和实施学习索引，不是工作包状态或 Gate 事实源

> 本文保持 F01—T08 共 37 个父工作包，不创建第 38 个工作包，不创建平行进度真相。原子验收项只是父工作包内部的可判定分解；只有经批准的 Manifest 新版本才能改变正式验收定义。D1 仍是工作包状态、GateSubmission 和 GateDecision 的权威来源，Git 仍冻结实现、测试与验收证据。

## 1. 原子化规则

本文把“最小验收项”定义为同时满足以下条件的一项：

1. 只表达一个可以观察的结果；
2. 可以独立判定 `PASS` 或 `FAIL`；
3. 有明确测试方法或人工复核方法；
4. 有一个主证据回执；
5. 失败时可以明确阻断所属父工作包，而不依赖平均分掩盖；
6. 浏览器版本、存储类型、角色、故障类型等重复维度作为参数化测试用例，不为每个排列组合另建工作包。

表格中的参考强度：

- **直接**：项目或标准可直接支撑该验收的大部分实现或验证。
- **部分**：只能提供组件、测试工具或设计模式，平台权威语义仍需自建。
- **规范**：主要用于定义验收口径，不能代替实现。
- **无通用替代**：没有开源项目能够替代企业授权、人类签署或本项目的权威边界，只能参考相邻标准。

## 2. 官方参考目录

| 编号 | 领域 | 官方开源项目或规范 | 可学习/复用内容 | 不能替代的内容 |
|---|---|---|---|---|
| R01 | 规范化、哈希与来源 | [RFC 8785 JSON Canonicalization](https://www.rfc-editor.org/rfc/rfc8785)、[W3C PROV-O](https://www.w3.org/TR/prov-o/) | 确定性 JSON、内容摘要输入、来源关系 | Gate 权威、业务决定语义 |
| R02 | Schema 与 API | [JSON Schema 2020-12](https://json-schema.org/draft/2020-12)、[OpenAPI 3.1.1](https://spec.openapis.org/oas/v3.1.1.html)、[CloudEvents](https://github.com/cloudevents/spec)、[RFC 9457 Problem Details](https://www.rfc-editor.org/rfc/rfc9457) | 契约、事件外壳、错误格式、兼容边界 | 授权与业务正确性 |
| R03 | 契约与兼容测试 | [Pact](https://github.com/pact-foundation/pact-js)、[WireMock](https://github.com/wiremock/wiremock)、[Schemathesis](https://github.com/schemathesis/schemathesis)、[Testcontainers](https://github.com/testcontainers/testcontainers-node) | 消费者/提供者契约、Mock、Schema 生成测试、临时依赖环境 | 真实企业接入证明 |
| R04 | Synthetic Fixture 与秘密扫描 | [Faker](https://github.com/faker-js/faker)、[Hypothesis](https://github.com/HypothesisWorks/hypothesis)、[Gitleaks](https://github.com/gitleaks/gitleaks) | 固定种子虚构数据、属性测试、凭据扫描 | 证明没有企业语义或公开资料污染 |
| R05 | AI 与威胁建模 | [OWASP Threat Dragon](https://github.com/OWASP/threat-dragon)、[OWASP LLM Top 10](https://genai.owasp.org/llm-top-10/)、[MITRE ATLAS](https://atlas.mitre.org/)、[NIST AI RMF](https://www.nist.gov/itl/ai-risk-management-framework) | 信任边界、滥用案例、AI风险类别 | 本项目零容忍门与责任签署 |
| R06 | AI 评测与红队 | [promptfoo](https://github.com/promptfoo/promptfoo)、[garak](https://github.com/NVIDIA/garak)、[Langfuse](https://github.com/langfuse/langfuse) | 回归、红队、数据集、Trace、人工反馈 | C18 审计、权限与发布批准 |
| R07 | 产品前端与组件测试 | [Next.js](https://github.com/vercel/next.js)、[shadcn/ui](https://github.com/shadcn-ui/ui)、[Storybook](https://github.com/storybookjs/storybook)、[Playwright](https://github.com/microsoft/playwright) | 页面实现、组件目录、交互和浏览器 E2E | 服务端授权和业务状态真相 |
| R08 | 可访问性 | [WCAG 2.2](https://www.w3.org/TR/WCAG22/)、[axe-core](https://github.com/dequelabs/axe-core) | 可访问性要求、自动扫描 | 完整人工读屏结论或法律认证 |
| R09 | 身份联邦与生命周期 | [Keycloak](https://github.com/keycloak/keycloak)、[OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html)、[SCIM RFC 7643](https://www.rfc-editor.org/rfc/rfc7643)、[SCIM RFC 7644](https://www.rfc-editor.org/rfc/rfc7644) | OIDC/SAML、会话、身份联邦、Provisioning | 企业组织事实与业务授权 |
| R10 | 稳定身份与委托 | [RFC 9562 UUID](https://www.rfc-editor.org/rfc/rfc9562)、[RFC 8693 OAuth Token Exchange](https://www.rfc-editor.org/rfc/rfc8693)、[SPIFFE/SPIRE](https://github.com/spiffe/spire) | 稳定 ID、主体交换、工作负载身份 | 本项目 Principal 合并和委托政策 |
| R11 | 细粒度授权 | [OpenFGA](https://github.com/openfga/openfga)、[OPA](https://github.com/open-policy-agent/opa)、[AuthZEN](https://openid.net/specs/authorization-api-1_0.html) | ReBAC/ABAC、PDP/PEP、模型测试 | Runtime Authorization 的企业授权来源 |
| R12 | 多租户数据隔离 | [PostgreSQL Row Security](https://www.postgresql.org/docs/current/ddl-rowsecurity.html)、[pgvector](https://github.com/pgvector/pgvector)、[Kubernetes Multi-tenancy](https://kubernetes.io/docs/concepts/security/multi-tenancy/) | RLS、向量过滤、隔离设计 | 全存储面组合证明 |
| R13 | 状态、可靠任务与补偿 | [PostgreSQL](https://www.postgresql.org/docs/)、[CloudEvents](https://github.com/cloudevents/spec)、[pg-boss](https://github.com/timgit/pg-boss)、[Temporal](https://github.com/temporalio/temporal) | 事务、Outbox事件、队列、长流程和重试 | 外部副作用的业务幂等与人工门 |
| R14 | 个人状态与记忆 | [LangGraph](https://github.com/langchain-ai/langgraph)、[PostgreSQL](https://www.postgresql.org/docs/)、[pgvector](https://github.com/pgvector/pgvector) | Checkpoint、状态保存、向量召回 | 本人确认、隐私和删除政策 |
| R15 | 文档解析与来源 | [Docling](https://github.com/docling-project/docling)、[Apache Tika](https://github.com/apache/tika)、[ClamAV](https://github.com/Cisco-Talos/clamav)、[W3C PROV-O](https://www.w3.org/TR/prov-o/) | 多格式解析、元数据、恶意文件扫描、来源建模 | 企业资料发布授权与真实性 |
| R16 | 权限感知 RAG | [pgvector](https://github.com/pgvector/pgvector)、[OpenSearch](https://github.com/opensearch-project/OpenSearch)、[promptfoo](https://github.com/promptfoo/promptfoo) | 混合检索、向量/全文过滤、RAG 回归 | C06 权限真相和 EvidenceRef 业务语义 |
| R17 | Agent 编排 | [LangGraph](https://github.com/langchain-ai/langgraph)、[Semantic Kernel](https://github.com/microsoft/semantic-kernel)、[MCP Specification](https://modelcontextprotocol.io/specification/) | 显式状态图、节点、工具互操作 | 权限、预算、风险和批准决定 |
| R18 | Skill 制品与发布 | [Git](https://git-scm.com/docs)、[ORAS](https://github.com/oras-project/oras)、[Cosign](https://github.com/sigstore/cosign)、[promptfoo](https://github.com/promptfoo/promptfoo) | 版本、内容寻址、OCI制品、签名和评测 | Skill 业务批准与运行授权 |
| R19 | 模型服务与路由 | [LiteLLM](https://github.com/BerriAI/litellm)、[vLLM](https://github.com/vllm-project/vllm)、[KServe](https://github.com/kserve/kserve) | 统一模型接口、用量、推理服务和部署 | 数据分类、地区和企业授权政策 |
| R20 | Human workflow | [Temporal](https://github.com/temporalio/temporal)、[Flowable](https://github.com/flowable/flowable-engine)、[PostgreSQL](https://www.postgresql.org/docs/) | 持久流程、BPMN、事务状态机 | HumanDecision 定义和正式动作权限 |
| R21 | Tool Gateway | [OpenAPI](https://spec.openapis.org/oas/v3.1.1.html)、[MCP Specification](https://modelcontextprotocol.io/specification/)、[Envoy](https://github.com/envoyproxy/envoy)、[Kong](https://github.com/Kong/kong) | 窄接口、Schema、API网关、互操作 | 业务 Tool 授权和参数白名单 |
| R22 | Connector SDK 与 Mock | [Apache Camel](https://github.com/apache/camel)、[Pact](https://github.com/pact-foundation/pact-js)、[WireMock](https://github.com/wiremock/wiremock)、[Testcontainers](https://github.com/testcontainers/testcontainers-node) | Adapter、连接模式、Mock、兼容测试 | Connector Stage、企业授权和真实接口证据 |
| R23 | 追加审计与来源链 | [W3C PROV-O](https://www.w3.org/TR/prov-o/)、[RFC 8785](https://www.rfc-editor.org/rfc/rfc8785)、[Trillian](https://github.com/google/trillian) | 来源图、规范化哈希、透明日志模式 | C18 事件 Schema、保留政策与业务语义 |
| R24 | 可观测、用量与成本 | [OpenTelemetry](https://github.com/open-telemetry/opentelemetry-specification)、[Prometheus](https://github.com/prometheus/prometheus)、[Grafana](https://github.com/grafana/grafana)、[OpenCost](https://github.com/opencost/opencost) | Trace/Metric/Log、基础设施成本 | C19 去重用量与正式费率版本 |
| R25 | 隔离执行 | [Kata Containers](https://github.com/kata-containers/kata-containers)、[Firecracker](https://github.com/firecracker-microvm/firecracker)、[gVisor](https://github.com/google/gvisor)、[Kubernetes Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/) | microVM、沙箱运行时、Seccomp/PSS | 业务写回授权和输出业务正确性 |
| R26 | 密钥与工作负载身份 | [OpenBao](https://github.com/openbao/openbao)、[SPIRE](https://github.com/spiffe/spire)、[External Secrets Operator](https://github.com/external-secrets/external-secrets) | 动态秘密、租约、工作负载身份、Kubernetes Secret同步 | Enterprise User 权限 |
| R27 | 软件供应链 | [SLSA](https://slsa.dev/spec/)、[in-toto](https://github.com/in-toto/in-toto)、[Cosign](https://github.com/sigstore/cosign)、[Trivy](https://github.com/aquasecurity/trivy)、[Syft](https://github.com/anchore/syft)、[Kyverno](https://github.com/kyverno/kyverno) | Provenance、Attestation、签名、扫描、SBOM、准入 | 业务正确性与许可证法律结论 |
| R28 | SBOM 与许可证 | [CycloneDX](https://github.com/CycloneDX/specification)、[SPDX](https://spdx.dev/specifications/)、[ScanCode Toolkit](https://github.com/nexB/scancode-toolkit)、[FOSSology](https://github.com/fossology/fossology) | 依赖和许可证识别、SBOM格式 | 最终再分发和合同法律判断 |
| R29 | 部署与 GitOps | [Helm](https://github.com/helm/helm)、[Argo CD](https://github.com/argoproj/argo-cd)、[Kustomize](https://github.com/kubernetes-sigs/kustomize)、[OpenTofu](https://github.com/opentofu/opentofu) | 可重复打包、声明式部署、环境配置 | 数据迁移正确性和产品验收 |
| R30 | 备份、恢复与灾备 | [CloudNativePG](https://github.com/cloudnative-pg/cloudnative-pg)、[pgBackRest](https://github.com/pgbackrest/pgbackrest)、[Velero](https://github.com/velero-io/velero) | PostgreSQL HA/PITR、Kubernetes恢复 | Tenant级资产闭包和退出证明 |
| R31 | 性能、SLO 与混沌 | [k6](https://github.com/grafana/k6)、[Argo Rollouts](https://github.com/argoproj/argo-rollouts)、[Chaos Mesh](https://github.com/chaos-mesh/chaos-mesh)、[OpenSLO](https://github.com/OpenSLO/OpenSLO) | 压测、Canary、故障注入、SLO表达 | 业务质量、安全和隐私门 |
| R32 | 任务收件箱与通知 | [Novu](https://github.com/novuhq/novu) | 通知模板、偏好、投递、多渠道 | C08/C15事项和决定状态 |
| R33 | 图形工作台 | [React Flow](https://github.com/xyflow/xyflow)、[Node-RED](https://github.com/node-red/node-red) | 节点画布、可视化配置模式 | C12/C13运行、版本和权限真相 |
| R34 | AppSec | [OWASP ASVS](https://github.com/OWASP/ASVS)、[OWASP ZAP](https://github.com/zaproxy/zaproxy)、[DefectDojo](https://github.com/DefectDojo/django-DefectDojo) | 应用安全要求、DAST、漏洞闭环 | 风险自动接受或独立渗透签署 |
| R35 | 隐私工程 | [Fides](https://github.com/ethyca/fides)、[NIST Privacy Framework](https://www.nist.gov/privacy-framework/privacy-framework)、[W3C DPV](https://w3c-cg.github.io/dpv/2.0/dpv/) | 数据目录、隐私请求、政策词汇 | 具体法域法律意见 |
| R36 | 产品分析与权益 | [Matomo](https://github.com/matomo-org/matomo)、[PostHog](https://github.com/PostHog/posthog)、[OpenFeature](https://github.com/open-feature/spec)、[OpenMeter](https://github.com/openmeterio/openmeter) | 事件、漏斗、Feature Flag、权益和计量 | 员工绩效、会计与合同真相 |
| R37 | 文档与引导 | [Docusaurus](https://github.com/facebook/docusaurus)、[Driver.js](https://github.com/nilbuild/driver.js) | 版本化文档站、产品内引导 | 独立执行验收和培训效果 |
| R38 | 可移植数据包 | [BagIt RFC 8493](https://www.rfc-editor.org/info/rfc8493/)、[RO-Crate](https://www.researchobject.org/ro-crate/specification.html)、[Frictionless Data Package](https://specs.frictionlessdata.io/data-package/) | 文件清单、校验和、元数据和引用打包 | Tenant资产范围和保留例外 |
| R39 | 国际化 | [FormatJS](https://github.com/formatjs/formatjs)、[ECMA-402 Intl](https://tc39.es/ecma402/)、[WCAG 2.2](https://www.w3.org/TR/WCAG22/) | 语言、日期、时区、数字和可访问界面 | 翻译质量和真实用户复核 |
| R40 | 开发者入口 | [Scalar](https://github.com/scalar/scalar)、[OpenAPI Generator](https://github.com/OpenAPITools/openapi-generator)、[Backstage](https://github.com/backstage/backstage) | API文档、SDK生成、开发者门户模式 | API授权、密钥和审计真相 |
| R41 | 运行支持与事故 | [Uptime Kuma](https://github.com/louislam/uptime-kuma)、[Zammad](https://github.com/zammad/zammad)、[NIST SP 800-61r3](https://csrc.nist.gov/pubs/sp/800/61/r3/final)、[Google SRE Incident Response](https://sre.google/workbook/incident-response/) | 状态监测、工单、事件角色和流程 | 实际恢复证据和业务审批 |
| R42 | BI语义与指标 | [Cube](https://github.com/cube-js/cube)、[MetricFlow](https://github.com/dbt-labs/metricflow)、[dbt-core](https://github.com/dbt-labs/dbt-core) | 语义层、指标定义、版本化转换 | 企业认证口径和员工权益决定 |
| R43 | 后期视觉动效 | [React Bits](https://github.com/DavidHDev/react-bits) | 动画与交互参考 | 完整设计系统、可访问性、权限；采用前需复核 Commons Clause 等实际许可证 |

## 3. P0 原子验收矩阵

### F01 产品领域模型与阶段治理

| ID | 最小通过条件 | 验证与主证据 | 参考 |
|---|---|---|---|
| F01-AC01 | 领域词典分别定义 Stage Approval、Runtime Authorization 和 HumanDecision，且不存在同义混用 | Schema/文档术语扫描；领域词典回执 | 规范：R01、R02；核心语义需自建 |
| F01-AC02 | P0—P3 的入口、出口和依赖可以由程序判定 | 对完整和缺失依赖样本执行 Gate 检查；Gate规则回执 | 部分：R02、R03 |
| F01-AC03 | Frozen Evidence Package 有唯一的规范化序列化结果 | 同一逻辑对象乱序输入后字节完全一致；规范化回执 | 直接：R01 |
| F01-AC04 | 同一冻结包重复计算得到相同 SHA-256 | 至少三次独立计算及跨进程比较；哈希回执 | 直接：R01 |
| F01-AC05 | GateDecision 精确绑定一个不可变 GateSubmission 哈希 | 篡改 Submission 任一字节后旧Decision不再匹配；绑定测试回执 | 部分：R01、R02；决定语义自建 |
| F01-AC06 | Manifest 定义、D1状态和Git证据三类事实不会互相冒充 | 权威来源负例测试；事实源矩阵回执 | 无通用替代：R01仅提供来源表达 |

### F02 Synthetic Fixture Factory 与零企业数据门

| ID | 最小通过条件 | 验证与主证据 | 参考 |
|---|---|---|---|
| F02-AC01 | 三个固定种子的 Synthetic Tenant 可重复生成 | 清空输出后重复生成并比较摘要；Fixture生成回执 | 直接：R04 |
| F02-AC02 | 每个 Synthetic Tenant 内用户、组织、权限、知识和流程引用闭合 | Schema及引用完整性检查；Fixture清单回执 | 直接：R02、R04 |
| F02-AC03 | 所有合成资料和运行对象带可机器识别的 `SYNTHETIC` 标识 | 全量Surface扫描无缺失；水印检查回执 | 部分：R02、R04 |
| F02-AC04 | 受保护Surface出现已知真实企业标识时构建被阻断 | 注入负例并运行CI；企业标识门回执 | 部分：R04；企业语义词表自建 |
| F02-AC05 | 受保护Surface出现凭据模式时构建被阻断 | 注入Token/私钥/连接串负例；秘密扫描回执 | 直接：R04 |
| F02-AC06 | Public Enterprise Context 只能存在于独立Registry且不会进入发行包 | 注册合法公开资料后扫描构建制品；Containment回执 | 无通用替代：R04只能辅助扫描 |

### F03 API、事件、Schema 与兼容实验室

| ID | 最小通过条件 | 验证与主证据 | 参考 |
|---|---|---|---|
| F03-AC01 | Canonical Schema 均通过固定版本 JSON Schema 校验器 | 正例与负例运行；Schema验证回执 | 直接：R02 |
| F03-AC02 | Portal、Core、Model、Tool、Connector、Audit 均有版本化最小契约 | 契约目录枚举和缺失检查；契约清单回执 | 直接：R02 |
| F03-AC03 | 事件外壳符合冻结的 CloudEvents Profile | 事件正反例验证；事件兼容回执 | 直接：R02 |
| F03-AC04 | API错误符合 Problem Details 且不返回堆栈、秘密或内部路径 | 错误注入及响应扫描；错误安全回执 | 直接：R02、R03 |
| F03-AC05 | 消费者和提供者可以只依赖契约完成合成集成测试 | Pact/Mock执行通过；契约测试回执 | 直接：R03 |
| F03-AC06 | 不兼容变更在CI中被自动阻断 | 提交破坏字段、枚举和响应负例；兼容门回执 | 直接：R03 |
| F03-AC07 | 每个废弃接口都有版本、替代路径和停止日期 | 废弃矩阵完整性检查；Deprecation回执 | 部分：R02、R40 |

### F04 威胁模型、质量评测与发布门基线

| ID | 最小通过条件 | 验证与主证据 | 参考 |
|---|---|---|---|
| F04-AC01 | 资产、信任边界和数据流在版本化威胁模型中完整登记 | 与架构清单交叉核对；Threat Model回执 | 直接：R05 |
| F04-AC02 | 跨Tenant泄露测试任何一次命中都直接失败 | 运行冻结攻击集；零容忍回执 | 直接：R05、R06 |
| F04-AC03 | 服务端越权测试任何一次错误允许都直接失败 | 运行授权负例集；授权安全回执 | 直接：R05、R11 |
| F04-AC04 | 审批绕过测试任何一次成功都直接失败 | 篡改、过期和直接API负例；HumanDecision安全回执 | 部分：R05、R20；语义自建 |
| F04-AC05 | P0—P2 企业内部数据进入任一Surface时直接失败 | 企业标识和凭据Canary扫描；零企业数据回执 | 部分：R04、R05 |
| F04-AC06 | 冻结评测集在相同版本和种子下产生可重复结果 | 重复运行并比较原始结果；评测重复性回执 | 直接：R06 |
| F04-AC07 | 人工基线、阈值和分歧裁决在采证前冻结 | 核验Dataset/Metric/Adjudication摘要；发布门回执 | 规范：R05、R06 |

## 4. P1 原子验收矩阵

### C01 最终用户 AI 门户与身份 BFF

| ID | 最小通过条件 | 验证与主证据 | 参考 |
|---|---|---|---|
| C01-AC01 | BFF只接受服务端验证后的可信身份上下文 | 伪造Header/Cookie/客户端角色负例；身份边界回执 | 直接：R07、R09 |
| C01-AC02 | 绕过UI直接调用受保护API仍被拒绝 | 直接API授权负例；Portal授权回执 | 直接：R11 |
| C01-AC03 | 上传文件在进入知识流程前完成Tenant和Principal隔离 | 跨用户文件引用测试；上传隔离回执 | 部分：R07、R12、R15 |
| C01-AC04 | 流式回答的取消、超时和断线不会显示假成功 | E2E故障注入；流式状态回执 | 直接：R07、R13 |
| C01-AC05 | 回答引用可以打开准确EvidenceRef或明确显示不可用 | J01 E2E及来源位置对账；引用回执 | 部分：R07、R16 |
| C01-AC06 | 替换最小门户不迁移授权、HumanDecision或审计数据 | 替换Portal Adapter演练；可替换性回执 | 部分：R07；权威边界自建 |
| C01-AC07 | P1门户只能使用Synthetic Principal与Fixture | 运行库、Trace和截图Canary扫描；Synthetic范围回执 | 部分：R04、R07 |

### C02 Tenant 管理与治理门户

| ID | 最小通过条件 | 验证与主证据 | 参考 |
|---|---|---|---|
| C02-AC01 | 每个管理写命令都在服务端按可信主体重鉴权 | 直接API、篡改角色和重放测试；管理授权回执 | 直接：R11 |
| C02-AC02 | 业务管理员默认不能读取私人会话、个人记忆和未发布草稿 | 多角色负例矩阵；私人数据拒绝回执 | 直接：R11、R12 |
| C02-AC03 | 业务管理员不能更新或删除历史审计事件 | UI与API写入负例；审计不可变回执 | 部分：R23 |
| C02-AC04 | 配额、Connector状态和发布状态只展示Core权威投影 | 篡改前端状态后重新加载对账；投影一致性回执 | 部分：R07；状态语义自建 |
| C02-AC05 | 高风险管理变更产生可追溯的决定和审计引用 | 权限提升/发布/停用流程测试；高风险变更回执 | 部分：R11、R20、R23 |
| C02-AC06 | 隐藏菜单或修改路由参数不能扩大能力 | 路由遍历与按钮解锁负例；Capability View回执 | 直接：R07、R11 |

### C03 Tenant Registry 与生命周期

| ID | 最小通过条件 | 验证与主证据 | 参考 |
|---|---|---|---|
| C03-AC01 | 相同幂等键重复创建只产生一个Tenant | 并发和重试测试；创建幂等回执 | 部分：R13 |
| C03-AC02 | Provisioning部分失败时Tenant不会进入`ACTIVE` | 阶段故障注入；生命周期回执 | 部分：R13 |
| C03-AC03 | `tenant_kind` 创建后不可变 | SYNTHETIC→ENTERPRISE和反向变更负例；种类不可变回执 | 无通用替代：R02仅提供Schema |
| C03-AC04 | Synthetic与Enterprise使用不同ID Namespace且不能复用资产引用 | Namespace碰撞和复用负例；边界回执 | 部分：R10、R12 |
| C03-AC05 | Tenant暂停后所有新业务请求均被拒绝 | 跨模块暂停矩阵；暂停回执 | 部分：R11、R13 |
| C03-AC06 | Outbox/Reconciler在崩溃后收敛到唯一合法状态 | Worker崩溃、乱序和重放测试；对账回执 | 直接：R13 |
| C03-AC07 | 删除操作的每个数据面传播状态可查询且可证明 | SQL/向量/对象/缓存删除矩阵；删除传播回执 | 部分：R12、R35 |

### C04 身份联邦、SSO 与 Provisioning

| ID | 最小通过条件 | 验证与主证据 | 参考 |
|---|---|---|---|
| C04-AC01 | OIDC issuer、audience、signature、nonce和redirect均严格校验 | 错误Token及redirect负例；OIDC兼容回执 | 直接：R09 |
| C04-AC02 | SCIM重复事件不会创建重复IdentityLink | 重放Create/Update/Delete；SCIM幂等回执 | 直接：R09、R13 |
| C04-AC03 | 乱序事件不能恢复已离职或停用账号 | Delete后发送旧Update；账号生命周期回执 | 直接：R09 |
| C04-AC04 | 会话在停用后于冻结SLA内失效 | 停用后持续调用测试；会话撤销回执 | 直接：R09 |
| C04-AC05 | 同名或同邮箱身份不会自动合并 | 碰撞Fixture测试；身份碰撞回执 | 部分：R09、R10；合并政策自建 |
| C04-AC06 | 认证成功不自动获得任何业务权限 | 新身份登录后授权负例；认证授权分离回执 | 直接：R09、R11 |
| C04-AC07 | P1只连接Synthetic IdP/SCIM，配置中无企业端点或凭据 | 配置、网络和日志扫描；Synthetic IdP回执 | 部分：R04、R09 |

### C05 Stable Principal 与委托链

| ID | 最小通过条件 | 验证与主证据 | 参考 |
|---|---|---|---|
| C05-AC01 | 外部邮箱、姓名或IdP变化时`principal_id`保持不变 | 身份迁移测试；Stable Principal回执 | 部分：R10 |
| C05-AC02 | 同一外部身份在同一Tenant不能绑定多个活动Principal | 唯一约束和并发测试；IdentityLink回执 | 部分：R10、R13 |
| C05-AC03 | 同邮箱不会跨Tenant或跨身份源自动合并 | 多Tenant碰撞测试；隔离身份回执 | 部分：R10、R12 |
| C05-AC04 | Human、Agent和Service主体类型不可混淆 | Schema及非法转换负例；Principal类型回执 | 规范：R02、R10 |
| C05-AC05 | 每次动作同时记录human subject、workload actor和delegation | 代理及Agent调用链回放；委托链回执 | 部分：R10、R23 |
| C05-AC06 | 主体停用会传播到活动委托和工作负载会话 | 停用后委托调用负例；停用传播回执 | 部分：R09、R10、R13 |

### C06 统一授权策略与 PEP SDK

| ID | 最小通过条件 | 验证与主证据 | 参考 |
|---|---|---|---|
| C06-AC01 | 读取、检索、下载、管理、Tool和Sandbox路径全部登记在PEP覆盖表 | 路由/operation清单与PEP清单差异为零；覆盖回执 | 直接：R11 |
| C06-AC02 | 每条受保护路径都有Allow和Deny Fixture | 授权Fixture全量运行；策略测试回执 | 直接：R11 |
| C06-AC03 | 客户端、Prompt、Skill或MCP声明不能改变授权结果 | 注入角色和allowed-tools负例；授权权威回执 | 直接：R11、R17、R21 |
| C06-AC04 | 每个决定固定`authorization_model_id`和策略版本 | 决定记录完整性检查；策略绑定回执 | 直接：R11 |
| C06-AC05 | PDP故障时高敏路径失败关闭 | 关闭PDP并调用下载/Tool/Sandbox；故障关闭回执 | 直接：R11 |
| C06-AC06 | 历史授权决定可使用原模型和输入重放 | 决定回放对比；授权重放回执 | 直接：R11、R23 |
| C06-AC07 | 策略发布失败可回滚到上一已批准模型 | 错误模型发布演练；策略回滚回执 | 直接：R11 |
| C06-AC08 | 撤权在冻结SLA内影响缓存和全部PEP | 权限变更后跨路径重试；撤权传播回执 | 直接：R11、R12 |

### C07 Tenant 数据隔离与生命周期

| ID | 最小通过条件 | 验证与主证据 | 参考 |
|---|---|---|---|
| C07-AC01 | SQL、向量、对象、搜索、缓存和恢复副本的跨Tenant读取均为零 | 参数化全存储矩阵；隔离回执 | 直接/部分：R12 |
| C07-AC02 | PostgreSQL使用`FORCE RLS`且应用角色无`BYPASSRLS` | Catalog检查和Owner角色负例；RLS回执 | 直接：R12 |
| C07-AC03 | 向量和全文检索过滤由服务端可信上下文生成 | 篡改客户端Tenant Filter；检索隔离回执 | 直接：R11、R12、R16 |
| C07-AC04 | 对象Key、Bucket/Prefix策略和签名URL均绑定Tenant | 跨Tenant对象引用与URL重放；对象隔离回执 | 部分：R12 |
| C07-AC05 | 缓存Key包含隔离维度且命中后仍重鉴权 | 缓存污染和撤权后命中测试；缓存回执 | 直接：R11、R12 |
| C07-AC06 | 连接池复用不会残留上一个Tenant上下文 | 交替高并发Tenant测试；连接池回执 | 部分：R12、R13 |
| C07-AC07 | 恢复副本上线前重新通过隔离矩阵 | 从备份恢复后重跑负例；恢复隔离回执 | 直接：R12、R30 |
| C07-AC08 | 删除传播完成前资产不会重新进入检索或缓存 | 删除过程中持续查询；删除一致性回执 | 部分：R12、R16 |
| C07-AC09 | Tenant停用后所有数据面新访问均被拒绝 | 停用后参数化访问矩阵；停用传播回执 | 直接：R11、R12 |

### C08 AIOS 状态核心

| ID | 最小通过条件 | 验证与主证据 | 参考 |
|---|---|---|---|
| C08-AC01 | Case、Thread、Run、Artifact和ToolCall均绑定Tenant与Stable Principal | Schema及跨Tenant引用负例；状态Schema回执 | 部分：R02、R10、R13 |
| C08-AC02 | 一次Run可还原Model、Prompt、Skill、Knowledge、Tool和Policy版本 | Run回放与Digest闭包检查；可重放回执 | 部分：R01、R13、R23 |
| C08-AC03 | 业务状态变更和Outbox消息在同一事务提交 | 事务中断测试；Outbox原子性回执 | 直接：R13 |
| C08-AC04 | 相同幂等键和命令摘要不会创建重复状态转换 | 并发重试测试；命令幂等回执 | 部分：R13 |
| C08-AC05 | 崩溃后重放收敛到与无故障运行相同的终态 | 节点级Kill与重放；崩溃恢复回执 | 直接：R13 |
| C08-AC06 | 重试不会产生重复Tool或Connector副作用 | 故障窗口内重复消费；副作用去重回执 | 部分：R13、R20 |
| C08-AC07 | 自由聊天正文不会被当作正式流程状态 | 聊天内容注入状态指令负例；状态权威回执 | 无通用替代：R13仅提供运行机制 |
| C08-AC08 | 企业业务事实只保存引用、版本和回读证据，不复制为新权威 | 模拟源事实变更并对账；事实边界回执 | 无通用替代：R22仅提供Adapter模式 |

### C09 个人 Profile、会话与记忆

| ID | 最小通过条件 | 验证与主证据 | 参考 |
|---|---|---|---|
| C09-AC01 | 模型产生的Candidate Memory默认不参与召回 | 创建候选后检索；候选隔离回执 | 部分：R14 |
| C09-AC02 | 只有对应Human Principal确认后记忆变为Confirmed | 他人确认和服务确认负例；记忆同意回执 | 部分：R14、R35；确认语义自建 |
| C09-AC03 | 本人纠正产生新版本且旧值不再默认召回 | 纠正前后回放；记忆纠正回执 | 部分：R14 |
| C09-AC04 | 召回同时过滤Tenant、Principal、状态和过期时间 | 四维参数化负例；记忆召回回执 | 直接：R11、R12、R14 |
| C09-AC05 | 价格、订单、合同、认证和KPI类型被拒绝进入个人记忆 | 禁止类别Fixture；记忆政策回执 | 无通用替代：R35仅提供政策词汇 |
| C09-AC06 | 删除请求传播到主库、向量索引和缓存 | 删除后全数据面查询；记忆删除回执 | 部分：R12、R14、R35 |
| C09-AC07 | 保留例外和备份到期规则可以解释并验证 | 删除后备份窗口演练；保留回执 | 规范：R35、R30 |

### C10 知识摄取、解析与目录

| ID | 最小通过条件 | 验证与主证据 | 参考 |
|---|---|---|---|
| C10-AC01 | 新文件先进入隔离Quarantine且不可被检索 | 上传后直接查询负例；隔离上传回执 | 直接：R12、R15 |
| C10-AC02 | 原件内容哈希在解析前冻结并贯穿派生对象 | 原件、页、表和Chunk引用闭包；内容哈希回执 | 直接：R01、R15 |
| C10-AC03 | 恶意文件、宏或禁止内容在发布前被阻断 | 恶意基准集；文件安全回执 | 直接/部分：R15 |
| C10-AC04 | 冻结文档基准集达到预先定义的解析质量阈值 | Docling/Tika对照及人工抽检；解析回执 | 直接：R15 |
| C10-AC05 | 缺Owner、来源、版本、有效期、密级或ACL任一字段时不能发布 | 每字段删除负例；目录完整性回执 | 部分：R02、R15；发布政策自建 |
| C10-AC06 | 从Chunk可追溯到原件、页、节、表和坐标 | 随机抽样逆向追踪；来源链回执 | 直接：R15、R23 |
| C10-AC07 | 撤回资料不再进入新检索请求 | 发布后撤回并持续检索；撤回回执 | 部分：R13、R16 |
| C10-AC08 | 删除传播完成后索引、缓存和派生文件均不可访问 | 全数据面删除验证；知识删除回执 | 部分：R12、R15、R16 |

### C11 权限感知检索与 RAG

| ID | 最小通过条件 | 验证与主证据 | 参考 |
|---|---|---|---|
| C11-AC01 | 授权过滤发生在候选检索之前 | Trace证明先取得允许集合；ACL前置回执 | 直接：R11、R16 |
| C11-AC02 | 草稿、过期、撤回和未授权资料不会进入模型上下文 | 四类参数化负例；上下文隔离回执 | 直接/部分：R12、R16 |
| C11-AC03 | 客户端或模型不能自行指定Tenant/ACL Filter | 篡改Filter和Prompt注入；可信过滤回执 | 直接：R11、R12 |
| C11-AC04 | 混合检索在冻结基准集达到召回与精度阈值 | FTS/向量基准运行；检索质量回执 | 直接：R16 |
| C11-AC05 | 每个事实性回答返回可验证的EvidenceRef和位置 | 答案与来源位置对账；引用正确性回执 | 部分：R16、R23 |
| C11-AC06 | 证据不足时系统明确拒答而不编造来源 | 无答案与冲突资料测试；拒答回执 | 直接：R06、R16 |
| C11-AC07 | 删除或撤回后旧向量、缓存和引用不会继续生效 | 删除传播与as-of测试；索引失效回执 | 部分：R12、R16 |

### C12 Agent 编排与任务路由

| ID | 最小通过条件 | 验证与主证据 | 参考 |
|---|---|---|---|
| C12-AC01 | TaskEnvelope 和每个节点I/O符合版本化Schema | 正反例验证；节点契约回执 | 直接：R02、R17 |
| C12-AC02 | 每次Run固定状态图、节点和调用版本 | 重放并比较版本闭包；编排版本回执 | 直接：R13、R17 |
| C12-AC03 | 路由先执行权限、风险和预算硬过滤 | 构造高分但不允许候选；硬过滤回执 | 部分：R11、R17 |
| C12-AC04 | 路由选择和拒绝理由可解释并进入受控Trace | 候选集及理由检查；路由解释回执 | 部分：R17、R24 |
| C12-AC05 | Checkpoint可恢复执行但不冒充C18审计 | 中断恢复及字段边界检查；Checkpoint回执 | 直接/部分：R13、R17、R23 |
| C12-AC06 | 节点失败不会绕过HumanDecision | 审核节点前后故障注入；人工门回执 | 部分：R17、R20 |
| C12-AC07 | 节点重试不产生重复外部副作用 | 重复执行Tool节点；副作用回执 | 部分：R13、R17、R20 |
| C12-AC08 | 模型输出不能决定权限、上云、预算或批准 | Prompt注入四类决定负例；模型边界回执 | 规范：R05、R11、R17 |

### C13 Skills Registry、测试、发布与回滚

| ID | 最小通过条件 | 验证与主证据 | 参考 |
|---|---|---|---|
| C13-AC01 | 每个Skill包含版本化Manifest、Owner、权限声明和输入输出Schema | 缺字段负例；Skill Manifest回执 | 直接/部分：R02、R18 |
| C13-AC02 | Skill变更经过受保护Git评审和指定Owner批准 | 未批准提交发布负例；评审回执 | 直接：R18 |
| C13-AC03 | 静态检查和冻结评测在发布前通过 | 恶意/不合格Skill样本；质量门回执 | 直接：R06、R18 |
| C13-AC04 | 运行只绑定不可变内容SHA-256 | 同版本名替换内容负例；Digest绑定回执 | 直接：R01、R18 |
| C13-AC05 | 未测试、未批准或已撤回版本不能解析到新Run | 三类状态负例；解析门回执 | 部分：R13、R18 |
| C13-AC06 | pilot和stable发布范围独立可控 | 不同Tenant/Principal目录测试；灰度回执 | 部分：R11、R18 |
| C13-AC07 | 回滚后新Run绑定目标旧Digest且历史Run不改写 | 发布/回滚/回放；回滚回执 | 直接/部分：R18 |
| C13-AC08 | P1任意Skill脚本保持关闭；P2未签名制品被拒绝 | 脚本和未签名OCI负例；执行边界回执 | 直接：R18、R25、R27 |

### C14 模型网关、路由与本地推理

| ID | 最小通过条件 | 验证与主证据 | 参考 |
|---|---|---|---|
| C14-AC01 | Model Registry固定Provider、模型、能力、地区、价格和版本 | 目录Schema及缺失检查；模型目录回执 | 直接/部分：R02、R19 |
| C14-AC02 | 统一请求、响应、Usage和Error契约通过Provider兼容测试 | 多Provider Mock契约；网关兼容回执 | 直接：R02、R03、R19 |
| C14-AC03 | 授权硬过滤在质量/成本/延迟排序前执行 | 禁止模型高分候选测试；授权过滤回执 | 直接：R11、R19 |
| C14-AC04 | 数据分类和地区规则在路由前执行 | 敏感/地区Fixture；数据政策回执 | 部分：R11、R19、R35 |
| C14-AC05 | 云/本地允许集合外的模型永不成为Fallback | Provider故障和空集合测试；Fallback回执 | 直接/部分：R19 |
| C14-AC06 | 敏感任务不会静默改发云端 | 本地模型故障测试；敏感路由回执 | 部分：R19；政策自建 |
| C14-AC07 | 每次路由保存候选、硬过滤、评分和最终选择理由 | Trace回放；路由决定回执 | 直接/部分：R19、R24 |
| C14-AC08 | Provider用量与C19计量可按请求对账 | Token/请求/费用差异检查；模型成本回执 | 直接/部分：R19、R24 |

### C15 HumanDecision 与可靠工作流

| ID | 最小通过条件 | 验证与主证据 | 参考 |
|---|---|---|---|
| C15-AC01 | 待决定业务Artifact使用确定性规范化并生成唯一哈希 | 字段乱序和重复计算；Artifact Hash回执 | 直接：R01 |
| C15-AC02 | 审核界面展示完整对象、差异、来源和风险 | J03脚本及截图索引；审批展示回执 | 部分：R07、R20 |
| C15-AC03 | 决定主体是当前仍获授权的Human Tenant Principal | 过期会话、Service和Agent决定负例；决定主体回执 | 直接/部分：R09、R10、R11 |
| C15-AC04 | 决定绑定Artifact Hash、版本、范围和过期时间 | 缺字段及过期负例；决定绑定回执 | 部分：R01、R20 |
| C15-AC05 | 受批字段、收件人、附件、规则、Skill或相关版本任一变化使旧决定失效 | 参数化篡改矩阵；决定失效回执 | 无通用替代：R01、R20仅提供机制 |
| C15-AC06 | 撤权发生后未提交决定不可继续Commit | 决定后撤权再执行；每次重鉴权回执 | 直接：R11、R20 |
| C15-AC07 | Outbox崩溃重放不产生重复提交 | Commit窗口故障注入；可靠提交回执 | 直接/部分：R13、R20 |
| C15-AC08 | Commit后Readback与批准Artifact逐字段对账 | 模拟源系统不同结果；回读回执 | 部分：R20、R22 |
| C15-AC09 | 回读不一致进入显式失败或补偿而非假成功 | 不一致和补偿故障测试；补偿回执 | 直接/部分：R13、R20 |
| C15-AC10 | P1真实外部执行为零且Synthetic Test Decision不能迁移到P3 | 网络、Adapter和导入负例；Synthetic决定边界回执 | 无通用替代：R04、R20仅辅助 |

### C16 Tool Gateway 与每次调用重鉴权

| ID | 最小通过条件 | 验证与主证据 | 参考 |
|---|---|---|---|
| C16-AC01 | 每个Tool有唯一`operation_id`、用途、输入、输出和风险等级 | Catalog完整性检查；Operation Catalog回执 | 直接：R02、R21 |
| C16-AC02 | Tool发现阶段按可信主体授权过滤 | 未授权Tool目录负例；发现授权回执 | 直接：R11、R21 |
| C16-AC03 | 参数确认阶段重新鉴权并执行Schema/白名单校验 | 篡改参数和过期授权；参数回执 | 直接：R02、R11、R21 |
| C16-AC04 | 实际执行前再次基于当前主体重鉴权 | 确认后撤权再执行；执行授权回执 | 直接：R11 |
| C16-AC05 | 任意SQL和模型生成SQL接口不存在或被拒绝 | Operation扫描及注入负例；无任意SQL回执 | 部分：R21；窄操作需自建 |
| C16-AC06 | 任意URL、内网探测和重定向逃逸被拒绝 | SSRF测试集；出口安全回执 | 直接/部分：R21、R34 |
| C16-AC07 | 万能管理员Tool和跨Tenant凭据不存在 | Catalog/Secret扫描和调用负例；最小权限回执 | 直接/部分：R11、R26 |
| C16-AC08 | 生产凭据为短期、限定范围且不会进入模型上下文 | 租约过期、Trace/Prompt扫描；凭据回执 | 直接：R26 |
| C16-AC09 | 每次Tool调用记录主体、操作、参数摘要、策略和结果引用 | 审计字段闭包检查；Tool审计回执 | 部分：R21、R23 |
| C16-AC10 | 限流、超时和错误响应不会泄露秘密或显示假成功 | 故障和错误扫描；Tool失败回执 | 直接/部分：R02、R21、R34 |

### C17 Connector Template SDK 与 Mock Lab

| ID | 最小通过条件 | 验证与主证据 | 参考 |
|---|---|---|---|
| C17-AC01 | 审批协同、ERP/业务和BI三类Template均符合Canonical Envelope | 三类Schema验证；Template回执 | 直接：R02、R22 |
| C17-AC02 | SDK和校验器能从空项目生成并验证最小Adapter | 独立测试者执行示例；SDK回执 | 直接：R22、R40 |
| C17-AC03 | Mock行为通过消费者/提供者契约测试 | Pact/WireMock运行；Mock兼容回执 | 直接：R03、R22 |
| C17-AC04 | SSRF、凭据泄露、Tenant混淆和授权绕过负例全部失败关闭 | Connector安全矩阵；安全回执 | 直接/部分：R22、R34 |
| C17-AC05 | Schema注入、重放、超时和乱序不会形成错误成功 | 参数化故障测试；可靠性回执 | 直接：R03、R13、R22 |
| C17-AC06 | Mock和Template不会被投影成真实Connector Instance | UI/API状态负例；C0边界回执 | 无通用替代：R22仅提供实现模式 |
| C17-AC07 | P0—P2仓库、配置、网络和运行记录不含真实企业端点与凭据 | Surface和网络扫描；零企业连接回执 | 直接/部分：R04、R22 |
| C17-AC08 | OpenAPI、错误码、版本和弃用政策可由集成开发者独立使用 | 文档执行测试；开发者体验回执 | 直接：R02、R40 |
| C17-AC09 | Webhook签名、重放窗口和密钥轮换契约有正反例 | Mock Webhook测试；Webhook回执 | 部分：R22、R26 |

### C18 审计、证据与来源链

| ID | 最小通过条件 | 验证与主证据 | 参考 |
|---|---|---|---|
| C18-AC01 | AuditEvent Schema覆盖主体、授权、模型、知识、Skill、Tool、决定和结果引用 | 字段闭包检查；审计Schema回执 | 直接/部分：R02、R23 |
| C18-AC02 | 业务状态和审计Outbox在同一事务提交 | 事务中断测试；审计原子性回执 | 直接：R13 |
| C18-AC03 | 事件采用规范化摘要并形成可验证哈希链 | 重算链条；哈希链回执 | 直接：R01、R23 |
| C18-AC04 | 业务管理员不能更新或删除历史事件 | SQL/API/UI负例；追加性回执 | 部分：R23 |
| C18-AC05 | 审计正文最小化且不默认保存Prompt、文件或Tool正文 | Synthetic Canary扫描；最小化回执 | 规范：R23、R35 |
| C18-AC06 | 来源关系可以从结果追溯到主体、输入和版本化依赖 | 随机结果逆向闭包；Provenance回执 | 直接：R23 |
| C18-AC07 | 备份恢复后哈希链和保留策略仍有效 | 恢复后重算及查询；审计恢复回执 | 直接/部分：R23、R30 |
| C18-AC08 | 任一历史事件篡改、缺失或重排都能被检测 | 三类破坏负例；篡改检测回执 | 直接：R23 |

### C19 可观测、用量、配额与成本

| ID | 最小通过条件 | 验证与主证据 | 参考 |
|---|---|---|---|
| C19-AC01 | 一次请求使用统一Trace ID跨Portal、Core、Model、Tool和Sandbox关联 | E2E Trace闭包；关联回执 | 直接：R24 |
| C19-AC02 | 关键指标名称、单位和标签基数受版本化字典约束 | 指标Lint和高基数负例；Metric回执 | 直接：R24 |
| C19-AC03 | Log和Trace不包含Prompt、文件、Tool正文、秘密或直接联系信息 | Synthetic Canary扫描；遥测隐私回执 | 直接/部分：R24、R35 |
| C19-AC04 | Usage事件使用稳定去重键，重放不会重复计量 | 重复消费测试；计量幂等回执 | 部分：R13、R24、R36 |
| C19-AC05 | 每笔用量绑定准确费率版本和计费单位 | 费率切换边界测试；费率回执 | 部分：R24、R36 |
| C19-AC06 | Tenant和Principal配额在并发下不超发 | 高并发临界值测试；配额回执 | 部分：R13、R36 |
| C19-AC07 | 成本可按Tenant、任务、模型、Tool和Sandbox对账 | 五维汇总与原始事件对账；成本回执 | 直接/部分：R24、R36 |
| C19-AC08 | Provider账单、基础设施成本和内部账本差异在阈值内 | 周期性差异报告；FinOps回执 | 直接/部分：R24 |
| C19-AC09 | C19不保存项目进度、发票或企业BI指标真相 | 非法写入和Schema边界测试；事实边界回执 | 无通用替代：R24、R36仅辅助 |

## 5. P2 原子验收矩阵

### O01 Sandbox Broker 与隔离执行

| ID | 最小通过条件 | 验证与主证据 | 参考 |
|---|---|---|---|
| O01-AC01 | 每个不可信任务创建全新短生命周期microVM | 连续任务实例ID和磁盘状态比较；实例隔离回执 | 直接：R25 |
| O01-AC02 | Sandbox默认无网络出口 | DNS、HTTP、内网和元数据地址负例；出口回执 | 直接：R25 |
| O01-AC03 | 仅经批准的窄目的地可临时放行且任务后撤销 | Egress Policy生命周期测试；例外出口回执 | 直接/部分：R21、R25 |
| O01-AC04 | Sandbox不能访问宿主机文件、设备或Docker Socket | 挂载和Socket逃逸测试；宿主隔离回执 | 直接：R25 |
| O01-AC05 | CPU、内存、磁盘、进程数和执行时间均有硬限制 | 资源耗尽负例；资源限制回执 | 直接：R25 |
| O01-AC06 | 任务只获得短期、限定范围的工作负载身份 | 租约过期和越权测试；Sandbox身份回执 | 直接：R25、R26 |
| O01-AC07 | 输入和输出经过恶意内容及秘密扫描 | 带Canary输入输出；内容扫描回执 | 直接/部分：R15、R27 |
| O01-AC08 | 超时、节点失联和Kill Switch都会触发Reaper并销毁实例 | 三类故障注入；销毁回执 | 直接：R25 |
| O01-AC09 | 任务销毁后不能恢复工作盘、内存或凭据状态 | 新任务取证测试；残留回执 | 直接/部分：R25、R26 |
| O01-AC10 | Sandbox不能承担正式业务Commit或绕过C15/T07 | 尝试调用正式写回Operation；业务边界回执 | 无通用替代：R20、R21、R25仅辅助 |

### O02 密钥、短期凭据与工作负载身份

| ID | 最小通过条件 | 验证与主证据 | 参考 |
|---|---|---|---|
| O02-AC01 | Root Token和长期Provider Key不进入应用配置 | 配置、环境、镜像和运行进程扫描；Root Secret回执 | 直接：R26 |
| O02-AC02 | 跨Tenant、跨服务和跨环境秘密读取均被拒绝 | 参数化身份矩阵；Secret Policy回执 | 直接：R26 |
| O02-AC03 | 动态凭据具有最小Scope和冻结TTL | 签发、权限和到期测试；租约回执 | 直接：R26 |
| O02-AC04 | 撤销凭据后新请求在SLA内失败 | 主动撤销再调用；撤销回执 | 直接：R26 |
| O02-AC05 | 秘密不进入Git、镜像、Prompt、Trace、Log或文档 | 多Surface Canary扫描；秘密泄露回执 | 直接：R04、R26、R27 |
| O02-AC06 | 签名密钥轮换前后新旧检查点按政策可验证 | 轮换窗口测试；签名轮换回执 | 直接/部分：R26、R27 |
| O02-AC07 | OpenBao或等价秘密系统HA故障不导致越权降级 | 节点故障和网络分区；Secret HA回执 | 直接：R26 |
| O02-AC08 | 密钥系统恢复后Policy、租约边界和审计一致 | 隔离恢复演练；Secret恢复回执 | 直接：R26、R30 |
| O02-AC09 | Break-glass有双人或独立批准、限时、可撤销和完整审计 | 紧急访问演练；Break-glass回执 | 部分：R26、R41；组织控制自建 |
| O02-AC10 | 工作负载身份不能冒充Enterprise User或HumanDecision主体 | Token Exchange和主体类型负例；身份边界回执 | 直接/部分：R10、R26 |

### O03 软件供应链与制品信任

| ID | 最小通过条件 | 验证与主证据 | 参考 |
|---|---|---|---|
| O03-AC01 | 发行镜像、Skill和前端制品全部固定不可变Digest | Tag漂移和未固定引用扫描；Digest回执 | 直接：R18、R27 |
| O03-AC02 | 每个发行制品具有可验证来源Provenance | 缺失或篡改Attestation负例；Provenance回执 | 直接：R27 |
| O03-AC03 | 每个发行制品产生完整SBOM | 镜像与SBOM组件对账；SBOM回执 | 直接：R27、R28 |
| O03-AC04 | 漏洞扫描覆盖代码依赖、镜像和IaC | 植入已知漏洞/错误配置；扫描覆盖回执 | 直接：R27、R34 |
| O03-AC05 | 每个制品使用批准身份签名且可离线或受控验证 | 错误签名者和损坏签名负例；签名回执 | 直接：R27 |
| O03-AC06 | 未签名、Digest不符或缺必要材料的制品被准入控制拒绝 | 三类部署负例；准入回执 | 直接：R27 |
| O03-AC07 | 许可证清单包含固定版本、目录、许可证和使用方式 | 发行物与SPDX/CycloneDX对账；许可证回执 | 直接：R28 |
| O03-AC08 | AGPL、自定义许可证、Commons Clause和品牌限制有明确结论 | 许可证规则扫描加人工复核；限制性许可回执 | 部分：R28；法律结论需人类 |
| O03-AC09 | 未使用的候选项目不会进入依赖锁、镜像或静态资源 | 候选名称和包扫描；未采用候选回执 | 直接/部分：R27、R28 |
| O03-AC10 | 风险例外有Owner、范围、到期和替代控制，且到期自动失败 | 过期例外部署负例；例外回执 | 直接：R27、R34 |
| O03-AC11 | 紧急撤回后受影响Digest不能继续部署或启动新任务 | 撤回制品演练；撤回回执 | 直接：R27 |
| O03-AC12 | 同一Release Manifest可关联镜像、SBOM、Provenance、签名、扫描和许可证证据 | 引用闭包和哈希检查；供应链证据索引回执 | 直接：R01、R27、R28 |

### O04 可重复打包、部署、升级、回滚与产品化交付

| ID | 最小通过条件 | 验证与主证据 | 参考 |
|---|---|---|---|
| O04-AC01 | Release Manifest固定全部制品Digest、Schema版本和配置Profile | Manifest引用闭包检查；Release Manifest回执 | 直接：R01、R27、R29 |
| O04-AC02 | 同一Release Manifest可在空环境完成安装 | 全新隔离环境自动安装；空环境安装回执 | 直接：R29 |
| O04-AC03 | 重复执行安装不会产生重复Tenant、密钥或初始化记录 | 二次安装与状态对账；重复安装回执 | 直接/部分：R13、R29 |
| O04-AC04 | 支持矩阵内的上一版本可以升级到当前版本 | 数据库、配置和API迁移测试；升级回执 | 部分：R03、R29 |
| O04-AC05 | 失败升级可受控回退到冻结的上一版本 | 中途故障注入；回滚回执 | 直接/部分：R29 |
| O04-AC06 | 回滚后数据、权限、审计和签名验证结果与预期一致 | 回滚后重跑关键矩阵；一致性回执 | 部分：R11、R23、R27、R29 |
| O04-AC07 | 默认安装包不含企业名称、用户、资料、地址、凭据或Connector Instance | 制品和运行配置Canary扫描；企业中立回执 | 直接/部分：R04、R27 |
| O04-AC08 | 环境配置和秘密以外部引用注入，不嵌入Chart或镜像 | Chart、镜像和运行配置扫描；配置边界回执 | 直接：R26、R29 |
| O04-PX01 | Synthetic角色、J01—J10、信息架构和Capability映射完整 | Role/Journey/Route矩阵差异为零；PX01回执 | 部分：R07、R08；产品研究需自建 |
| O04-PX02 | 员工、审核、管理、运行和开发者关键页面随同一Release发布 | Route/Page清单和构建验证；PX02回执 | 直接：R07 |
| O04-PX03 | 每个关键页面覆盖适用的加载、空、拒绝、校验、超时、部分成功、重试、人工、降级、恢复和成功状态 | 哈希化State Matrix E2E；PX03回执 | 直接/部分：R07、R08 |
| O04-PX03A | 中文界面、UTC存储、Tenant时区展示及日期/数字格式在关键页面一致 | 时区跨日、夏令时和格式化测试；i18n基础回执 | 直接：R39 |
| O04-PX04 | WorkInbox只聚合C08/C15投影，通知失败不改变事项或决定状态 | 状态源对账和通知故障测试；PX04回执 | 部分：R13、R20、R32；投影语义自建 |
| O04-PX05 | AssetReleaseFacade可完成草稿、校验、送审、发布、灰度和回滚且不复制Registry真相 | J04/J05及Digest对账；PX05回执 | 部分：R18、R33 |
| O04-PX06 | 查询、导出、纠正、删除和退出共用版本化PrivacyPortability契约 | 合成权利流程和Schema测试；PX06回执 | 直接/部分：R35、R38 |
| O04-PX07 | 未参与实现者可按文档完成安装、J01、J03、J08和回滚 | 独立执行观察记录；PX07回执 | 直接：R37、R40 |
| O04-PX08 | Event Dictionary与Entitlement Dictionary定义目的、字段、可见人、保留、能力和配额 | Schema及禁止字段负例；PX08回执 | 直接/部分：R35、R36 |
| O04-AC09 | Connector Stage来自Tenant-scoped追加事件，Product Owner不能推进它 | 两个Synthetic scope与越权命令负例；Connector控制面回执 | 无通用替代：R22仅提供Adapter |
| O04-AC10 | G3投影同时绑定scope、onboarding、tenant和product release digest | 双scope重放与混淆负例；G3投影回执 | 部分：R01、R13 |
| O04-AC11 | legacy `task_events`被标记为非权威且删除投影后D1仍可重建项目状态 | 删除投影重建；治理投影回执 | 无通用替代：R01仅辅助验证 |
| O04-AC12 | 计划批准状态只投影D1的`PLAN_BASELINE_APPROVED`事件 | 修改标题/README/本地JSON负例；计划状态回执 | 无通用替代：本项目治理语义 |

### O05 高可用、备份、恢复、灾备与可移植性

| ID | 最小通过条件 | 验证与主证据 | 参考 |
|---|---|---|---|
| O05-AC01 | 备份范围覆盖数据库、对象、制品、配置和必要密钥恢复材料 | 资产清单与备份目录对账；备份范围回执 | 直接：R30 |
| O05-AC02 | 随机选取的冻结恢复点可以在隔离环境实际恢复 | 随机PITR演练；恢复回执 | 直接：R30 |
| O05-AC03 | 实测数据损失不超过Acceptance Profile冻结RPO | 写入时间线和恢复差异；RPO回执 | 直接：R30 |
| O05-AC04 | 端到端恢复时间不超过冻结RTO | 从宣告到服务验收计时；RTO回执 | 直接：R30、R41 |
| O05-AC05 | 恢复后跨Tenant隔离矩阵仍为零泄露 | 恢复副本全存储负例；恢复隔离回执 | 直接：R12、R30 |
| O05-AC06 | 恢复后授权模型、撤权和会话状态与cutoff一致 | 授权正反例重跑；恢复授权回执 | 直接/部分：R11、R30 |
| O05-AC07 | 恢复后C18哈希链和检查点签名可验证 | 重算链和签名验证；恢复审计回执 | 直接/部分：R23、R26、R30 |
| O05-AC08 | 删除标记、保留例外和到期策略在恢复后仍成立 | 删除前后恢复矩阵；保留回执 | 部分：R30、R35 |
| O05-AC09 | Synthetic Tenant导出包含全资产Inventory、Schema、cutoff、文件哈希和引用清单 | 导出清单闭包检查；导出回执 | 直接/部分：R35、R38 |
| O05-AC10 | 导出包可在全新Synthetic Tenant中受控重建 | 隔离环境导入并对账；重建回执 | 直接/部分：R38 |
| O05-AC11 | 缺失、篡改、重复或悬空引用的导出包全部被拒绝 | 四类负例导入；导入安全回执 | 直接：R38 |
| O05-AC12 | I1/I2/I3不同Isolation Profile的导出、恢复和密钥边界有独立证明 | 参数化Profile演练；Profile恢复回执 | 部分：R12、R26、R30 |
| O05-AC13 | 恢复后WorkInbox、产品事件、权益和隐私请求状态与cutoff一致 | 四类状态对账；产品状态恢复回执 | 部分：R13、R32、R35、R36 |
| O05-AC14 | 数据库备份成功不会被错误标记为Tenant可移植性通过 | 仅恢复数据库的负例；可移植性边界回执 | 无通用替代：R30、R38仅提供部件 |

### O06 SLO、容量、压测、混沌与产品质量发布门

| ID | 最小通过条件 | 验证与主证据 | 参考 |
|---|---|---|---|
| O06-AC01 | Capacity Profile在首次采证前冻结工作负载、并发、数据量、Provider和网络条件 | Profile Schema及SHA-256；容量基线回执 | 规范：R01、R31 |
| O06-AC02 | 2倍目标峰值持续60分钟达到冻结SLO和错误预算 | k6/等价原始结果；峰值回执 | 直接：R31 |
| O06-AC03 | 目标持续负载72小时达到冻结SLO且无资源泄漏 | 长稳原始Trace、Metric和资源曲线；长稳回执 | 直接：R24、R31 |
| O06-AC04 | Core API与用户端到端响应分别统计且不互相掩盖 | 分段Trace和两套报告；性能口径回执 | 直接：R24、R31 |
| O06-Q01 | J01—J10具有版本化SLI/SLO、错误预算和降级终态 | Journey/SLO矩阵；Q01回执 | 直接/部分：R24、R31 |
| O06-Q01A | 用户提交到durable acknowledgement或明确拒绝的p95不超过1秒且不显示任务成功 | E2E计时和状态检查；请求确认回执 | 直接：R24、R31 |
| O06-Q01B | 取消请求2秒内被服务端接受且无后续Tool/Connector副作用 | 取消、租约、Reaper和审计闭包；取消回执 | 部分：R13、R24、R31 |
| O06-Q01C | Model、RAG、Tool和Notification任一失败时不越权、不静默改政策、不伪造成功 | 四类故障注入；降级回执 | 直接/部分：R31、R32 |
| O06-Q02 | 至少6名未参与实现的人完成至少30次预设任务，成功率不低于80%，高风险错误成功为零 | 参与者、脚本、原始分母和观察记录；可用性回执 | 规范：R07、R08 |
| O06-Q02A | 关键旅程键盘可完成，axe Critical/Serious为零，并完成人工读屏复核 | 键盘、axe、读屏原始证据；可访问性回执 | 直接：R08 |
| O06-Q02B | 冻结的Chrome、Edge、Safari准确版本及前一主要版本通过关键旅程 | Playwright/人工浏览器矩阵；浏览器回执 | 直接：R07 |
| O06-Q02C | 1440×900、1024×768、390×844视口达到冻结的桌面、平板和手机能力边界 | 视觉回归和E2E；响应式回执 | 直接：R07 |
| O06-Q03 | 每个AI场景绑定Dataset、Metric、Model、Prompt、Skill、Knowledge和Acceptance Profile Digest | 引用闭包和缺失负例；AI质量回执 | 直接/部分：R06 |
| O06-Q03A | 候选版本回归、人工分歧裁决和回滚条件均在采证前冻结 | 重复评测及Adjudication Log；评测门回执 | 直接：R06 |
| O06-Q04 | 互联网暴露面满足冻结OWASP ASVS L2 Profile，未关闭Critical/High为零 | ASVS清单、SAST/DAST和授权负例；AppSec回执 | 直接：R34 |
| O06-Q04A | 每个安全发现有Owner、修复时限、例外到期和复测结果 | 漏洞生命周期对账；安全闭环回执 | 直接：R34 |
| O06-Q05 | 身份/授权、模型、对象/数据库、凭据泄露和通知五类事故均完成演练 | 五类时间线和复盘；事故演练回执 | 直接：R41 |
| O06-Q05A | 发现≤5分钟、人工确认≤10分钟、首次沟通≤15分钟、安全遏制≤30分钟 | 时间戳对账；事故时限回执 | 规范：R41 |
| O06-Q06 | Product Event使用字段Allowlist，Prompt、正文、秘密和直接联系信息Canary泄露为零 | Trace/Log/Event/通知/导出落点扫描；隐私遥测回执 | 直接/部分：R24、R35、R36 |
| O06-Q07 | Tenant资产清单和引用闭包100%对账，导出、校验、重建和删除文档可独立执行 | Inventory、Closure和独立执行；可移植文档回执 | 直接/部分：R37、R38 |
| O06-AC05 | Canary发现异常时自动中止发布 | 注入阈值超限；Canary中止回执 | 直接：R31 |
| O06-AC06 | 自动或受控回滚恢复到上一批准Digest且证据完整 | 发布故障演练；发布回滚回执 | 直接：R29、R31 |
| O06-AC07 | 许可证清单无未决禁止项，React Bits等未复核候选不进入发行物 | 制品与许可证Inventory对账；许可证发布回执 | 直接/部分：R28、R43 |
| O06-AC08 | 所有O06子验收绑定同一Release Digest和Acceptance Profile Digest | Evidence Index引用检查；O06总回执 | 直接/部分：R01 |

## 6. P3 原子验收矩阵

### T01 企业接入控制、Tenant 创建与 Data Policy Pack

| ID | 最小通过条件 | 验证与主证据 | 参考 |
|---|---|---|---|
| T01-AC01 | Enterprise Authorized Onboarding Principal的身份和授权引用仍有效 | 由目标企业提供可验证授权并独立复核；企业授权回执 | 无通用替代：R09只能认证身份 |
| T01-AC02 | Enterprise Onboarding Package在接入前规范化、冻结并哈希 | 重算包Digest；Onboarding Package回执 | 直接：R01、R02 |
| T01-AC03 | 接入包不嵌入密码、Token、私钥或连接串 | Secret Canary和全包扫描；无明文秘密回执 | 直接：R04、R26 |
| T01-AC04 | 为目标企业创建全新的`tenant_kind=ENTERPRISE` Tenant | Registry事件和创建对账；Enterprise Tenant回执 | 部分：R13；Tenant语义自建 |
| T01-AC05 | 不复用Synthetic ID、身份、知识、密钥、对象、数据库或备份链 | 资产和Namespace差异检查；零复用回执 | 直接/部分：R10、R12、R26、R30 |
| T01-AC06 | I1/I2/I3 Isolation Profile在采证前由企业授权确认 | 授权引用与Profile Digest检查；隔离档回执 | 无通用替代：R12仅提供技术模式 |
| T01-AC07 | 选定Profile的数据库、向量、对象、密钥、计算、备份和部署正反例全部通过 | 参数化隔离矩阵；Tenant隔离回执 | 直接/部分：R12、R25、R26、R30 |
| T01-AC08 | Data Policy Pack定义数据分类、允许模型和地区 | 缺失及禁止路由负例；模型数据政策回执 | 部分：R19、R35；企业政策需授权 |
| T01-AC09 | Data Policy Pack定义保留、删除、审计和备份规则 | Schema及执行负例；生命周期政策回执 | 直接/部分：R23、R30、R35 |
| T01-AC10 | Data Policy Pack定义配额、Entitlement和适用SLA | 配额/能力/支持等级对账；权益回执 | 部分：R36 |
| T01-AC11 | 真实角色和Manager可见范围由企业明确确认 | Role/Capability矩阵签署；角色政策回执 | 无通用替代：R11仅执行政策 |
| T01-AC12 | 员工透明度、隐私告知、允许事件和禁止用途被企业确认 | 告知文本、Event Dictionary和授权引用；隐私接入回执 | 规范：R35 |
| T01-AC13 | 允许的通知渠道、联系偏好和升级范围被企业确认 | 渠道政策和测试通知；通知政策回执 | 部分：R32、R35 |
| T01-AC14 | 导入、导出、退出、停用和删除的责任人及保留例外被企业确认 | RACI与授权引用；退出责任回执 | 规范：R35、R38 |
| T01-AC15 | Public Enterprise Context不会自动升级为内部权威资料 | 公开资料与内部目录隔离测试；公开资料边界回执 | 无通用替代：本项目领域边界 |
| T01-AC16 | Tenant可独立暂停并进入受控删除流程 | 暂停、恢复和删除演练；Tenant退出准备回执 | 部分：R13、R35、R38 |

### T02 身份、组织与账号生命周期实例

| ID | 最小通过条件 | 验证与主证据 | 参考 |
|---|---|---|---|
| T02-AC01 | 真实IdP Metadata、Issuer和SCIM来源由企业身份管理员授权 | 授权引用和Metadata哈希；身份源回执 | 无通用替代：R09只提供协议 |
| T02-AC02 | 每个真实用户映射到Tenant内唯一Stable Principal | 映射清单和碰撞测试；用户映射回执 | 直接/部分：R09、R10 |
| T02-AC03 | 部门、角色、兼岗和经理关系按冻结映射规则生成 | 正反例及企业Owner复核；组织映射回执 | 部分：R09、R11；组织事实来自企业 |
| T02-AC04 | Manager只能看到明确授权的正式成果和事项 | 经理多角色越权矩阵；Manager可见性回执 | 直接：R11 |
| T02-AC05 | 私人会话、个人记忆和未发布草稿默认不可见 | 直接API和UI负例；私人边界回执 | 直接：R11、R12 |
| T02-AC06 | 代理审核有明确时间、范围、委托人并可提前撤销 | 委托创建、过期、撤销测试；代理回执 | 部分：R10、R20 |
| T02-AC07 | 调岗、离职和停用后权限在冻结SLA内撤销 | 生命周期场景测试；撤权SLA回执 | 直接/部分：R09、R11 |
| T02-AC08 | 调岗、离职和代理到期后WorkInbox、通知和会话同步失效 | 三个投影和会话对账；投影撤权回执 | 部分：R09、R13、R32 |
| T02-AC09 | 乱序和重放身份事件不能恢复已撤销权限 | 旧事件重放；真实身份可靠性回执 | 直接：R09、R13 |
| T02-AC10 | 隐私权利请求绑定Stable Principal而不是邮箱 | 邮箱变更后查询/删除测试；权利主体回执 | 部分：R10、R35 |

### T03 企业知识与 Skills 接入实例

| ID | 最小通过条件 | 验证与主证据 | 参考 |
|---|---|---|---|
| T03-AC01 | 待接入知识和Skill清单由企业知识Owner授权并冻结哈希 | 清单、授权引用和Digest核验；接入清单回执 | 无通用替代：R01、R15仅辅助 |
| T03-AC02 | 企业资料进入Tenant专属Quarantine且不跨Tenant | 上传和对象隔离测试；企业上传回执 | 直接/部分：R12、R15 |
| T03-AC03 | 每项知识具备Owner、来源、版本、有效期、密级和ACL | 缺字段负例及企业Owner复核；企业目录回执 | 部分：R02、R15 |
| T03-AC04 | 权限预览与C06实际决定一致 | 预览结果和直接API对账；ACL预览回执 | 直接：R11 |
| T03-AC05 | 首批3—5个Skill各自绑定企业场景、Owner、Digest和评测集 | Skill清单和引用闭包；企业Skill回执 | 直接/部分：R06、R18 |
| T03-AC06 | Dataset、Model、Prompt、Skill和Knowledge版本完整绑定 | 评测及运行闭包检查；企业AI质量回执 | 直接/部分：R06、R23 |
| T03-AC07 | 发布工作台可以完成草稿、测试、审核、灰度、撤回和回滚 | J04/J05真实任务；企业发布回执 | 部分：R18、R33 |
| T03-AC08 | 分享、评论、交接和归档不会改变原资产Digest | 协作操作前后摘要比较；协作回执 | 部分：R01、R07；协作语义自建 |
| T03-AC09 | 过期、撤回和删除在检索、缓存和新Run中按SLA失效 | 三类传播测试；企业资产失效回执 | 直接/部分：R12、R16、R18 |
| T03-AC10 | 3—5个Skill达到预先冻结的真实任务质量和安全基线 | 真实授权案例集及人工裁决；Skill基线回执 | 直接/部分：R06 |
| T03-AC11 | 企业知识Owner能独立完成发布、撤回、过期和删除 | 无提示任务测试；Owner可用性回执 | 规范：R07、R08、R37 |
| T03-AC12 | 企业差异只存在于Tenant配置、知识包和Skill Release，不Fork Product Core | 代码和配置差异检查；零核心Fork回执 | 部分：R18、R29 |

### T04 审批/协同系统 Connector Instance

| ID | 最小通过条件 | 验证与主证据 | 参考 |
|---|---|---|---|
| T04-AC01 | Applicability在启动前冻结为REQUIRED、OPTIONAL或NOT_IN_SCOPE | Applicability事件和依赖检查；范围回执 | 无通用替代：本项目治理语义 |
| T04-AC02 | Connector Instance绑定准确Tenant、Template和产品Release Digest | 引用闭包和跨Tenant负例；实例绑定回执 | 部分：R01、R22 |
| T04-AC03 | C0阶段只运行Template/Mock且不接触企业网络 | 网络和配置扫描；C0回执 | 直接/部分：R03、R22 |
| T04-AC04 | C1阶段绑定企业授权快照及内容哈希 | 授权快照重算和过期测试；C1回执 | 部分：R01、R22；授权来自企业 |
| T04-AC05 | C2阶段只开放批准的窄只读Operation | Operation Catalog和越权测试；C2回执 | 直接/部分：R11、R21、R22 |
| T04-AC06 | 可选`prepare_*`只生成候选Artifact，不执行Commit | 调用prepare并检查外部副作用为零；Prepare回执 | 部分：R20、R22 |
| T04-AC07 | 源系统ACL与平台政策取交集，任一拒绝即失败 | 双策略正反例；权限交集回执 | 直接：R11 |
| T04-AC08 | 每次读取返回来源、as-of和新鲜度状态 | 超期与缺来源负例；协同来源回执 | 部分：R02、R22、R23 |
| T04-AC09 | 撤权、接口故障或Kill Switch后失败关闭且可停用 | 三类故障测试；协同停用回执 | 直接/部分：R13、R22 |
| T04-AC10 | 不通过浏览器抓取、生产库直连或万能凭据绕过正式接口 | 网络、Operation和Secret扫描；禁止绕过回执 | 直接/部分：R21、R22、R26 |

### T05 ERP/业务系统 Connector Instance

| ID | 最小通过条件 | 验证与主证据 | 参考 |
|---|---|---|---|
| T05-AC01 | Applicability和目标业务对象在启动前冻结 | 范围、Owner和依赖检查；ERP范围回执 | 无通用替代：本项目治理语义 |
| T05-AC02 | Connector Instance绑定准确Tenant、Template和企业接口授权 | 引用闭包与跨Tenant负例；ERP实例回执 | 部分：R01、R22 |
| T05-AC03 | C0/C1/C2每个阶段单独形成授权、配置和证据哈希 | 逐阶段重放；ERP阶段回执 | 部分：R01、R22 |
| T05-AC04 | 只暴露已批准`operation_id`和Canonical Mapping | Operation及字段Allowlist检查；ERP契约回执 | 直接/部分：R02、R21、R22 |
| T05-AC05 | 不提供任意SQL、生产数据库账号或模型生成SQL | Catalog、Secret和注入测试；无直库回执 | 直接/部分：R21、R26、R34 |
| T05-AC06 | 字段、单位、来源、Schema版本和as-of可验证 | 查询结果与字典对账；ERP来源回执 | 部分：R02、R23 |
| T05-AC07 | 过期数据、空值、超时和限流均返回明确非成功状态 | 四类故障测试；ERP失败回执 | 直接：R02、R03、R22 |
| T05-AC08 | 可选`prepare_*`只生成候选Artifact，不执行正式写回 | Prepare调用及源系统副作用检查；ERP Prepare回执 | 部分：R20、R22 |
| T05-AC09 | 撤权和Kill Switch在冻结SLA内阻止新读取 | 撤权后调用；ERP停用回执 | 直接/部分：R11、R22 |
| T05-AC10 | 正式业务事实始终以源系统或批准只读模型为准 | 源事实修订及AIOS对账；事实边界回执 | 无通用替代：R22仅实现连接 |

### T06 BI/认证指标 Connector Instance

| ID | 最小通过条件 | 验证与主证据 | 参考 |
|---|---|---|---|
| T06-AC01 | Applicability、Metric Catalog和企业指标Owner在启动前冻结 | 授权引用与Catalog Digest；BI范围回执 | 无通用替代：R42只提供语义工具 |
| T06-AC02 | 每个Metric定义口径、分母、单位、维度、窗口、排除项和版本 | Schema及缺字段负例；Metric定义回执 | 直接/部分：R02、R42 |
| T06-AC03 | BI Connector只读取企业已认证指标，不重新定义KPI | 指标ID与源Catalog对账；认证口径回执 | 部分：R42；权威来自企业BI |
| T06-AC04 | 查询权限与企业源ACL及C06政策取交集 | 指标/维度越权负例；BI授权回执 | 直接：R11 |
| T06-AC05 | 每个结果返回Metric版本、as-of、新鲜度和EvidenceRef | 结果字段及来源对账；BI来源回执 | 部分：R23、R42 |
| T06-AC06 | 空值、迟到、修订和口径变化均显式表达 | 四类数据状态测试；BI数据状态回执 | 部分：R02、R42 |
| T06-AC07 | KPI解释在冻结案例集达到准确性和拒答阈值 | 案例评测与人工裁决；BI解释回执 | 直接/部分：R06、R42 |
| T06-AC08 | BI Connector无`prepare_*`、Commit或C3升级路径 | Operation扫描及调用负例；BI只读回执 | 直接/部分：R21、R22 |
| T06-AC09 | 不用聊天量、Token或AI采用量暗中评价员工 | Event/Metric/报表字段扫描；员工权益回执 | 规范：R35、R36 |
| T06-AC10 | 涉及员工权益的决定始终由获授权人类处理 | 尝试自动决定负例；BI人类决定回执 | 无通用替代：R20仅提供流程 |

### T07 C3 受控写回、回读与对账

| ID | 最小通过条件 | 验证与主证据 | 参考 |
|---|---|---|---|
| T07-AC01 | 目标Connector Instance属于当前Tenant | 跨Tenant实例引用负例；C3 Tenant回执 | 直接：R11、R12 |
| T07-AC02 | 同一实例已完成T04或T05的C2验收且证据哈希有效 | C2 Evidence引用闭包；C3入口回执 | 无通用替代：R01、R22仅辅助 |
| T07-AC03 | `prepare_operation_id`和契约版本已在C2中验收 | 未验收Operation和旧版本负例；Prepare契约回执 | 直接/部分：R02、R03 |
| T07-AC04 | C3 Runtime Authorization匹配Tenant、Instance、Action、Scope和Expiry | 每字段错配负例；C3授权回执 | 直接/部分：R11；授权来自企业 |
| T07-AC05 | Prepare输出经过确定性校验并形成完整Artifact Hash | 重算、缺字段和篡改测试；C3 Artifact回执 | 直接：R01、R20 |
| T07-AC06 | 具备正式动作权限的Human Tenant Principal对完整哈希作HumanDecision | Agent/Service/无权限Human负例；C3决定回执 | 无通用替代：R09、R11、R20仅辅助 |
| T07-AC07 | 受批内容任一变化都会要求重新HumanDecision | 参数化篡改矩阵；C3再批准回执 | 部分：R01、R20 |
| T07-AC08 | Commit执行前再次验证授权、决定、版本和幂等键 | 决定后撤权/过期/版本变更；Commit门回执 | 直接/部分：R11、R13、R20 |
| T07-AC09 | 重复和并发请求不会重复提交 | 高并发及网络重试；C3幂等回执 | 直接/部分：R13、R20 |
| T07-AC10 | Commit后Readback与批准Artifact逐字段对账 | 源系统返回差异测试；C3回读回执 | 部分：R20、R22 |
| T07-AC11 | 回读不一致进入失败/补偿并保持可追溯 | 补偿成功和失败场景；C3补偿回执 | 直接/部分：R13、R20 |
| T07-AC12 | 审计同时记录human subject、workload actor、Connector和源系统回执 | 审计闭包检查；C3审计回执 | 直接/部分：R10、R23 |
| T07-AC13 | Sandbox、Product Owner和普通maturity按钮不能发起或批准C3动作 | 三类越权负例；C3权力边界回执 | 无通用替代：本项目治理和运行授权语义 |
| T07-AC14 | T06 BI Connector任何情况下都不能进入C3 | BI实例升级及Commit负例；BI C3拒绝回执 | 无通用替代：R22仅提供Adapter |

### T08 真实试点、切换、运行与退出

| ID | 最小通过条件 | 验证与主证据 | 参考 |
|---|---|---|---|
| T08-AC01 | 最终Applicability只包含REQUIRED或NOT_IN_SCOPE且依赖闭包有效 | 图遍历和状态检查；Applicability回执 | 无通用替代：本项目治理语义 |
| T08-AC02 | 任何已启动、创建实例、被主场景引用或产生证据的OPTIONAL自动转为REQUIRED | 四类状态转换测试；Applicability升级回执 | 无通用替代：本项目治理语义 |
| T08-AC03 | Pilot主场景、用户批次、观察窗口、样本量、分母、阈值和停止条件在采证前冻结 | Tenant Acceptance Profile Digest；试点基线回执 | 规范：R01、R06、R31 |
| T08-AC04 | 真实用户完成角色化培训并达到预设任务通过标准 | 培训清单、任务脚本和原始结果；培训回执 | 直接/部分：R37 |
| T08-AC05 | WorkInbox、审核深链、失败恢复和通知偏好在真实角色下可用且不改变C08/C15真相 | 真实授权场景和通知故障；任务体验回执 | 部分：R07、R20、R32 |
| T08-AC06 | 真实任务成功率、AI质量、满意度和失败漏斗达到冻结目标 | 原始分母、评测和调查；价值回执 | 直接/部分：R06、R36 |
| T08-AC07 | 产品事件的字段、目的、可见人、保留和禁止用途完成企业告知与授权 | Event Dictionary和授权引用；产品分析回执 | 规范：R35、R36 |
| T08-AC08 | 目标浏览器、设备和可访问性在真实用户场景通过 | 浏览器、键盘、读屏和观察记录；真实UX回执 | 直接：R07、R08 |
| T08-AC09 | 支持入口、事件分级、状态沟通和升级责任真实可用 | 工单和事故演练；支持回执 | 直接/部分：R41 |
| T08-AC10 | Canary异常、权限风险或质量跌破停止条件时能暂停试点 | 注入停止条件；试点停止回执 | 直接/部分：R31、R41 |
| T08-AC11 | Rollback后用户、权限、数据和业务动作处于预期安全状态 | 真实或授权克隆回滚演练；试点回滚回执 | 直接/部分：R29、R30 |
| T08-AC12 | 在企业授权的隔离恢复环境完成Tenant导出、校验、重建、对照和到期销毁 | 短期凭据、资产闭包和销毁证据；退出演练回执 | 直接/部分：R26、R30、R38 |
| T08-AC13 | 只有企业正式退出决定后才停用或删除真实试点Tenant | 无授权删除负例及正式授权引用；退出决定回执 | 无通用替代：R35仅提供隐私流程 |
| T08-AC14 | 授权退出克隆证明停用、删除或退出不影响其他Tenant | 双Tenant隔离演练；退出隔离回执 | 直接/部分：R12、R30、R38 |
| T08-AC15 | 权益、用量、成本和适用SLA能够逐项对账 | Entitlement、C19和支持记录对账；商业运行回执 | 直接/部分：R24、R36、R41 |
| T08-AC16 | 聊天正文、Token数或AI使用量不会成为秘密员工绩效画像 | 分析、BI、报表和导出字段扫描；员工透明度回执 | 规范：R35、R36 |
| T08-AC17 | 若T04/T05/T06为NOT_IN_SCOPE，页面、文档和销售表述不声称已接入 | UI、文档和演示内容扫描；能力声明回执 | 无通用替代：R37仅辅助文档管理 |
| T08-AC18 | 首个Tenant通过只证明单Tenant；第二个Tenant在零核心代码Fork下通过后才可声明重复交付 | 两次独立G3 Release/差异对账；多企业重复交付回执 | 部分：R29；产品声明语义自建 |

## 7. Gate 原子验收矩阵

### G0：P0 → P1

| ID | 最小通过条件 | 验证与主证据 | 参考 |
|---|---|---|---|
| G0-AC01 | F01—F04各自全部原子验收通过 | 四个父工作包Receipt索引；G0覆盖回执 | 部分：R01、R02 |
| G0-AC02 | 37项边界、依赖、领域词汇、契约、威胁模型和No-Go均冻结 | 定义闭包和Digest；G0定义回执 | 规范：R01、R02、R05 |
| G0-AC03 | 三个Synthetic Tenant可生成但未冒充P1部署结果 | Fixture与运行环境状态对账；阶段边界回执 | 部分：R04 |
| G0-AC04 | P0—P2零企业内部数据门自动阻断全部保护Surface | 正负Canary运行；零企业数据回执 | 直接/部分：R04 |
| G0-AC05 | G0 Frozen Evidence Package规范化并产生真实稳定SHA-256 | 重复构建和重算；G0冻结包回执 | 直接：R01 |
| G0-AC06 | Product Owner只对准确G0 Submission Hash作不可变决定 | 错误Hash和修改后重用决定负例；G0决定回执 | 无通用替代：R01仅提供哈希机制 |

### G1：P1 → P2

| ID | 最小通过条件 | 验证与主证据 | 参考 |
|---|---|---|---|
| G1-AC01 | C01—C19各自全部原子验收通过且保持P1 Synthetic边界 | 19个父工作包Receipt索引；G1覆盖回执 | 部分：R01、R02 |
| G1-AC02 | 三个Synthetic Tenant真实部署且每个含多用户和多角色 | 运行时Inventory与角色矩阵；Synthetic运行回执 | 部分：R04、R09、R11 |
| G1-AC03 | SQL、向量、文件、对象、搜索、缓存、Tool和恢复副本的跨Tenant/用户/角色泄露为零 | 全Surface隔离矩阵；G1隔离回执 | 直接/部分：R11、R12 |
| G1-AC04 | “登录→Agent→RAG/Tool→Synthetic Test Decision→审计/用量”可完整重放 | E2E运行和证据闭包；G1旅程回执 | 部分：R09、R17、R20、R23、R24 |
| G1-AC05 | P1运行真实外部副作用为零 | 网络、Adapter和源系统调用扫描；零副作用回执 | 部分：R04、R22 |
| G1-AC06 | 任意代码执行保持关闭，Connector保持Template+Mock/C0 | Sandbox和Connector状态检查；执行边界回执 | 直接/部分：R22、R25 |
| G1-AC07 | Product Owner只对准确G1 Frozen Evidence Package Hash作决定 | Submission/Decision绑定检查；G1决定回执 | 无通用替代：R01仅提供哈希机制 |

### G2：P2 → P3

| ID | 最小通过条件 | 验证与主证据 | 参考 |
|---|---|---|---|
| G2-AC01 | O01—O06全部必选原子验收通过 | 六个父工作包Receipt索引；G2覆盖回执 | 部分：R01、R02 |
| G2-AC02 | 固定Release Digest上重跑F02、F04和C01—C19关键回归且无退化 | 回归清单和差异报告；P0/P1不回退回执 | 直接/部分：R03、R06 |
| G2-AC03 | 产品可从空环境重复安装、升级和回滚 | O04安装/升级/回滚Receipt；交付回执 | 直接：R29 |
| G2-AC04 | 未固定、未签名或缺SBOM/Provenance/许可证结论的制品被阻断 | O03准入负例；供应链回执 | 直接：R27、R28 |
| G2-AC05 | microVM一任务一实例、默认断网、销毁和资源隔离通过 | O01原始证据；沙箱回执 | 直接：R25 |
| G2-AC06 | 短期凭据、检查点签名、密钥轮换和恢复通过 | O02/O05证据闭包；密钥回执 | 直接：R26、R30 |
| G2-AC07 | 2倍峰值60分钟和持续负载72小时达到冻结SLO与错误预算 | O06原始负载结果；容量回执 | 直接：R24、R31 |
| G2-AC08 | O04-PX01—PX08全部通过并绑定同一产品Release | 产品化Receipt索引；产品体验回执 | 部分：R07、R08、R32、R35—R40 |
| G2-AC09 | O06-Q01—Q07全部通过，任一安全、隐私、AI质量、可访问性或恢复失败均阻断 | 产品质量Receipt索引；质量门回执 | 直接/部分：R06、R08、R31、R34、R35、R38、R41 |
| G2-AC10 | PITR、全栈恢复、Tenant导出、重建和删除契约达到冻结RPO/RTO及闭包要求 | O05/O06证据；恢复可移植回执 | 直接/部分：R30、R38 |
| G2-AC11 | Connector Template安全矩阵在发布候选上通过且仍为C0 Mock | C17重跑和UI声明检查；Connector模板回执 | 直接/部分：R03、R22 |
| G2-AC12 | 默认发行物和运行初始化不含企业名称、用户、资料、端点、凭据或Connector Instance | 全发行物Canary扫描；企业中立回执 | 直接/部分：R04、R27 |
| G2-AC13 | 每项关键证据由符合独立性要求的人类复核 | Reviewer身份、贡献记录和独立性声明；独立复核回执 | 无通用替代：R41只提供角色模式 |
| G2-AC14 | G2 Evidence Package绑定准确Release、Fixture和Acceptance Profile Digest | 引用闭包和重算；G2冻结包回执 | 直接：R01 |
| G2-AC15 | Product Owner只对准确G2 Submission Hash作决定且不替代专业签署 | Decision、专业签署和Hash绑定检查；G2决定回执 | 无通用替代：本项目治理语义 |

### G3：单个Tenant P3最终验收

| ID | 最小通过条件 | 验证与主证据 | 参考 |
|---|---|---|---|
| G3-AC01 | T01授权引用、Onboarding Package和Data Policy Pack在提交时仍有效 | 授权状态和Digest检查；G3接入回执 | 无通用替代：R01、R35仅辅助 |
| G3-AC02 | Tenant的隔离、模型路由、审计、备份和删除正反例全部通过 | T01/O05关键矩阵；Tenant控制回执 | 直接/部分：R12、R19、R23、R30、R35 |
| G3-AC03 | 最终Applicability仅含REQUIRED/NOT_IN_SCOPE且依赖闭包有效 | 图和状态机器检查；Applicability回执 | 无通用替代：本项目治理语义 |
| G3-AC04 | T02及全部REQUIRED工作包通过，NOT_IN_SCOPE边界在启动前已冻结 | T工作包Receipt索引；P3范围回执 | 部分：R01 |
| G3-AC05 | 任一C3由企业运行授权主体放行，正式动作由获授权Human Principal作HumanDecision | T07授权和决定证据；C3权力回执 | 无通用替代：R09、R11、R20仅辅助 |
| G3-AC06 | 真实任务成功、AI质量、满意度、支持和SLO达到Tenant Acceptance Profile | T08原始分母和结果；真实试点回执 | 直接/部分：R06、R31、R36、R41 |
| G3-AC07 | 产品事件、隐私告知、可见人、保留和禁止用途完成企业授权 | T01/T08隐私证据；Tenant隐私回执 | 规范：R35、R36 |
| G3-AC08 | 企业授权隔离环境中的导出、校验、重建、到期销毁和退出克隆演练通过 | T08资产闭包与销毁证据；退出回执 | 直接/部分：R30、R38 |
| G3-AC09 | 全部运行依赖固定版本并有许可证结论 | Release与License Inventory对账；P3许可证回执 | 直接/部分：R27、R28 |
| G3-AC10 | SLA、Entitlement、配额、用量和成本逐项对账 | T01/T08/C19结果；运行权益回执 | 直接/部分：R24、R36、R41 |
| G3-AC11 | NOT_IN_SCOPE的OA/ERP/BI能力未在页面、文档或销售表述中宣称已接入 | 能力声明扫描；真实能力边界回执 | 部分：R37 |
| G3-AC12 | G3 Submission绑定tenant、onboarding、product release、Acceptance Profile和企业授权引用 | Schema及引用闭包检查；G3冻结包回执 | 直接/部分：R01、R02 |
| G3-AC13 | Product Owner只决定Stage Gate，不替代企业数据、退出或业务动作授权 | 权限和流程负例；G3权力边界回执 | 无通用替代：本项目领域语义 |
| G3-AC14 | 首个G3结果只标记为单Tenant验证，不扩大为多企业重复交付 | 页面、文档和发布声明检查；声明边界回执 | 无通用替代：R37仅辅助 |
| G3-AC15 | 第二个独立Tenant使用同一Product Core Release且零核心代码Fork通过G3后，才允许声明重复交付 | 两次G3包和代码差异对账；重复交付回执 | 部分：R29；声明规则自建 |

## 8. 覆盖统计与治理边界

### 8.1 数量与覆盖

| 范围 | 原子验收项数 | 说明 |
|---|---:|---|
| P0：F01—F04 | 26 | 治理、Synthetic数据门、契约、威胁与评测基线 |
| P1：C01—C19 | 150 | 通用产品核心 |
| P2：O01—O06 | 91 | 生产加固、产品化、恢复和G2质量门 |
| P3：T01—T08 | 100 | 单Tenant真实接入、运行和退出 |
| G0—G3 | 43 | 阶段级不可替代条件 |
| **合计** | **410** | 所有ID唯一，覆盖37个工作包和4个Gate |

参考覆盖：

| 参考类型 | 项数 | 含义 |
|---|---:|---|
| 直接或部分开源实现参考 | 349 | 有可复用组件、测试工具或实现模式，但“部分”项仍需自建权威语义 |
| 主要由规范定义验收口径 | 18 | 标准可以定义如何验收，但不提供完整运行实现 |
| 无通用开源替代 | 43 | 主要是Product Owner Gate、目标企业授权、HumanDecision、事实源边界和产品声明规则 |
| **合计** | **410** | 每个原子项均已给出参考结论 |

### 8.2 条件后置能力

以下能力存在参考项目，但不属于当前G2或首个G3必选验收。只有触发条件成立并完成范围修订后，才能新增正式原子项。

| 候选能力 | 启动条件 | 可参考项目/资料 | 当前结论 |
|---|---|---|---|
| 主动式AI和定时任务 | 至少2个真实高频场景需要无人值守触发 | R13；pg-boss、Temporal | 当前只冻结安全边界，不实施 |
| Temporal长流程 | PostgreSQL Outbox无法满足跨天等待、复杂回调或补偿指标 | R13、R20 | 先做Gap Report、ADR和迁移回滚PoC |
| 实时多人共编 | 真实用户证明异步分享、评论和交接不足 | [Yjs](https://github.com/yjs/yjs) | 需先冻结冲突、ACL、版本锁和审计模型 |
| 图形工作流画布 | 表单式工作台无法表达已冻结复杂流程 | R33 | 画布不能成为C12运行或权限真相 |
| 完整订阅和发票 | 出现付费合同、税务和财务对接要求 | R36、[Kill Bill](https://github.com/killbill/killbill)、[Lago](https://github.com/getlago/lago) | C19/OpenMeter不能冒充会计和发票 |
| 白标 | 合同明确要求且依赖许可证允许 | R28、R43 | 先做品牌、升级、支持和再分发复核 |
| 多语言和RTL | 已确定第二语言Tenant | R39 | 先冻结术语、翻译、搜索和QA流程 |
| 原生移动端 | 响应式Web无法满足已验证业务需求 | R07、R09、R26 | 需新增设备安全、离线、推送和发布运维范围 |
| 重型开发者门户 | 外部集成方数量和支持量达到量化阈值 | R40 | OpenAPI＋生成SDK仍为默认最小方案 |
| 后期视觉动效 | 可用性和关键业务流程已稳定 | R43 | React Bits仅作后期参考，许可证复核前不进入可销售发行物 |

### 8.3 开源采用边界

1. 本文中的项目是学习资料、候选Implementation或可替换Adapter，不代表已经安装、采用或验证。
2. 同一能力默认只采用一个实现，不并行建设双授权、双工作流、双通知、双评测或双计量真相。
3. 所有候选在进入Release Digest前仍须通过v5.2的统一采用门：量化缺口、固定版本、许可证、数据流、Synthetic PoC、故障回滚、Owner、SBOM、签名和准入。
4. PostHog、Langfuse等开源核心包含企业功能边界；Zammad为AGPL；React Bits实际许可证含Commons Clause等边界。必须按冻结版本、使用目录和交付方式复核。
5. 开源项目不能替代目标企业授权、隐私/法务意见、独立安全复核、人类可用性参与者或Product Owner对准确Submission Hash的决定。
6. 任一参考工具都不能成为D1、C08、C15、C18、C19或企业源系统之外的第二事实源。

### 8.4 后续正式化顺序

1. 由Product Owner审阅410项是否准确覆盖v5.2，重点确认P2新增范围和P3企业授权边界。
2. 对每个原子项补充正式Owner、入口依赖、适用性、阈值和Receipt Schema。
3. 生成机器可校验但不覆盖v1.0的Manifest v1.1候选；仍保持37个工作包。
4. 在第一次采证前冻结P2 Acceptance Profile、工具准确版本和原始证据格式。
5. 由独立人类分别复核安全、恢复、可用性、可访问性、隐私和许可证。
6. 只有Manifest v1.1获批并激活后，新增原子验收才成为正式工作包定义；本文本身不改变任何工作包状态。
