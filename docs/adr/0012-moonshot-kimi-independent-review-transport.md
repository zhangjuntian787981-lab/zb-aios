# ADR 0012: Moonshot Kimi 独立复核传输候选

- 状态：Candidate
- 日期：2026-07-30
- 范围：P0–P2 合成数据阶段的独立模型复核传输
- 数据边界：SYNTHETIC_ONLY

## 背景

ADR 0011 定义了提供商无关的 Independent Review Policy、Review Bundle、
隔离证据和 Receipt 语义。此前 Terra 运行记录只证明了失败或不完整的候选
路径，不能冒充当前独立复核结论。当前需要在不削弱 ADR 0011 边界的前提下，
为一个固定模型增加最小传输适配。

## 候选决定

当前唯一候选传输固定为：

- provider：`moonshot`；
- model：`kimi-k2.7-code`；
- base URL：`https://api.moonshot.ai/v1`；
- endpoint：`POST /chat/completions`；
- credential environment name：`MOONSHOT_API_KEY`；
- Keychain service 建议名：`kimi-p2-independent-review`；
- `thinking: {"type":"enabled"}`；
- `tool_choice: "none"`；
- 请求中不提供 `tools`；
- `response_format.type: "json_schema"` 且 `strict: true`；
- 不主动设置 `frequency_penalty`、`n`、`presence_penalty`、
  `temperature` 或 `top_p`；
- 禁止任何模型或端点回退。

以上准确值、576 KiB Review Material、768 KiB 完整请求和 64 KiB 原始响应
UTF-8 上限，以及禁用回退策略，冻结在
`moonshot-kimi-k2.7-code.v1.json`。这些是保守的固定字节上限，不声称等价于
模型 token 上下文容量；任一上限越界均失败关闭。配置的 `configSha256` 是删除
`configSha256` 字段后，对键按字典序递归排序的 canonical JSON UTF-8 字节
计算的 SHA-256。

## Review Material 与上下文边界

模型不能读取仓库、实现会话或隐藏上下文。调用前必须生成关闭字段的
`independent-review-material.v1`，其中逐项内嵌并绑定：

- 准确 Review Bundle；
- base/source commit、tree 和 patch；
- 规范与相关源码；
- 测试结果描述符；
- reviewer prompt；
- Canonical Output Schema；
- Canonical Receipt Schema；
- 不含凭据值、Authorization、Cookie、邮箱或账户信息的固定 Moonshot/Kimi
  模型可见协议投影。

每个 section 都绑定路径、UTF-8 字节数和 SHA-256，Material 自身也使用
canonical JSON 自哈希。实际序列化 Material 超过固定上下文预算时必须以
`KIMI_REVIEW_MATERIAL_CONTEXT_BUDGET_EXCEEDED` 失败关闭；不得裁剪材料、
静默改用其他模型或代理端点。

同一冻结路径同时属于被审查源码和固定治理材料时，只内嵌一次
`GOVERNANCE` section；生成器仍从 source commit 重读并校验该
source subject。该确定性去重不删除唯一材料，也不改变 patch、Bundle、
source subject 哈希或上下文上限。

请求预检必须从可信 Bundle 和 source commit 重建唯一允许的 section
集合，并逐项绑定 patch、全部 reviewed source、specification、test
evidence、固定 governance bytes 和 model-visible protocol。缺失、额外、
改名、改 kind、摘要失配或顺序变化均失败关闭；Material 自哈希不能替代
该外部覆盖绑定。

正式 runner 还必须从真实 Git 重新计算 source tree、完整 binary patch、
changed paths、source mode/blob 摘要和 specification 摘要；自洽但脱离
真实 commit 的替代 Bundle 与 Material 不得进入模型请求。

`specificationSubjects` 必须精确覆盖 Bundle generator 固定的五个规范路径，
不能由调用者删减后重新自哈希。测试证据必须逐条对应冻结 test plan，并闭合
冻结 collector 字节、命令摘要、source commit/tree、隔离执行前后快照、
result attestation 以及 stdout/stderr 原始字节。

stdout/stderr 与 runtime binding 原始字节继续是外部冻结证据：生成
Material 前必须从证据根逐字节读取，并通过 Result JSON 中的路径、字节数和
SHA-256 复验。模型可见 Material 只内嵌 Result JSON，不重复内嵌已经由
Result 准确绑定的成功 stdout/stderr 和 runtime binding。该确定性投影不得
跳过外部闭包验证，也不得改变 Bundle、Result、日志或运行时摘要；它只避免
把冗长成功证据复制进固定上下文预算。

正式 runner 不把调用者提交的 test evidence 或 Material 当作模型输入。它
必须从同一 source commit 的无 Git 元数据隔离归档中重新执行冻结 test plan，再用
新产生的准确 stdout、stderr 和 result bytes 重建 Review Bundle 与 Review
Material；调用者提交的 Bundle 只提供需要逐字段复核的静态范围，提交的
Material 只提供关闭字段 `materialId`。完全自洽但并非实际执行所得的伪造
PASS 不得到达凭据门或模型网络。实际送往 Kimi 的 Bundle、Material 和测试
证据必须一起写入外部证据目录、逐字节回读，并再次通过共享测试证据闭包验证。

每条冻结命令使用独立 `git archive` 临时导出；控制平面从 Git tree
逐 blob 重算模式、字节数和 SHA-256，并在执行前后与归档逐项比较。
归档明确不含 `.git`，源文件和源目录使用只读文件系统模式；macOS Seatbelt
仅允许独立 TMPDIR 以及 `.next`、`.vinext`、`.wrangler`、`dist` 和本地
dependency overlay 内的 `node_modules/.vite-temp` 写入。`node_modules`
overlay 的其他顶层条目只作为指向已验证共享依赖根的只读符号链接，证据
目录必须位于仓库和共享依赖根之外。

执行环境不继承用户凭据或代理配置，网络策略为 `DENY_ALL`，包括
localhost。仓库中两个通常依赖本机 HTTP 的测试在该正式证据模式下只执行
冻结的确定性离线替代：F03 只验证协议、Schema 和样例，不声称同时运行两个
HTTP 实现；浏览器渲染测试只验证同一冻结 HTML 的静态契约。正常开发回归
仍在证据采集前另行执行其标准 HTTP 路径，离线替代不能冒充该标准路径。

每次执行使用 source commit 中冻结的参数化 Seatbelt template，并绑定其
准确字节 SHA-256、仅含路径哈希的参数集 SHA-256，以及由可执行文件、
template 摘要和参数集摘要确定性计算的 invocation SHA-256。测试结果必须
通过同一 source commit 中冻结的 `independent-review-test-result.v3`
Schema 和共享语义 Validator；仅在 `toolVersions` 中写入任意摘要不能形成
可信绑定。每条命令结束后销毁隔离归档；只能声称源树、主仓库和受保护文件
未变化，不能把这些一次性构建输出根描述为只读。

测试依赖通过源归档内的只读符号链接 overlay 指向冻结的共享
`node_modules`。只有 overlay 自己的 `node_modules/.vite-temp` 是额外的
一次性可写构建根；Vite 配置加载不得写入共享依赖树。collector 在每条命令
前后核对 overlay 顶层集合、每个链接的真实目标和 `.vite-temp` 的非链接
目录边界。测试证据中的 `writableWorkRoots` 必须显式包含该目录，同时继续
固定 `sharedDependenciesWritable: false`。

macOS 的 `/usr/bin/git` 会通过 Xcode Command Line Tools 解析真实 Git。
因此测试运行时绑定还必须固定 Git shim、解析后的 Git executable、
`libxcrun` 的准确字节和版本，并固定 `DEVELOPER_DIR`。Seatbelt 只读开放
冻结的 `/Library/Developer/CommandLineTools` 根，不授予任何写权限；
该工具链绑定必须进入 runtime binding、每条测试结果和闭包复验，不能只靠
PATH 或系统默认选择。

实现者身份不能由调用者在 Bundle 中声明。Bundle generator 必须从同一
source commit 读取固定路径的 implementation participant manifest，校验
其关闭字段和固定的 OpenAI `gpt-5.6-sol` 实施者边界，并由该文件的准确
原始字节计算 `participantManifestSha256`；Kimi Material 也必须包含该
manifest。调用者提交的 provider、model、session hash 或替代 manifest
不得进入可信重建结果。

Seatbelt 还必须显式拒绝 `/usr/bin/security` 和 securityd 的 Keychain
IPC；冻结攻击探针只能查询虚构 service，并必须在进程执行边界被拒绝。
collector 在凭据取得前运行，因此不声称扫描尚未取得的 Keychain 值；它只
拒绝证据进程继承的 `MOONSHOT_API_KEY`。正式传输适配器取得实际凭据后，
必须用该准确值扫描请求和响应的原始字节及解析对象，命中即失败关闭。两层
扫描都是纵深防御，不能替代 OS 层 Keychain 拒绝；任何实际凭据均不得写入
Bundle、Material、日志或 Receipt。

完整 provider config 的准确字节通过 Material binding、请求制品和 Receipt
摘要在本地验证。若该文件属于被审查提交，它也会作为源码进入 Material，
因此非秘密的环境变量名和 Keychain service 建议名可能作为配置源码被审查；
任何实际凭据值、Authorization 或账户信息均不得进入模型请求。

## 请求、响应与 Receipt

传输适配器只负责固定 Moonshot 请求和原始响应捕获。提供商无关的 Policy、
Bundle、Output Schema 和语义 Validator 继续复用。

即使服务端声称执行 strict JSON Schema，客户端仍必须：

1. 固定原始请求、原始响应和模型 `content` 的准确 UTF-8 字节；
2. 分别计算并冻结 SHA-256；
3. 解析 `content`；
4. 使用冻结的 Canonical Output Schema 校验；
5. 使用现有独立复核语义验证；
6. 核对 provider、requested/actual model、base URL、source commit、
   Bundle、Prompt、Schema 和配置绑定；
7. 任一失配、空输出、截断、非 JSON、超时或网络失败均失败关闭。

`independent-model-review-receipt.v3` 追加绑定 Moonshot/Kimi 模型身份、
Review Material、Canonical Schema、原始请求/响应/content、Validator
版本、API 无工具隔离、仓库前后快照、Git 冻结的完整运行时依赖清单与记录
时间。Receipt 还绑定与待审 source commit 不同、且为其 Git ancestor 的
runtime trust commit、tree、Bootstrap、外部净化启动器、Runner 和 runtime
manifest 摘要。运行时清单绑定 Node 可执行字节、npm CLI 与完整 npm 包树、
`package-lock.json`、完整 `node_modules` 字节树、关键 Ajv 依赖的锁定
integrity/入口/目录摘要，以及本地执行闭包的准确字节。Moonshot 当前直接接收
Canonical Output Schema，因此 `providerTransportSchemaSha256` 为 `null`；
未来如确需传输 Schema 适配，必须冻结其准确字节，且最终输出仍须通过
Canonical Schema 与语义验证。

历史 Terra 证据必须保留，但 Receipt v3 固定
`historicalTerraEvidenceAccepted: false`，不得作为当前 Kimi 复核结果。

## 凭据和隔离

正式调用只能由 `/usr/bin/env -i` 启动
`launch-kimi-independent-review.sh`，再进入
`bootstrap-kimi-independent-review.mjs`。该 Bootstrap 静态只导入 Node
内置模块，拒绝 `NODE_OPTIONS`、`NODE_PATH`、非空 `process.execArgv` 和
初始环境中的 `MOONSHOT_API_KEY`。Bootstrap 必须核对外部钉住的 runtime
commit/tree 及 Bootstrap/launcher 摘要，证明该 runtime commit 是待审
subject commit 的不同 Git ancestor，再只从 runtime commit 的无 Git 元数据
归档动态导入 Runner。待审 subject commit 只能作为 Git 字节、Bundle 和
Material 输入，不能提供本次执行的 verifier 或 Runner。直接执行
`run-kimi-independent-review.mjs` 固定返回
`KIMI_BOOTSTRAP_REQUIRED`，不得接触凭据或网络。

为使凭据在运行时验真和可信测试完成前不可用，正式 Runner 先用 runtime
commit 的固定实现重建 Bundle、Material、测试证据、请求和完整 runtime
closure；全部通过后才从 macOS Keychain service
`kimi-p2-independent-review` 读取凭据。凭据不会导出到子进程环境，正式
入口也不接受调用者注入的 key、fetch、clock 或 closure verifier。固定配置中的
`credentialEnv: MOONSHOT_API_KEY` 继续描述适配器的凭据名称和兼容边界，
但正式高保证路径不从初始环境读取其值。密钥和 Authorization 不得进入
Review Material、请求制品、响应制品、日志、Receipt 或 Git。Keychain
凭据不存在或余额不可用时，必须在模型网络请求前返回
`KIMI_API_CREDENTIAL_OR_BALANCE_REQUIRED`。

正式 Runner 从 runtime commit 内部构造同一冻结 runtime manifest 的复验，
不接受调用者提交或覆盖验证结果。Runner 在可信测试完成后、模型联网前复验
一次，并在取得模型响应后、冻结任何 Receipt 前再次复验。缺少验证器、验证
抛错或任一次字节闭包失配均返回
`INDEPENDENT_REVIEW_RUNTIME_CLOSURE_NOT_PROVED`；首次失配必须保持零模型
网络调用，响应后失配不得生成 Receipt。带假 fetch 或假 closure 的测试
harness 固定不能发布正式 Receipt。

Bootstrap 所用文件必须先从准确 source commit 提取，不能直接执行可能已被
工作区修改的副本。完整依赖树在可信测试和模型调用前后各重算一次；任一
Node、npm、lockfile、依赖或本地执行字节失配均以
`INDEPENDENT_REVIEW_RUNTIME_CLOSURE_NOT_PROVED` 失败关闭，模型网络调用
次数保持为零。

Kimi 只获得两个消息：冻结 reviewer prompt 和冻结 Review Material。API
请求不给模型文件、Shell、Git、浏览器、D1、Sites 或治理决定工具。传输前后
必须绑定同一仓库 HEAD、tree、工作区状态、受保护文件摘要和受控 ignored
path 排除策略；排除策略之外的 ignored path 直接失败关闭。Receipt 先写入
外部目录的 pending 文件并逐字节回读，只有在最终仓库、runtime 和 closure
检查全部通过后才以原子 rename 发布为 `receipt.json`。

## 不采用项

- `gpt-5.6-terra`、DeepSeek、`kimi-k3`、
  `kimi-k2.7-code-highspeed` 以及第三方代理端点：`REJECT`，不得作为自动
  或人工静默回退。
- 运行时执行 GitHub API 或将仓库凭据提供给模型：`REJECT`。
- 仅凭 strict JSON Schema 跳过本地 Canonical Schema 或语义校验：
  `REJECT`。
- 以普通测试通过、Git commit 或聊天确认冒充独立复核 Receipt：
  `REJECT`。

## 治理效力

This ADR is a candidate and has no governance effect.

This ADR does not activate Independent Review Policy v2.

This ADR does not accept historical Terra evidence as a Kimi review.

This ADR does not satisfy independent human review.

This ADR does not change P1-B11, D1, Gate, Profile, Manifest, Ruleset, or any
work-package state.

This ADR does not authorize or start O02 or O03.

P3、生产发布及 ADR 0011 列出的高风险范围继续要求真实第二名人类复核。
