# 通用多企业 AI 员工平台：v5.3 补证查重报告

- 报告版本：v1.0
- 报告日期：2026-07-28
- 报告性质：只读证据查重快照，不是工作包、进度系统、GateSubmission 或 GateDecision
- 审查范围：v5.3 第 6 节的 26 组补证动作，覆盖原 29 个 B 类最小验收项
- v5.3 SHA-256：`bae704aa9fc8cf4275b8d85f8593139f1d83f8913c03d330227690eea98d43f3`
- 410 项矩阵 SHA-256：`d326404ed55b43eccdba01287793ea64812aaafa83f02596bd58b3f83ccdad7a`
- Git 冻结提交：`b4914ceaac86a00f7acaddfc879e0952f70f922a`
- 审查源码 HEAD：`b4914ceaac86a00f7acaddfc879e0952f70f922a`

## 1. 治理边界

本报告遵守以下边界：

1. F01—T08 仍然只有 37 个工作包；
2. 410 项仍然只是父工作包下面的子验收目录；
3. 本报告不保存工作包或子验收的持续进度；
4. D1 仍是工作包状态、GateSubmission 和 GateDecision 的唯一权威来源；
5. Git 冻结证据仍是源码、测试与验收结果的权威来源；
6. 本报告不修改 P0/P1 工作包状态；
7. 本报告不撤销、覆盖或重新批准 G0/G1；
8. 本报告不修改 Manifest v1、v5.3、410 项矩阵或既有冻结证据；
9. “确需补证”不等于行为已经失败；
10. “发现实际失败”只提出整改与追加式复核建议，不自动改变历史 Gate。

## 2. 线上 D1 只读刷新结果

### 2.1 本次结果

线上只读刷新尚未完成。

已执行的只读检查：

- Sites 项目仍为 `active`；
- 当前生产版本号仍为 14；
- 当前生产地址仍存在；
- 最近一小时没有 Worker 错误事件；
- 未调用任何 D1 POST、写命令、迁移或环境变量修改。

阻塞：

- 生产站点为私有访问；
- 当前终端网络路径被 Cloudflare 私有访问层返回 `403`；
- Chrome 和应用内浏览器的私有 API GET 均未在限定时间内返回；
- 当前工具集中没有直接执行 D1 `SELECT` 的受权只读接口；
- 本地 Wrangler 未登录，且本地 Miniflare SQLite 不是线上 D1。

因此，本报告不能声称线上 revision 仍为 64。revision 64 只是上一次已核验快照，不是本次刷新结果。

### 2.2 明确未做

- 没有生成或轮换新的站点绕过令牌；
- 没有把本地 `governance-events.v1.json` 当作线上事实；
- 没有把本地 SQLite 当作线上 D1；
- 没有写入 v5.3 计划批准事件；
- 没有修改工作包、Gate 或 Connector 状态。

## 3. Git 冻结结果

v5.3 和其引用的 410 项矩阵已经单独冻结到 Git：

| 文件 | SHA-256 |
|---|---|
| `docs/plans/通用多企业AI员工平台_完备工程级方案_v5.3.md` | `bae704aa9fc8cf4275b8d85f8593139f1d83f8913c03d330227690eea98d43f3` |
| `docs/plans/通用多企业AI员工平台_v5.2最小验收项与开源参考矩阵_v1.0.md` | `d326404ed55b43eccdba01287793ea64812aaafa83f02596bd58b3f83ccdad7a` |

冻结提交：

```text
b4914ceaac86a00f7acaddfc879e0952f70f922a
docs: freeze v5.3 engineering plan baseline
```

该提交只有上述两个文件。README、v5.2、AGENTS.md、`docs/agents/` 和其他未跟踪文件均未混入。

## 4. 查重判定口径

| 类别 | 判定条件 | 后续处理 |
|---|---|---|
| 已有证据 | 现有源码、测试和冻结回执已经完整覆盖新增的精确条件 | 不重复补证；在后续 Acceptance Profile 中建立映射 |
| 确需补证 | 已有部分实现或测试，但缺跨模块、计时、CI、真实回读、参数化或冻结回执闭环 | 待 Product Owner 确认报告后补最小证据 |
| 发现实际失败 | 当前实现或测试语义已经能够证明要求不成立 | 先修复机制，再补回归证据；必要时追加 Gate 复核建议 |

“测试全绿”不自动代表“已有证据”。现有测试可能没有覆盖新增精度，也可能把错误行为写成了预期结果。

## 5. 汇总结论

### 5.1 按补证组

| 结论 | 组数 |
|---|---:|
| 已有证据，足够闭环 | 1 |
| 确需补证 | 24 |
| 发现实际失败 | 1 |
| 合计 | **26** |

### 5.2 按原 B 类最小验收项

| 结论 | 验收项数 |
|---|---:|
| 已有证据，建议后续由 B 映射为已满足 | 1 |
| 确需补证 | 27 |
| 发现实际失败 | 1 |
| 合计 | **29** |

本报告不会原地改写已批准 v5.3 的 A137/B29/C5/D5 快照。上述结果应作为 v5.3 获批后的补充审查结论，在未来 P2 Acceptance Profile 中引用。

## 6. 已有证据

### P0-B10 / F04-AC04

结论：现有后续 C15 冻结证据已经完整覆盖，建议不再重复补证。

现有证据：

- `implementation/p1/c15/c15-verification-evidence.v2.json`
- SHA-256：`9b53f2dcc84ef5e70c960e5d30b8e5ab2ec4b4617d8a39a52ec9ef426bf8ac33`
- 验证源码提交：`6a23e93ed37eabec1201ff3a7bb00a0d9231fc49`
- 冻结提交：`9aab0cb19d14848dfd837729dd7df07828043258`

已有测试覆盖：

- 对象或目录绑定变化使旧决定失效；
- 过期、撤回、身份撤销和哈希篡改失败关闭；
- 聊天同意、Stage Approval 和普通按钮值不能冒充 HumanDecision；
- C06 拒绝发生在 C15 副作用写入之前；
- 直接调用执行入口时无有效决定会被拒绝；
- 被拒绝路径的副作用写入数为零。

处理建议：

- 保留 v5.3 原文不变；
- 在 P2 Acceptance Profile 中把 F04-AC04 映射到上述 C15 冻结证据；
- 不再为 P0-B10 重复创建同义测试。

## 7. 确需补证

### 7.1 P0：9 组，覆盖 12 项

| 组 | 覆盖项 | 已有支持 | 仍缺少的最小闭环 |
|---|---|---|---|
| P0-B01 | F01-AC03 | 已有递归对象键排序和稳定摘要实现 | 乱序、嵌套对象、数组边界的规范化 UTF-8 bytes 与摘要回执 |
| P0-B02 | F01-AC04 | 同进程两个 Control 实例摘要相同 | 三个独立进程、环境信息、规范化 bytes 摘要和最终 SHA-256 对账 |
| P0-B04 | F02-AC03/04/05、F04-AC05 | Fixture 水印、企业标识和凭据单文件负例 | 全部保护 Surface 清单、Canary、正式 build/CI 阻断和发布包回执 |
| P0-B05 | F03-AC01 | Canonical Schema 和手写结构检查 | 固定版本 JSON Schema 2020-12 校验器、编译及逐关键字正反例 |
| P0-B06 | F03-AC05 | Compatibility Matrix 和同模块 Mock | 独立 Consumer/Provider 只依赖冻结契约完成 Synthetic 集成 |
| P0-B07 | F03-AC06 | Breaking checker 已覆盖多类变更 | 全类别 mutation、CLI 非零退出和正式 CI 阻断 |
| P0-B08 | F03-AC07 | Deprecation Matrix 目前全部 ACTIVE | deprecated 正反例、替代路径、公告日和停止日闭包 |
| P0-B09 | F04-AC01 | Threat Model、资产和测试分别存在 | 架构—资产—边界—数据流—威胁—案例机器对账，未映射为零 |
| P0-B11 | F04-AC07 | Dataset、阈值、人工候选和 C13 治理引用已冻结 | 线上 D1 人工基线事件 ID/时间、准确引用和分歧裁决摘要 |

### 7.2 P1 C01—C10：9 组，覆盖 9 项

| 组 | 覆盖项 | 已有支持 | 仍缺少的最小闭环 |
|---|---|---|---|
| P1-B01 | C01-AC04 | Stream Tenant/Owner/Run/Sequence 绑定和 Core 异常拒绝 | 取消、服务端超时、客户端断线 E2E，以及后续 Tool/Connector 副作用为零 |
| P1-B02 | C01-AC05 | Citation View 合同和 C11 EvidenceRef | C01→C11→C10 真实 Synthetic 对账；撤回、删除、无权限时显示不可用 |
| P1-B03 | C02-AC05 | 高风险二次确认和 C18 namespace 检查 | 真实 C18 append、同 Tenant 回读、哈希绑定、不可变和重放 |
| P1-B04 | C04-AC02 | SCIM Adapter 幂等和 C05 IdentityLink 独立唯一性 | 重复/乱序 SCIM 贯穿 C04→C05 的组合闭环 |
| P1-B05 | C04-AC04 | 停用后 epoch/session 会拒绝 | 数值 SLA、提交时间、最后允许时间和跨 BFF/Core/Cache 计时 |
| P1-B06 | C05-AC05 | 单次 Action Identity、C15 局部 operation 和 G1 主链 | 全部受保护 operation→C05/C06/C08/C15/C18 归因覆盖表 |
| P1-B07 | C06-AC08 | 下一请求使用新授权版本且旧 Allow 不能提交 | 撤权 SLA、全部 PEP 与缓存的逐路径计时 |
| P1-B08 | C08-AC08 | 静态 ref/version/hash 和重建证据 | 可变 Synthetic 权威源、陈旧引用识别和 C08 无正文专项扫描 |
| P1-B09 | C09-AC06 | 主库、Checkpoint、恢复副本删除不复活 | 个人记忆完整数据面清单；向量/缓存 N/A 或删除命中为零 |

### 7.3 P1 C11—C19：6 组，覆盖 6 项

| 组 | 覆盖项 | 已有支持 | 仍缺少的最小闭环 |
|---|---|---|---|
| P1-B10 | C11-AC04 | 四个固定安全/权限/拒答查询和确定性排名 | 更完整相关性标注集、Recall/Precision 公式、分母、阈值和逐查询结果 |
| P1-B11 | C13-AC02 | CODEOWNERS、本地 review fixture 和发布状态机 | 真实托管仓库分支保护、required approval/status check 和未审批拒绝证据 |
| P1-B12 | C15-AC05 | 完整候选对象进入 artifact/hash，部分变化已使旧决定失效 | 字段、收件人、附件、规则、Skill、各版本逐项参数化失效矩阵 |
| P1-B13 | C17-AC05 | Schema 注入、重放和超时负例 | 乱序、迟到、重复事件负例及统一可靠性回执 |
| P1-B14 | C19-AC08 | Synthetic booked/supplier variance 计算 | 独立 Provider/基础设施账单输入、账期、行映射、阈值和未匹配负例 |
| P1-B15 | C19-AC09 | 严格字段集合和任意 metadata 拒绝 | 项目进度、发票、企业 BI 指标三类非法真值穿过 Schema/API/DB 的负例 |

## 8. 发现实际失败

### P0-B03 / F01-AC06

要求：

> Manifest 定义、D1 状态和 Git 证据三类事实不能互相冒充。

当前行为不满足该要求。

### 8.1 发现一：Manifest 状态被当成当前投影

`lib/project-control.mjs` 的 `projectState()` 在应用 D1 journal event 之前，直接使用 Manifest 中的：

- `implementation_status`
- `verification_status`
- `artifact_refs`
- `evidence_hashes`
- `verified_at`

初始化当前工作包状态。

现有测试 `the current baseline reports only evidence-verified work and keeps G0 closed` 在空 journal 下仍断言 F01、F02、F03 为 `VERIFIED`。这证明 Manifest 状态正在充当 D1 当前状态。

### 8.2 发现二：仅格式合法的伪证据可以令工作包 VERIFIED

现有测试辅助 `verifyPackage()` 使用：

- 实际不存在的 `evidence/F02.json` 等路径；
- 仅满足 `sha256:<64位十六进制>` 格式的伪哈希；

仍能通过 `RECORD_WORK_PACKAGE` 把工作包标为 `VERIFIED`，随后令 G0 达到 `READY_TO_SUBMIT`。

当前命令只检查：

- EvidenceRef 数组非空；
- EvidenceHash 数组非空；
- 哈希字符串格式合法。

它没有证明：

- Git 对象真实存在；
- 文件内容与声明哈希相同；
- Evidence Index 已冻结并引用该对象；
- Evidence Index 属于正确父工作包；
- 当前提交或 Release Digest 包含该证据。

### 8.3 为什么测试仍然全绿

相关只读复跑为通过，原因不是机制正确，而是测试把上述行为写成了预期结果。

本次主复核再次确认：

- 空 journal 继承 Manifest 状态的测试通过；
- 使用伪路径和伪哈希打开 G0 的测试通过；
- 因此这是“绿色测试掩盖的机制缺陷”，不是普通缺回执。

### 8.4 Gate 影响边界

该缺陷不能自动撤销 G0。

当前只能确认：

- Gate 机制存在接受伪证据引用的能力；
- 还没有读取本次线上最新 D1；
- 还没有核验历史 G0 每一条实际 D1 evidence ref 是否都指向真实 Git 对象；
- 因此不能直接认定历史 G0 一定误判。

只有完成机制修复并回放历史 G0 后，发现历史 Submission 实际引用也不成立，才应提出追加式 G0 复核或整改事件。

### 8.5 建议整改

在 Product Owner 确认本报告后：

1. 当前状态投影缺少工作包状态事件时失败关闭，不再从 Manifest 状态字段继承实时状态；
2. Manifest 继续只提供工作包定义、依赖、Gate 成员和初始定义基线；
3. `VERIFIED` 事件必须引用被冻结的 Evidence Index；
4. 在受信任 Git/Release 校验层核验对象存在、内容哈希、父包归属和 Commit/Release Digest；
5. 增加三类负例：
   - 修改 Manifest 状态不能改变 D1 当前投影；
   - D1 事件不能改变 Manifest 定义；
   - 虚假、缺失或未冻结 Git 证据不能令包 `VERIFIED`；
6. 修复后只读回放历史 G0 Submission；
7. 若历史证据真实闭环，只追加修复回执，不改历史 G0；
8. 若历史证据不成立，再提交追加式复核和整改建议，不覆盖旧记录。

## 9. 测试复核说明

本轮查重包含只读测试复跑：

- P0 相关现有测试：74 PASS，0 FAIL；
- P1 C11—C19 目标测试：191 PASS，0 FAIL；
- 主复核再次运行 P0 事实源相关测试和 C15 审批绕过相关测试：6 PASS，0 FAIL。

这些结果只证明现有测试可以重复执行。它们不能把未覆盖的最小验收项自动判为 PASS。

## 10. 建议下一步

在 Product Owner 确认本报告前：

- 不修改 D1；
- 不补证；
- 不修复 P0-B03；
- 不改变 v5.3；
- 不冻结 P2 Acceptance Profile；
- 不开始 O02/O03。

确认报告后，建议顺序：

1. 恢复线上 D1 受权只读访问并取得最新 revision；
2. 优先整改 P0-B03，生成机制修复和负例回执；
3. 回放并核验历史 G0 实际证据引用；
4. 将 P0-B10 映射为已有证据，避免重复建设；
5. 按风险顺序补齐其余 24 组、27 项缺口；
6. 冻结补证汇总 Evidence Index；
7. 冻结 P2 Acceptance Profile；
8. 再开始 O02 和 O03。

