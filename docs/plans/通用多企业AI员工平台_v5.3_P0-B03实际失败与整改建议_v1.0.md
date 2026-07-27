# 通用多企业 AI 员工平台：v5.3 P0-B03 实际失败与整改建议

- 报告版本：v1.0
- 报告日期：2026-07-28
- 对应批准报告：`通用多企业AI员工平台_v5.3补证查重报告_v1.0.md`
- 对应批准报告 SHA-256：`0aaa1ec6987a9479874d21f44ca8663df4537e341e3d352d07b8811c67163cd5`
- 报告性质：只读历史回放、机制修复与整改建议，不是 D1 事件、工作包状态、GateSubmission 或 GateDecision

## 1. 结论

P0-B03 的机制缺陷已经修复并冻结到 Git；同时，授权 GET-only 历史回放确认，线上 F04 最新记录所引用的一个工程证据哈希确实不是 Git 冻结版本。

因此，本次结果属于：

1. **机制缺陷已修复**：Manifest 状态不再冒充 D1 当前状态；新 `VERIFIED` 命令必须精确匹配 Git 冻结证据目录；
2. **历史实际失败已确认**：F04 的线上工程证据哈希与可达 Git 历史不一致；
3. **历史记录未被改写**：线上 D1 仍记录 F04 为 `VERIFIED`，G0/G1 仍为 `APPROVED`；
4. **下一步必须追加式整改**：不能删除或覆盖旧事件，应先追加有效 F04 证据，再重新提交并决定 G0。

## 2. 治理边界

本轮严格保持以下边界：

- 未修改 `work-package-manifest.v1.json`；
- 未修改 v5.3 或 410 项矩阵；
- 未向线上 D1 写入任何事件；
- 未修改 P0/P1 工作包状态；
- 未撤销、覆盖或重新批准 G0/G1；
- 未启动 O02、O03；
- 未接入企业资料、企业用户、企业凭据或企业系统；
- GET-only 临时访问路径只用于读取 `/api/progress`，未把令牌写入仓库、日志或报告。

## 3. 线上 D1 只读快照

授权 GET-only 读取获得：

- D1 revision：`64`
- 服务端时间：`2026-07-27T17:47:47.383Z`
- 工作包：`37`
- D1 已记录 `VERIFIED`：`23`
- P0：`4/4`
- P1：`19/19`
- G0：`APPROVED`
- G1：`APPROVED`
- G2：`NOT_READY`
- G3：`NOT_READY`

该结果只是上述服务端时间的只读快照，不代表未来 revision 永远保持 64。

## 4. 历史证据回放结果

### 4.1 F01—F03

F01、F02、F03 的线上 EvidenceRef 与 EvidenceHash 均能精确匹配 Git 冻结目录及提交：

- 冻结提交：`f43b861da7775d39d069d438a5e7dc2d941ae831`
- F01：`sha256:11baffbcb40eebd6496b5739798974aecb0a01cb214abe7a3c884d6e6f531f13`
- F02：`sha256:cf7255d621f7db0f88c70b0f690ced20d64294fd49aa711a8cfd1d9923797cb8`
- F03：`sha256:64aac8860a9b397860015542338ca90b2a8bd2e9381e56e53fa2ffb1dc01bcda`

### 4.2 F04

线上 D1 最新 F04 记录包含两个哈希：

```text
sha256:851851fcec6d961efaf17f6a0ced172c12dad2dced6746c9c9b805a205c95f62
sha256:1ac738d40ed6fb0bdaadb876c92b4f3cbde0d722142093bb786447365c9c5de0
```

Git 冻结事实为：

```text
implementation/p0/evidence/f04-evidence.v1.json
sha256:4791558978f34a3ccd15de80f05efc8beb13660227c11a4a308380ac9d100f35

implementation/p0/f04/human-baseline-candidate.v1.json
sha256:1ac738d40ed6fb0bdaadb876c92b4f3cbde0d722142093bb786447365c9c5de0
```

对 `implementation/p0/evidence/f04-evidence.v1.json` 的全部可达 Git 历史逐提交复算后，只发现：

```text
f43b861da7775d39d069d438a5e7dc2d941ae831
sha256:4791558978f34a3ccd15de80f05efc8beb13660227c11a4a308380ac9d100f35
```

没有发现内容哈希为 `851851...` 的已提交版本。因此：

- 人工基线哈希 `1ac738...` 有效；
- 工程证据哈希 `851851...` 不属于该文件的可达 Git 冻结版本；
- F04 历史证据引用不完整成立。

### 4.3 C01—C19

revision 64 中 C01—C19 的历史 EvidenceRef 不是纯路径，而是 D1 保存的单个完整字符串：

```text
<path> <sha256>
```

C04 还包含：

```text
source_commit:<commit> evidence_commit:<commit>
```

19 项准确原文已经保存为只含证据绑定的文件：

`implementation/governance/p1-d1-evidence-bindings.revision-64.v1.json`

该文件：

- 不包含工作包状态；
- 不包含 Gate 状态；
- 不包含进度；
- 不构成第二套治理真相；
- 只用于证明 D1 EvidenceRef 与 Git 冻结对象之间的精确绑定。

逐项回放结果：C01—C19 均匹配，没有新增 P1 历史证据失败。

## 5. 已完成的机制修复

源码提交：

```text
472762d94ea40ea45a8bffc6cde47b5038ce0866
fix(governance): bind verified state to frozen evidence
```

发布证据提交：

```text
e0592a4572e8181432756ece50834e447b5f4880
test(governance): freeze evidence verifier release
```

主要修复：

1. 空 D1 journal 时，37 个工作包全部从 `NOT_STARTED / NOT_VERIFIED` 投影，不再继承 Manifest 的运行状态；
2. Manifest 继续只定义工作包、依赖、适用性和 Gate 成员；
3. D1 仍独占工作包状态、GateSubmission 和 GateDecision；
4. 新 `VERIFIED` 命令必须与 Git 冻结证据目录逐项精确匹配；
5. 历史不匹配只生成 `EVIDENCE_NOT_FROZEN` 治理问题，不自动把 D1 的 `VERIFIED` 改成 `NOT_VERIFIED`；
6. 历史不匹配不自动撤销 G0/G1；
7. 当前阶段存在证据问题时，新的 Gate 提交或决定失败关闭；
8. P2 入口要求 G0 与 G1 同时有效；P3 入口要求 G0、G1、G2 同时有效；
9. C01—C19 使用 revision 64 的准确历史 EvidenceRef 格式，不再由纯路径推导。

## 6. 验证结果

最终验证：

- Build：PASS
- 全量测试：`895 PASS / 0 FAIL`
- Lint：PASS
- 定向 Git 冻结发布校验：`4 PASS / 0 FAIL`
- P0/P1 历史回放：
  - F01—F03：PASS
  - F04：发现实际失败
  - C01—C19：PASS

Git/Release 绑定：

- `implementation/governance/frozen-evidence-release.v1.json`
- SHA-256：`376fdcfd946191d5f2e2152d9556b10565accdf04f594cf2fb56debf0a25d6af`

该 Release 证据把 P0/P1 目录、运行时消费者、精确匹配校验器、治理控制器和回放测试绑定到源码提交 `472762d...`。

## 7. 对历史状态的影响

本报告不直接改变任何历史状态。

在没有新的 D1 事件前：

- F04 仍按 D1 显示 `VERIFIED`；
- G0 仍按 D1 显示 `APPROVED`；
- G1 仍按 D1 显示 `APPROVED`；
- 历史决定仍可审计；
- 证据健康单独显示为 F04 治理问题。

只有 Product Owner 批准并追加有效 F04 证据事件后，当前 G0 scope 才会发生显式变化。届时：

- F04 仍为 `VERIFIED`，但引用改为真实 Git 冻结证据；
- F04 治理问题清除；
- 历史 G0 Decision 保留；
- G0 当前投影变为需要重新提交；
- G0 重新批准前，P1/P2 阶段入口失败关闭；
- G0 重新批准后，如 G1 scope 未变化且 G1 历史批准仍有效，则不自动重做 G1。

## 8. 建议的追加式整改顺序

1. 只读刷新 D1，确认执行时 revision；
2. 展示一条准确的 F04 `WORK_PACKAGE_RECORDED` 候选事件；
3. Product Owner 对候选事件的完整内容和幂等键单独批准；
4. 追加 F04 有效证据：
   - 工程证据 `479155...`
   - 人工基线 `1ac738...`
5. GET 回读，确认 revision 增加、F04 治理问题清除、历史事件仍存在；
6. 生成新的 G0 GateSubmission 及准确 package hash；
7. Product Owner 对准确 G0 package hash 单独决定；
8. GET 回读，确认 G0 恢复 `APPROVED`；
9. 再继续其余 24 组补证。

## 9. 当前未授权事项

在 Product Owner 进一步批准前，不执行：

- 任何 D1 写入；
- F04 修复事件；
- G0 新提交或决定；
- G1 重新批准；
- G2；
- P2 Acceptance Profile；
- O02/O03；
- 生产企业资料或系统接入。
