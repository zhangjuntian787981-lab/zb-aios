# ADR 0008: C13 受保护源码评审

- 状态：Candidate
- 日期：2026-07-30
- 范围：C13 / P1-B11 / C13-AC02
- 数据边界：P1_SYNTHETIC_ONLY

## 决定

参考
`implementation/p1/c13/p1-b11-official-reference-research.v1.md`，
C13 的目标托管控制采用 GitHub CODEOWNERS、active branch Ruleset、
required human/code-owner review、required status checks 和只读 REST
回读。正常路径不配置 human、administrator、team、App 或 deploy key
bypass。

候选 Ruleset 精确命中默认分支，禁止删除和 non-fast-forward，要求：

- 至少一名批准者；
- Code Owner 批准；
- 新 push 撤销旧批准；
- 最新可评审 push 由非最后推送者批准；
- review thread 全部解决；
- `protected-surface-gate`、`contract-compatibility-gate` 和
  `c13-source-review-gate` 均通过且来源为 GitHub Actions。

## 当前阻塞

GitHub 官方只读 API 对当前私有仓库的 Ruleset 与 branch protection
能力返回稳定 403，并要求升级 GitHub Pro 或把仓库公开。为通过验收而公开
源代码不是可接受的自动修复，本 ADR 不改变仓库可见性或订阅。

当前也不存在第二名真实人类复核人。现有仓库 Owner 可以使 CODEOWNERS
语法可解析，但不能审查自己的提交，不能替代独立复核。正式闭合必须先：

1. 由外部完成适合私有仓库的 GitHub 套餐能力；
2. 邀请具有写权限的第二名真实人类复核人；
3. 将 C13 敏感路径绑定到该复核人或合格团队；
4. 读回零 CODEOWNERS 错误；
5. 应用并读回无 bypass 的 Ruleset；
6. 冻结未批准、stale approval 和 required check 失败均无法合并的真实负例；
7. 冻结第二名 Code Owner 对准确 head SHA 的真实批准。

## 推迟与拒绝

- Classic branch protection：`DEFER`。只有 Ruleset 不可用且能证明同等
  admin 不可绕过能力时才重新审查。
- Merge queue：`DEFER`。当前没有高并发合并需求，且不属于 P1-B11
  的最小边界。
- 正常路径任何 bypass：`REJECT`。
- 为取得私有仓库规则能力而自动公开仓库：`REJECT`。

## 治理效力

This ADR does not close P1-B11.

This ADR does not claim that the candidate Ruleset is applied.

This ADR does not prove an independent human review.

This ADR does not create D1, Gate, Profile, or start-authorization state.

候选 Ruleset、CODEOWNERS 和托管检查只是后续远端验收的输入。Git 冻结
这些字节不会产生远端保护效力，也不会改变 P0/P1、G0/G1、Manifest、
Profile 或 O02/O03 状态。
