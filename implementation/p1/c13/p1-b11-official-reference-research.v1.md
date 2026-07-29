# P1-B11 / C13-AC02 GitHub 官方参考研究

## 1. 研究边界

- 查询日期：`2026-07-30`
- 本仓库研究基线：`5d12201e984937a905ab8bae90a86a4b1763d899`
- 工作包：`C13`
- 补证项：`P1-B11`
- 验收目标：为“Skill 变更经过受保护 Git 评审和指定 Owner 批准”确定可复核的 GitHub 托管控制与证据读取方法。
- 权威来源范围：GitHub 官方 Docs、GitHub 官方文档仓库、GitHub 官方 REST OpenAPI 仓库。
- 明确排除：第三方博客、搜索摘要、AI 回答、未经官方文档支持的产品能力推断。

本文件是只读研究快照，不是 Reference Review Receipt、ADR、Ruleset、branch protection、required review、required status check 或治理批准。它不证明任何控制已在远端启用，也不改变 `P1-B11` 当前状态。

## 2. 官方资料快照与许可证

### 2.1 GitHub Docs

- 官方仓库：[github/docs](https://github.com/github/docs)
- 固定快照 commit：[`6f69b5126a8616e7fab257af61999e8f9416250d`](https://github.com/github/docs/tree/6f69b5126a8616e7fab257af61999e8f9416250d)
- 该 commit 时间：`2026-07-29T20:41:16Z`
- 文档内容许可证：[Creative Commons Attribution 4.0 International](https://github.com/github/docs/blob/6f69b5126a8616e7fab257af61999e8f9416250d/LICENSE)
- 使用边界：本文件仅作摘要和链接引用；若复制或改编受许可文档内容，须按 CC BY 4.0 履行署名要求。GitHub 托管服务本身不是因文档许可证而成为可再分发或可白标的开源软件。

实际阅读的固定文件：

1. [`about-code-owners.md`](https://github.com/github/docs/blob/6f69b5126a8616e7fab257af61999e8f9416250d/content/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/about-code-owners.md)
   - `Who can use this feature?`
   - `About code owners`
   - `CODEOWNERS file location`
   - `CODEOWNERS and forks`
   - `CODEOWNERS file size`
   - `CODEOWNERS syntax`
   - `CODEOWNERS and branch protection`
2. [`about-rulesets.md`](https://github.com/github/docs/blob/6f69b5126a8616e7fab257af61999e8f9416250d/content/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/about-rulesets.md)
   - `Who can use this feature?`
   - `About rulesets and protected branches`
   - `Using ruleset enforcement statuses`
   - `About rule layering`
3. [`available-rules-for-rulesets.md`](https://github.com/github/docs/blob/6f69b5126a8616e7fab257af61999e8f9416250d/content/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/available-rules-for-rulesets.md)
   - `Require a pull request before merging`
   - `Required reviewers`
   - `Require status checks to pass before merging`
   - `Block force pushes`
4. [`creating-rulesets-for-a-repository.md`](https://github.com/github/docs/blob/6f69b5126a8616e7fab257af61999e8f9416250d/content/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/creating-rulesets-for-a-repository.md)
   - `Using ruleset enforcement statuses`
   - `Granting bypass permissions for your branch or tag ruleset`
   - `Choosing which branches or tags to target`
   - `Selecting branch or tag protections`
5. [`about-protected-branches.md`](https://github.com/github/docs/blob/6f69b5126a8616e7fab257af61999e8f9416250d/content/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches.md)
   - `About branch protection rules`
   - `Require pull request reviews before merging`
   - `Require status checks before merging`
   - `Do not allow bypassing the above settings`
6. [`managing-a-merge-queue.md`](https://github.com/github/docs/blob/6f69b5126a8616e7fab257af61999e8f9416250d/content/repositories/configuring-branches-and-merges-in-your-repository/configuring-pull-request-merges/managing-a-merge-queue.md)
   - `Who can use this feature?`
   - `About merge queues`
   - `Configuring continuous integration (CI) workflows for merge queues`
   - `Triggering merge group checks with GitHub Actions`

### 2.2 GitHub REST API

- 固定 API 版本：`2026-03-10`
- 版本依据：[API Versions](https://docs.github.com/en/rest/about-the-rest-api/api-versions?apiVersion=2026-03-10)
- 官方 OpenAPI 仓库：[github/rest-api-description](https://github.com/github/rest-api-description)
- 固定描述 commit：[`768a056f8e09a337a050da627073cc3c99ba1607`](https://github.com/github/rest-api-description/tree/768a056f8e09a337a050da627073cc3c99ba1607)
- 该 commit 时间：`2026-07-28T18:01:54Z`
- 许可证：[MIT](https://github.com/github/rest-api-description/blob/768a056f8e09a337a050da627073cc3c99ba1607/LICENSE.md)
- 使用边界：未来读取证据应显式发送 `X-GitHub-Api-Version: 2026-03-10`；本研究不复制 API 客户端代码，也不把 MIT OpenAPI 描述的许可解释为 GitHub 托管服务的再分发许可。

实际阅读的官方 API 文档：

- [Repository rules endpoints](https://docs.github.com/en/rest/repos/rules?apiVersion=2026-03-10)：适用规则、仓库 Rulesets、单个 Ruleset、Ruleset 历史和版本。
- [Protected branches endpoints](https://docs.github.com/en/rest/branches/branch-protection?apiVersion=2026-03-10)：读取 branch protection、required reviews、required checks 与 admin enforcement。
- [Repositories endpoints — List CODEOWNERS errors](https://docs.github.com/en/rest/repos/repos?apiVersion=2026-03-10)：按 `ref` 读取 CODEOWNERS 语法错误。

## 3. 官方事实与本项目含义

### 3.1 CODEOWNERS

GitHub 从 `.github/`、仓库根目录、`docs/` 依次查找第一个 `CODEOWNERS`；PR 使用 base branch 上的版本。Owner 必须拥有仓库写权限，团队还必须可见且拥有写权限。文件超过 3 MB 不会加载；无效行会被跳过；路径大小写敏感。

`CODEOWNERS` 会自动请求相关 Owner 评审，但这本身不等于必须批准。只有在分支保护或 Ruleset 中启用 required reviews / require review from Code Owners，Owner 批准才会成为合并条件。若同一路径列出多个 Owner，其中任意一个 Owner 的批准即可满足 Code Owner 要求。

官方还建议保护 `CODEOWNERS` 自身，最直接方式是在 `.github/CODEOWNERS` 中为 `/.github/CODEOWNERS` 或整个 `/.github/` 指定 Owner。

本项目含义：

- 现有 `.github/CODEOWNERS` 是必要输入，不是远端强制证据。
- 当前敏感路径只绑定 `@tristian`；在仅有一名实施者时，它不能产生真实独立评审。正式闭合需要第二名具有写权限的合格人类 Reviewer/Code Owner，或满足同等独立性要求的可审计团队。
- 正式证据必须包括 base branch 上准确 `CODEOWNERS` 字节、`List CODEOWNERS errors` 返回零错误，以及实际 PR 的 Review/mergeability 结果。

### 3.2 Rulesets 与 classic branch protection

Rulesets 与 classic branch protection 可以叠加；多条 Ruleset 同时命中时会聚合，冲突时采用更严格规则。Rulesets 有 `active`/`disabled` 状态、可由有读权限的人查看，并可通过 API 读取版本历史；这些特性更适合可审计治理。

Classic branch protection 同一时间只会有一条规则作用于某分支，且默认不约束 repository admin 或具有 bypass branch protections 权限的角色，除非显式启用“不允许绕过”。因此不能把“存在 branch protection”直接解释为管理员也不可绕过。

本项目含义：

- 目标控制优先采用一个 `active` 的 branch Ruleset，精确命中 `refs/heads/main`。
- 不应同时维护含义重叠但配置不同的 classic branch protection；若历史规则存在，必须读回并证明聚合后的最终约束，不得假定 Ruleset 覆盖它。
- Ruleset `bypass_actors` 应为空。任何 break-glass 例外必须另行治理，且不能算作 P1-B11 的正常受保护路径。

### 3.3 Required reviews

Ruleset 可以要求：

- PR 合并前达到指定批准数；
- 对命中 CODEOWNERS 的文件取得 Code Owner 批准；
- 新提交后撤销旧批准；
- 最新可评审 push 由非最后推送者批准；
- 限制谁可以 dismiss review。

本项目建议最小强制集：

1. require pull request before merging；
2. required approving review count 至少 `1`；
3. require code owner review；
4. dismiss stale approvals；
5. require approval of the most recent reviewable push；
6. Reviewer 必须不是实现者/最后推送者。

这组设置仍不能凭配置文件证明独立评审已发生；必须冻结真实第二名 Reviewer 的 GitHub review 回执。当前单一实施者条件下，若没有第二名合格 Reviewer，结果必须保持 `INCONCLUSIVE`。

### 3.4 Required status checks

GitHub 规定：设为 required 的 check/status 必须通过，才能合并到目标分支。可以指定提交状态的预期 GitHub App 来源；如果由其他人或集成提交同名状态，GitHub 不允许合并。

本项目含义：

- 必须使用已在真实 PR 上产生过的精确 check name；不得从 workflow 文件名猜测。
- required check 应绑定预期来源 GitHub Actions App，而不是 `any source`。
- 检查名称必须跨工作流唯一，否则可能产生歧义并阻断合并。
- 正式证据应同时冻结：
  - Ruleset 读回中的 required check 参数；
  - 成功 PR 上同名 check 的 `success` 回执；
  - 失败/缺失 required check 的未合并负例；
  - Ruleset API 与 PR mergeability 的时间、ID、commit SHA 和响应摘要。

### 3.5 Bypass 与 administrator

Ruleset 可向 repository role、team、GitHub App、用户等授予 `always` 或 `pull_request` bypass。即使是“仅 PR 绕过”，该 actor 仍可选择绕过保护并合并。

本项目决定：正常 P1-B11 受保护路径不接受任何 human、administrator、team、App 或 deploy key bypass。读取证据时必须检查 `bypass_actors` 的实际返回值，不能只看 UI 截图或本地期望配置。若平台、Owner 类型或计划导致不能证明 bypass 为空，P1-B11 必须 fail closed。

### 3.6 私有仓库与套餐限制

GitHub 官方资料明确：

- 私有仓库中的 CODEOWNERS 需要 GitHub Pro、GitHub Team、GitHub Enterprise Cloud 或 Enterprise Server。
- 私有仓库中的 Rulesets 需要 GitHub Pro、GitHub Team 或 GitHub Enterprise Cloud。
- 私有仓库中的 protected branches 需要 GitHub Pro、GitHub Team、GitHub Enterprise Cloud 或 Enterprise Server。
- 私有仓库 merge queue 仅适用于 GitHub Enterprise Cloud 下的组织仓库。

本研究不读取或推断当前账号套餐。当前仓库是否具备这些能力是 `UNKNOWN`，必须由 GitHub 官方 UI/API 的实际成功或稳定拒绝回执证明。若私有仓库计划不支持，不能用本地测试代替；需由 Product Owner 单独决定升级计划、迁移到合格组织仓库，或保持 P1-B11 未闭合。

### 3.7 Merge queue

Merge queue 适合高并发、多 PR 的繁忙分支。若 required checks 与 merge queue 共用 GitHub Actions，工作流必须额外监听 `merge_group`；否则 required check 不会在队列临时分支上触发，合并会失败。

当前 P1-B11 只需证明受保护 PR、Owner 批准与 required checks；没有证据表明需要 merge queue，且私有仓库还受组织 Enterprise Cloud 限制。因此本阶段推迟，不把它作为 P1-B11 硬阻塞。

## 4. 决定总表

| 候选 | 决定 | 当前适用范围 | 不能宣称 |
|---|---|---|---|
| GitHub CODEOWNERS | `ADOPT` | base branch 上的敏感路径 Owner 映射；保护 CODEOWNERS 自身；API 零错误验证 | 文件存在不等于 required approval 已启用 |
| GitHub repository branch Ruleset | `ADOPT`，以套餐可用为前提 | `active`、精确命中 `main`、要求 PR/review/check、阻止 force push/delete、空 bypass | 研究决定不等于远端已经创建或生效 |
| Classic branch protection | `DEFER` | Ruleset 不可用时的显式备选；使用前需单独决定并读回 admin enforcement | 不得与 Ruleset 形成未核验的重叠配置 |
| Required approving review | `ADOPT` | 至少 1 个合格人类批准；最新 push 由非推送者批准；撤销 stale approval | 单一实施者自批不能替代独立 Review |
| Required Code Owner review | `ADOPT` | C13 与治理敏感路径 | `@tristian` 单 Owner 不证明独立性 |
| Required status checks | `ADOPT` | 精确 check name、预期 GitHub Actions App、正负 PR 证据 | workflow/test 通过不等于已设为 required |
| Human/admin/App bypass | `REJECT` | 正常 P1-B11 保护路径中 `bypass_actors=[]` | 管理员身份不能被默认为“仍受保护” |
| Ruleset/branch protection 套餐升级或仓库迁移 | `DEFER` | 仅当官方实际回执证明当前私有仓库计划不支持时，由 Product Owner 单独决定 | 不得由研究或代码自动改变套餐/所有权/可见性 |
| Merge queue | `DEFER` | 未来高并发且满足组织/套餐前提时重新审查 | 当前不作为 P1-B11 闭合条件 |
| GitHub REST API `2026-03-10` 只读证据采集 | `ADOPT` | Ruleset、适用规则、历史版本、branch protection、CODEOWNERS errors 的确定性回读 | API 响应不能替代真实第二名 Reviewer |

未采用的内容：

- 不采用第三方 branch protection bot 或外部策略引擎；GitHub 原生控制已覆盖本项需要，新增外部执行面没有必要。
- 不采用 merge queue 作为当前 P1-B11 前置条件。
- 不采用 classic branch protection 作为首选，以避免与 Ruleset 的聚合配置形成难以解释的双重真相。
- 不采用本地 YAML、聊天批准、普通 commit 或成功 CI run 冒充远端 required 配置。

## 5. 最小远端验证合同

正式 P1-B11 补证至少应取得以下 GitHub 第一方事实，并按原始 UTF-8 响应字节或确定性 JSON canonicalization 冻结 SHA-256：

1. Repository identity、visibility、owner type 与套餐能力成功/拒绝回执。
2. base branch 上 `.github/CODEOWNERS` 的准确 blob SHA。
3. `GET /repos/{owner}/{repo}/codeowners/errors?ref=<base-sha>` 返回零错误。
4. `GET /repos/{owner}/{repo}/rulesets` 与单个 Ruleset 返回：
   - `target=branch`
   - `enforcement=active`
   - 精确 `main` include
   - `bypass_actors=[]`
   - require pull request
   - required approving review count
   - require code owner review
   - dismiss stale approvals
   - require last push approval
   - required status checks 及预期来源
   - block force pushes/deletions
5. `GET /repos/{owner}/{repo}/rules/branches/main` 证明最终生效规则，而不仅是某一 Ruleset 草案。
6. 正向 PR：
   - 第二名合格 Reviewer/Code Owner 的批准；
   - required checks 全部成功；
   - mergeability 允许；
   - 合并仅在单独授权范围内进行；本补证可以保持 PR 不合并。
7. 负向 PR：
   - 未批准时不能合并；
   - required check 失败或缺失时不能合并；
   - push 新 commit 后旧批准失效；
   - 没有 bypass actor 可以越过这些条件。

若当前只有一名实施者，步骤 6 的独立 Review 不得标记 PASS。平台配置可先完成，但 P1-B11 仍应保持 `INCONCLUSIVE`，直到真实第二名 Reviewer 出现。

## 6. 安全、运维与退出

- 权限：配置 Ruleset/branch protection 需要 administration 权限；证据采集使用最小只读权限，不能把长期管理 Token 写入仓库、日志或证据。
- 数据流：源代码、PR diff、Review 和 CI 元数据进入 GitHub 托管边界；本项不允许企业真实数据、OA、ERP、BI 或生产凭据进入仓库。
- 维护：固定 API 版本 `2026-03-10`；升级 API 版本前阅读 breaking changes 并重新跑只读契约测试。
- 漂移：Ruleset version、CODEOWNERS blob、required check name/source、base branch 或 bypass list 任一变化，都使旧 P1-B11 远端证据过期。
- 退出：若离开 GitHub，先导出 Ruleset/branch protection/CODEOWNERS/Review/check 证据及哈希，再选择具备等价“不可绕过评审 + required check + 审计回读”的平台；迁移前不得宣称控制等价。

## 7. 当前结论

官方资料支持使用 `CODEOWNERS + active branch Ruleset + required human/code-owner review + required status checks + empty bypass list` 作为 C13-AC02 的目标托管控制。

但本文件不证明：

- 当前私有仓库套餐支持上述能力；
- 远端 Ruleset 或 branch protection 已创建；
- CODEOWNERS Owner 资格和语法已由 GitHub 验证；
- required check 已绑定；
- 未批准/失败 PR 已被远端真实拒绝；
- 已存在第二名独立 Reviewer；
- P1-B11、P2 Profile 或任何启动授权已通过。

因此，研究阶段结论是：参考方案可采用，治理状态不变。正式闭合必须等待 GitHub 远端只读回执、正负 PR 拒绝证据和真实第二名独立 Reviewer。
