# C01 员工 AI 门户与身份 BFF

当前工程状态：`IMPLEMENTED / EVIDENCE_CANDIDATE`

当前范围：`P1_SYNTHETIC_ONLY / C0_DISABLED`

## 冻结边界

C01 是可替换的体验壳和身份 BFF，不拥有 Tenant、Principal、授权、Run、
HumanDecision 或审计真相。

```text
员工体验壳
→ C01 身份 BFF
→ 每次请求由 C06 重新鉴权
→ Product Core 窄 read / mutate / stream Port
→ 仅返回本人或已由服务端过滤的合成视图
```

浏览器不能直接访问模型、RAG、Connector 或 Product Core。前端本地隐藏按钮
不是权限；绕过界面直接调用 BFF 仍会经过同一个 C06 PEP。

## P1 体验范围

- 主页、会话、Run、文件状态；
- 服务端过滤的 Agent/Skill 和资源目录；
- 本人记忆与审批视图；
- 引用视图；
- 只传递冻结命令引用和哈希的写操作；
- 只传递引用、不传正文的顺序流事件。

身份 BFF 不接受原始文件字节。P1 的文件命令由 Product Core 解析，成功回执
只能返回当前 Tenant 下的 `quarantine://c10/...` 引用和
`QUARANTINED` 状态；这不等于生产杀毒、DLP 或真实对象存储已经部署。

## 可替换门户

`LIBRECHAT_ADAPTER` 和 `MINIMAL_REPLACEMENT` 使用同一 BFF 合同。替换 renderer
可以改变界面、布局和客户端交互，但不能迁移或复制授权、审批、Run 或审计
真相。

LibreChat 当前只被冻结为参考基线 `v0.8.7` /
`9e74cc0e57b395926122bd4062c1fcedc48ed465`。本仓库没有嵌入或部署 LibreChat，
也没有把该版本描述为完成安全审查或生产批准。

## 验证

```text
sh scripts/run-c01-tests.sh
```

## P1 不证明

- 不连接真实 IdP、企业员工、公司资料或企业系统；
- 不包含真实浏览器 Cookie、CSRF、CSP 或 OIDC 回调验证；
- 不执行真实文件上传、恶意软件扫描或对象存储隔离；
- 不证明 LibreChat 部署、插件兼容、升级或生产安全；
- 不证明 WCAG 辅助技术、跨浏览器、容量、HA、备份、恢复或长稳；
- 跨模块三 Tenant 完整链路属于 G1，不由单个 C01 单测冒充。

这些限制不改变 C01 的 P1 核心验收：合成用户的 UI 绕过仍失败关闭、私人数据
不能跨用户或跨 Tenant，文件不能越过隔离态，且替换门户不迁移权限和审批
真相。
