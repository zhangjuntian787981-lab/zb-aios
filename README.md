# 通用多企业 AI 员工平台

当前处于 P0“产品边界与技术基线”。P0—P2 只建设和验证通用产品，不索取或使用任何目标企业内部资料、真实员工、企业凭据或真实系统连接；P3 才一次性接入目标企业。

当前用户按“外部产品所有者”建模，不是目标企业员工，是 P0、P1、P2、P3 的唯一阶段审批人。项目只记录产品所有者的阶段审批结果，不跟踪其他部门的审批过程。

## 当前资料边界

- P0—P2：只使用 Synthetic Fixtures。
- P3 前可选：有来源的 `PUBLIC_EXTERNAL_CONTEXT`。
- P3：接收经授权的 Enterprise Onboarding Package。
- 企业 Connector 在 P3 前固定为 C0、无企业凭据、无企业网络访问。

详细方案：

- [完备工程级方案 v4.0](docs/plans/通用多企业AI员工平台_完备工程级方案_v4.0.md)
- [小白易懂方案 v2.0](docs/plans/通用多企业AI员工平台_小白易懂方案_v2.0.md)
- [P0 实施入口](implementation/p0/README.md)
- [通用产品与 P3 企业接入规则](implementation/p0/materials-and-recommendations.v1.md)

## Prerequisites

- Node.js `>=22.13.0`

## 本地运行

```bash
npm install
npm run dev
npm run build
```

## P0 阶段门

```bash
npm run p0:status
npm run p0:gate
```

- `p0:status`：只读显示产品边界、技术证据和产品所有者阶段审批状态。
- `p0:gate`：严格阶段门；未完成时退出码 `2`。
- 发现 P0—P2 企业内部资料、企业用户、企业凭据、企业网络、Connector 大于 C0 或提前开放 P1 时退出码 `3`。

## 验证

```bash
npm run lint
npm test
```

私有进度中心读取 D1 中的任务状态；只有“已验收”任务计入进度。后续阶段任务和 Connector 激活由服务端阶段门阻止跳级。
