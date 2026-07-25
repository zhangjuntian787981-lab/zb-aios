# 中宝企业 AI 员工平台

当前处于“P0 已授权、Owner 事实待核实”。总经理已批准项目，并授权当前项目负责人全权负责后续项目决策；不再逐项请示总经理。AI 推荐资料包已经形成，待业务、资料、IT 和安全 Owner 核实事实后，由项目负责人集中审批。OA、U9、BI 暂时保持 C0（未接入、无生产凭据、无生产出站网络）。

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

- `p0:status`：只读显示授权、Owner 事实核实、集中审批和技术证据。
- `p0:gate`：严格阶段门。当前应以退出码 `2` 返回 `NOT_READY`；只有全部公司确认和技术证据通过后才允许退出码 `0`。
- 退出码 `3` 表示发现凭据、出站网络、真实读取或提前开放 P1 等安全阻断。

P0 入口与边界见 `implementation/p0/README.md`。

## 验证

```bash
npm run lint
npm test
```

私有进度中心读取 D1 中的真实任务状态；只有“已验收”任务计入完成度，任务状态更新要求工作区身份和幂等编号。
