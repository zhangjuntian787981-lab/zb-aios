# 中宝企业 AI 员工平台

当前仓库正在执行 P0“准备与边界确认”。OA、U9、BI 暂时保持 C0（未接入、无生产凭据、无生产出站网络），不会阻塞本地阶段门、确认材料和进度中心。

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

- `p0:status`：只读显示公司待确认项和技术证据。
- `p0:gate`：严格阶段门。当前应以退出码 `2` 返回 `NOT_READY`；只有全部公司确认和技术证据通过后才允许退出码 `0`。
- 退出码 `3` 表示发现凭据、出站网络、真实读取或提前开放 P1 等安全阻断。

P0 入口与边界见 `implementation/p0/README.md`。

## 验证

```bash
npm run lint
npm test
```

私有进度中心读取 D1 中的真实任务状态；只有“已验收”任务计入完成度，任务状态更新要求工作区身份和幂等编号。
