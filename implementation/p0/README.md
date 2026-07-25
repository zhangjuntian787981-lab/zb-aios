# P0：通用产品边界与技术基线

本目录只服务于通用多企业 AI 员工平台的 P0，不代表任何企业已经接入。

## 当前规则

- 当前用户是外部产品所有者和唯一阶段审批人，不是目标企业员工。
- P0—P2 不请求、保存或使用任何企业内部资料、真实用户、凭据或网络地址。
- P0—P2 只使用合成租户、合成用户、合成知识和合成系统响应。
- P3 前可以收集有来源的公开企业信息，但必须标记为 `PUBLIC_EXTERNAL_CONTEXT`，不能作为企业内部事实。
- P2 经产品所有者批准后，P3 才能接收企业接入包并逐级激活 Connector。
- 本项目只记录产品所有者的阶段审批结果，不记录其他部门的审批过程。

## 主要文件

- `baseline.json`：可执行的 P0 阶段基线和门禁状态。
- `materials-and-recommendations.v1.md`：P0—P2 无资料建设及 P3 一次性接入清单。
- `connector-envelope.v1.json`：厂商无关的 Connector Template 契约。
- `evidence/product-model-directive-2026-07-25.md`：本轮产品模型与审批规则的用户指令证据。

## 本地核验

```bash
npm run p0:status
npm run p0:gate
node --test tests/project-policy.test.mjs tests/p0-gate.test.mjs
```

`p0:gate` 在阶段审批前保持阻断是正常结果。它应明确指出尚未完成的技术门和 P0 阶段审批，而不能要求企业内部资料或企业负责人。
