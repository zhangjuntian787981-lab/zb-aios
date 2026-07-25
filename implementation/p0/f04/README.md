# F04 质量与安全发布门基线

本目录交付的是可重复的发布门规则，不是生产通过证明。

## 文件

- `threat-model.v1.md`：资产、信任边界、滥用案例和剩余风险；
- `frozen-evaluation-cases.v1.json`：固定种子、冻结版本的 10 个案例；
- `human-baseline-placeholders.v1.json`：人工答案待填模板；明确不能作为通过证据；
- `zero-tolerance.v1.json`：七项零容忍规则；
- `release-gate.config.v1.json`：阈值、人工基线和判定优先级；
- `examples/pass-report.v1.json`：应判定为 `PASS` 的输入样例；
- `examples/fail-report.v1.json`：普通质量未达阈值，应判定为 `FAIL`；
- `examples/blocked-report.v1.json`：一次跨 Tenant 失败，即使平均分接近 1 也必须 `BLOCKED`。

## 判定器

纯函数：

```js
evaluateRelease({ config, suite, report })
```

它不读取网络、不修改输入，也不使用自动 Judge 结果。命令行只负责读取 JSON 并输出纯函数结果：

```bash
node scripts/f04-release-gate.mjs \
  implementation/p0/f04/examples/pass-report.v1.json
```

退出码：

- `0`：`PASS`
- `2`：`FAIL`
- `3`：`BLOCKED`

## 冻结与变更

通过记录必须绑定 `suite_id` 和 `release_digest`。已引用的测试集、人工基线或阈值不得原地修改；变化必须创建新版本并重跑。当前人工基线仍是占位状态，因此样例中的 `VALIDATED` 仅用于验证判定器，不能冒充 F04 已获得真实人工复核。
