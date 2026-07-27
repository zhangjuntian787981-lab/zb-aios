INSERT INTO `governance_events` (
  `id`,
  `project_id`,
  `revision`,
  `event_type`,
  `payload`,
  `actor_id`,
  `idempotency_key`,
  `command_hash`,
  `created_at`
) VALUES (
  'plan-baseline-v5.1-386a5778',
  'generic-multi-enterprise-ai-platform-v5',
  64,
  'PLAN_BASELINE_APPROVED',
  '{"baseline_id":"v5.1","phase":"P2","document_path":"docs/plans/通用多企业AI员工平台_完备工程级方案_v5.1.md","document_hash":"sha256:386a5778defc045dedf7c6b79a20e23111dde53f81485f4767a9c0ddd59e7cc0","approved_by":"external_product_owner","approved_at":"2026-07-27T01:40:52.777Z","note":"外部产品所有者批准 v5.1 作为 P2 执行基线；本事件不改变 G1、G2 或任何工作包状态。"}',
  'external_product_owner',
  'approve-plan-baseline-v5.1-386a5778',
  'sha256:b7149e89170d52bf6649f1f0a6b0c8c0c023340dce700e37adb974b5ad49bd70',
  '2026-07-27T01:40:52.777Z'
);
