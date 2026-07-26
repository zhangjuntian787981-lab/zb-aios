import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const base = new URL("../implementation/p1/c15/", import.meta.url);
const [openapi, artifactSchema, decisionSchema, matrix, fixtures, readme] =
  await Promise.all([
    "human-decision.openapi.v1.json",
    "draft-artifact.v1.schema.json",
    "synthetic-test-decision.v1.schema.json",
    "human-decision-verification-matrix.v1.json",
    "synthetic-workflow-fixtures.v1.json",
    "README.md",
  ].map(async (name) => {
    const raw = await readFile(new URL(name, base), "utf8");
    return name.endsWith(".json") ? JSON.parse(raw) : raw;
  }));
const [migration, roles, runner] = await Promise.all([
  readFile(
    new URL(
      "../implementation/p1/c15/postgresql/0027_human_decision.sql",
      import.meta.url,
    ),
    "utf8",
  ),
  readFile(
    new URL(
      "../implementation/p1/c15/postgresql/0028_human_decision_runtime_roles.sql",
      import.meta.url,
    ),
    "utf8",
  ),
  readFile(
    new URL("../scripts/run-c15-tests.sh", import.meta.url),
    "utf8",
  ),
]);

test("C15 contracts are closed and Synthetic-only", () => {
  assert.equal(openapi.openapi, "3.1.0");
  assert.deepEqual(
    Object.values(openapi.paths).map(
      (path) => path.post.operationId,
    ),
    [
      "C15_PREPARE_DRAFT",
      "C15_APPROVE_SYNTHETIC_TEST_DECISION",
      "C15_WITHDRAW_SYNTHETIC_TEST_DECISION",
      "C15_EXECUTE_SYNTHETIC_PREVIEW",
    ],
  );
  assert.equal(
    artifactSchema.properties.tenantKind.const,
    "SYNTHETIC",
  );
  assert.equal(
    artifactSchema.$defs.candidate.properties.operationId.const,
    "SYNTHETIC_PREVIEW_EFFECT",
  );
  assert.equal(
    decisionSchema.properties.decisionType.const,
    "SYNTHETIC_TEST_DECISION",
  );
  assert.equal(
    decisionSchema.properties.productionReusable.const,
    false,
  );
  assert.equal(
    decisionSchema.properties.externalEffectCount.const,
    0,
  );
  assert.equal(fixtures.scope, "P1_SYNTHETIC_ONLY");
  assert.equal(fixtures.workflows.length, 3);
  assert.equal(new Set(fixtures.workflows.map((item) => item.tenantId)).size, 3);
  assert.equal(matrix.productionStatus, "NOT_VERIFIED");
  assert.equal(matrix.assertions.length, 10);
});

test("C15 SQL fixes migrations, FORCE RLS, roles and paired Outboxes", () => {
  for (const table of [
    "draft_artifact",
    "synthetic_test_decision",
    "decision_withdrawal",
    "workflow_effect",
    "effect_outbox",
    "audit_intent",
    "audit_outbox",
    "command_receipt",
  ]) {
    assert.match(migration, new RegExp(`CREATE TABLE aios_decision\\.${table}`));
    assert.match(
      migration,
      new RegExp(
        `ALTER TABLE aios_decision\\.${table}\\s+FORCE ROW LEVEL SECURITY`,
      ),
    );
  }
  for (const role of [
    "aios_c15_runtime",
    "aios_c15_effect_worker",
    "aios_c15_audit_worker",
    "aios_c15_recovery_reader",
    "aios_c15_owner",
  ]) {
    assert.match(roles, new RegExp(`CREATE ROLE ${role}`));
  }
  assert.match(migration, /c15_effect_outbox_pair/);
  assert.match(migration, /c15_audit_intent_outbox_pair/);
  assert.match(migration, /c15_command_receipt_pair_guard/);
  assert.match(migration, /aios_audit\.metadata_only/);
});

test("C15 documentation and runner preserve the P1 boundary", () => {
  for (const statement of [
    "P1_SYNTHETIC_ONLY",
    "externalEffectCount = 0",
    "P3_REQUIRED",
    "NOT_VERIFIED",
    "0027_human_decision.sql",
    "0028_human_decision_runtime_roles.sql",
  ]) {
    assert.match(readme, new RegExp(statement.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
  }
  assert.doesNotMatch(readme, /生产就绪|已接入 OA|已接入 U9|已接入 BI/);
  assert.match(runner, /tests\/c15-human-decision-workflow\.test\.mjs/);
  assert.match(runner, /run-c15-postgres-tests\.sh/);
});
