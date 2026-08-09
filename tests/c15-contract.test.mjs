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
const [
  migration,
  roles,
  hardening,
  executionStart,
  restoreRoles,
  runner,
  postgresRunner,
] =
  await Promise.all([
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
      new URL(
        "../implementation/p1/c15/postgresql/0035_human_decision_effect_authorization_hardening.sql",
        import.meta.url,
      ),
      "utf8",
    ),
    readFile(
      new URL(
        "../implementation/p1/c15/postgresql/0036_human_decision_effect_execution_start.sql",
        import.meta.url,
      ),
      "utf8",
    ),
    readFile(
      new URL(
        "../implementation/p1/c15/postgresql/c15_restore_role_bootstrap.v1.sql",
        import.meta.url,
      ),
      "utf8",
    ),
    readFile(
      new URL("../scripts/run-c15-tests.sh", import.meta.url),
      "utf8",
    ),
    readFile(
      new URL("../scripts/run-c15-postgres-tests.sh", import.meta.url),
      "utf8",
    ),
  ]);
const [workflowSource, postgresStoreSource, effectWorkerSource] =
  await Promise.all([
  readFile(
    new URL("../lib/human-decision-workflow.mjs", import.meta.url),
    "utf8",
  ),
  readFile(
    new URL("../lib/postgres-human-decision-store.mjs", import.meta.url),
    "utf8",
  ),
  readFile(
    new URL("../lib/c15-outbox-worker.mjs", import.meta.url),
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
  for (const field of [
    "humanLifecycleVersion",
    "workloadActorLifecycleVersion",
  ]) {
    assert.ok(
      artifactSchema.$defs.identityBinding.required.includes(field),
    );
    assert.equal(
      artifactSchema.$defs.identityBinding.properties[field].minimum,
      1,
    );
  }
  assert.equal(fixtures.scope, "P1_SYNTHETIC_ONLY");
  assert.equal(fixtures.workflows.length, 3);
  assert.equal(new Set(fixtures.workflows.map((item) => item.tenantId)).size, 3);
  assert.equal(matrix.implementationStatus, "IMPLEMENTED");
  assert.equal(matrix.verificationStatus, "VERIFIED");
  assert.equal(matrix.productionVerificationStatus, "NOT_VERIFIED");
  assert.equal(matrix.enterpriseConnectors, "C0_DISABLED");
  assert.equal(matrix.assertions.length, 12);
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
  for (const constraint of [
    "c15_artifact_idempotency_key",
    "c15_decision_idempotency_key",
    "c15_withdrawal_idempotency_key",
    "c15_effect_idempotency_key",
  ]) {
    assert.match(
      migration,
      new RegExp(`CONSTRAINT ${constraint}\\s+UNIQUE`),
    );
    assert.match(postgresStoreSource, new RegExp(`"${constraint}"`));
  }
  assert.match(migration, /SET search_path = pg_catalog/);
  assert.match(
    hardening,
    /CREATE FUNCTION aios_decision\.assert_effect_execution_authorized\([\s\S]*?SECURITY DEFINER\s+SET search_path = pg_catalog/,
  );
  assert.match(
    hardening,
    /CREATE OR REPLACE FUNCTION aios_decision\.claim_effect_outbox/,
  );
  assert.match(
    hardening,
    /CREATE OR REPLACE FUNCTION aios_decision\.complete_effect/,
  );
  assert.match(hardening, /c15_effect_decision_active_guard/);
  assert.match(hardening, /decision_withdrawal/);
  assert.match(hardening, /expires_at > statement_timestamp\(\)/);
  assert.match(
    hardening,
    /GRANT EXECUTE ON FUNCTION aios_decision\.assert_effect_execution_authorized\([\s\S]*?TO aios_c15_effect_worker/,
  );
  assert.match(
    hardening,
    /REVOKE ALL ON FUNCTION aios_decision\.assert_effect_execution_authorized\([\s\S]*?FROM PUBLIC/,
  );
  assert.doesNotMatch(hardening, /CREATE (?:TABLE|ROLE)|ADD COLUMN/);
  assert.match(
    executionStart,
    /ALTER TABLE aios_decision\.effect_outbox[\s\S]*ADD COLUMN execution_started_at timestamptz/,
  );
  assert.match(
    executionStart,
    /CREATE FUNCTION aios_decision\.guard_effect_execution_start\(\)[\s\S]*SECURITY DEFINER\s+SET search_path = pg_catalog/,
  );
  assert.match(executionStart, /c15_decision_execution_started_guard/);
  assert.match(
    executionStart,
    /pg_advisory_xact_lock\([\s\S]*v_execution_started_at := clock_timestamp\(\)[\s\S]*SET execution_started_at = v_execution_started_at/,
  );
  assert.match(
    executionStart,
    /outbox\.execution_started_at IS NULL[\s\S]*decision\.expires_at <= statement_timestamp\(\)/,
  );
  const completedAfterStart = executionStart.slice(
    executionStart.indexOf(
      "CREATE OR REPLACE FUNCTION aios_decision.complete_effect(",
    ),
    executionStart.indexOf(
      "ALTER FUNCTION aios_decision.guard_effect_execution_start()",
    ),
  );
  assert.match(completedAfterStart, /current_execution_started_at IS NULL/);
  assert.doesNotMatch(
    completedAfterStart,
    /assert_effect_execution_authorized/,
  );
  assert.doesNotMatch(executionStart, /CREATE (?:TABLE|ROLE)/);
  assert.match(
    postgresStoreSource,
    /async function assertEffectExecutable\([\s\S]*?assert_effect_execution_authorized/,
  );
  assert.ok(
    effectWorkerSource.indexOf("store.assertEffectExecutable") <
      effectWorkerSource.indexOf("adapter.commit"),
  );
  assert.doesNotMatch(migration, /aios_audit\.metadata_only/);
  assert.match(
    roles,
    /GRANT USAGE ON SCHEMA aios_audit TO aios_c15_owner;/,
  );
  assert.match(roles, /REVOKE ALL ON SCHEMA aios_core FROM PUBLIC/);
  assert.match(migration, /OLD\.lease_until <= statement_timestamp\(\)/);
  for (const operation of [
    "claim_effect_outbox",
    "complete_effect",
    "fail_effect_outbox",
    "claim_audit_outbox",
    "publish_audit_outbox",
    "fail_audit_outbox",
  ]) {
    assert.match(migration, new RegExp(`FUNCTION aios_decision\\.${operation}`));
    assert.match(
      migration,
      new RegExp(
        `CREATE FUNCTION aios_decision\\.${operation}[\\s\\S]*?` +
          "SECURITY DEFINER\\s+SET search_path = pg_catalog",
      ),
    );
    assert.match(roles, new RegExp(`FUNCTION aios_decision\\.${operation}`));
  }
  assert.doesNotMatch(
    roles,
    /GRANT SELECT, UPDATE ON TABLE[\s\S]*aios_decision\.effect_outbox/,
  );
  assert.doesNotMatch(
    roles,
    /GRANT SELECT, UPDATE ON TABLE aios_decision\.audit_outbox/,
  );
  assert.match(migration, /c15_effect_terminal_before_publish/);
  assert.match(migration, /c15_effect_completion_guard/);
  assert.match(migration, /c18_event_id/);
  assert.match(migration, /c18_event_hash/);
  assert.match(restoreRoles, /aios_c07_scope_runtime/);
  assert.match(restoreRoles, /aios_c15_effect_worker/);
  for (const fragment of [
    "current_memberships",
    "session_memberships",
    "current_usages",
    "session_usages",
    "current_createdb",
    "current_createrole",
    "current_replication",
    "current_admin_option",
    "privileges_safe",
  ]) {
    assert.match(postgresStoreSource, new RegExp(fragment));
  }
  const emptyState = workflowSource.slice(
    workflowSource.indexOf("function emptyMemoryState()"),
    workflowSource.indexOf("function memoryBody("),
  );
  assert.equal(
    (emptyState.match(/\bauditIntents:/g) ?? []).length,
    1,
  );
});

test("C15 documentation and runner preserve the P1 boundary", () => {
  for (const statement of [
    "P1_SYNTHETIC_ONLY",
    "externalEffectCount = 0",
    "P3_REQUIRED",
    "NOT_VERIFIED",
    "0027_human_decision.sql",
    "0028_human_decision_runtime_roles.sql",
    "0035_human_decision_effect_authorization_hardening.sql",
    "0036_human_decision_effect_execution_start.sql",
  ]) {
    assert.match(readme, new RegExp(statement.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
  }
  assert.doesNotMatch(readme, /生产就绪|已接入 OA|已接入 U9|已接入 BI/);
  assert.match(runner, /tests\/c15-c18-audit-publisher\.test\.mjs/);
  assert.match(runner, /tests\/c15-human-decision-workflow\.test\.mjs/);
  assert.match(runner, /run-c15-postgres-tests\.sh/);
  assert.match(postgresRunner, /pg_dump/);
  assert.match(postgresRunner, /pg_restore/);
  assert.match(postgresRunner, /pg_control_system\(\)/);
  assert.match(
    postgresRunner,
    /c15_restore_role_bootstrap\.v1\.sql/,
  );
  assert.doesNotMatch(postgresRunner, /--no-owner/);
  assert.doesNotMatch(postgresRunner, /pg_dumpall/);
  assert.match(
    postgresRunner,
    /tests\/integration\/c15-postgres-restore\.test\.mjs/,
  );
});
