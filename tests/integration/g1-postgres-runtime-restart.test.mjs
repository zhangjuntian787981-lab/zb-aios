import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { promisify } from "node:util";
import pg from "pg";
import { g1DeploymentSha256 } from "./g1-persistent-matrix-helpers.mjs";

const { Pool } = pg;
const execFileAsync = promisify(execFile);
const EXPECTED_DEPLOYMENT_SHA256 =
  "sha256:0ad6c07cea92ea050232b34af2bf1362e7599ae5f694a5c6d23968e18c066162";
const migrationPaths = [
  "../../implementation/p1/c03/postgresql/0001_tenant_registry.sql",
  "../../implementation/p1/c04/postgresql/0002_identity_federation.sql",
  "../../implementation/p1/c04/postgresql/0003_identity_outbox_delivery.sql",
  "../../implementation/p1/c04/postgresql/0004_versioned_provider_configuration.sql",
  "../../implementation/p1/c04/postgresql/0005_scim_checkpoint.sql",
  "../../implementation/p1/c04/postgresql/0006_identity_runtime_roles.sql",
  "../../implementation/p1/c05/postgresql/0007_stable_principal.sql",
  "../../implementation/p1/c05/postgresql/0008_principal_runtime_roles.sql",
  "../../implementation/p1/c06/postgresql/0009_authorization.sql",
  "../../implementation/p1/c06/postgresql/0010_authorization_runtime_roles.sql",
  "../../implementation/p1/c07/postgresql/0011_tenant_data_isolation.sql",
  "../../implementation/p1/c07/postgresql/0012_tenant_data_runtime_roles.sql",
  "../../implementation/p1/c08/postgresql/0013_aios_state_core.sql",
  "../../implementation/p1/c08/postgresql/0014_aios_state_runtime_roles.sql",
  "../../implementation/p1/c09/postgresql/0015_personal_memory.sql",
  "../../implementation/p1/c09/postgresql/0016_personal_memory_runtime_roles.sql",
  "../../implementation/p1/c10/postgresql/0017_knowledge_catalog.sql",
  "../../implementation/p1/c10/postgresql/0018_knowledge_catalog_runtime_roles.sql",
  "../../implementation/p1/c13/postgresql/0019_skill_registry.sql",
  "../../implementation/p1/c13/postgresql/0020_skill_registry_runtime_roles.sql",
  "../../implementation/p1/c14/postgresql/0021_model_gateway.sql",
  "../../implementation/p1/c14/postgresql/0022_model_gateway_runtime_roles.sql",
  "../../implementation/p1/c18/postgresql/0023_audit_evidence.sql",
  "../../implementation/p1/c18/postgresql/0024_audit_evidence_runtime_roles.sql",
  "../../implementation/p1/c11/postgresql/0025_permission_aware_rag.sql",
  "../../implementation/p1/c11/postgresql/0026_permission_aware_rag_runtime_roles.sql",
  "../../implementation/p1/c15/postgresql/0027_human_decision.sql",
  "../../implementation/p1/c15/postgresql/0028_human_decision_runtime_roles.sql",
  "../../implementation/p1/c16/postgresql/0029_tool_gateway.sql",
  "../../implementation/p1/c16/postgresql/0030_tool_gateway_runtime_roles.sql",
  "../../implementation/p1/c12/postgresql/0031_agent_orchestrator_state.sql",
  "../../implementation/p1/c12/postgresql/0032_agent_orchestrator_runtime_roles.sql",
  "../../implementation/p1/c19/postgresql/0033_observability_usage.sql",
  "../../implementation/p1/c19/postgresql/0034_observability_runtime_roles.sql",
];
const migrations = await Promise.all(
  migrationPaths.map((path) =>
    readFile(new URL(path, import.meta.url), "utf8"),
  ),
);
const roleBindings = Object.freeze({
  g1_c04: "aios_c04_core_runtime",
  g1_c05: "aios_c05_core_runtime",
  g1_c06_control: "aios_c06_control_runtime",
  g1_c06_decision: "aios_c06_decision_runtime",
  g1_c06_outbox: "aios_c06_outbox_worker",
  g1_c07_data: "aios_c07_data_runtime",
  g1_c07_scope: "aios_c07_scope_runtime",
  g1_c07_lifecycle: "aios_c07_lifecycle_runtime",
  g1_c07_control: "aios_c07_owner",
  g1_c07_restore: "aios_c07_restore_runtime",
  g1_c08_runtime: "aios_c08_runtime",
  g1_c08_outbox: "aios_c08_outbox_worker",
  g1_c10_runtime: "aios_c10_runtime",
  g1_c10_reader: "aios_c10_reader",
  g1_c11_projector: "aios_c11_projector",
  g1_c11_query: "aios_c11_query",
  g1_c12_runtime: "aios_c12_runtime",
  g1_c14_runtime: "aios_c14_runtime",
  g1_c15_runtime: "aios_c15_runtime",
  g1_c15_effect: "aios_c15_effect_worker",
  g1_c15_audit: "aios_c15_audit_worker",
  g1_c15_recovery: "aios_c15_recovery_reader",
  g1_c16_runtime: "aios_c16_runtime",
  g1_c16_tool: "aios_c16_worker",
  g1_c16_audit: "aios_c16_audit_worker",
  g1_c16_recovery: "aios_c16_recovery_reader",
  g1_c18_writer: "aios_c18_writer",
  g1_c18_reader: "aios_c18_reader",
  g1_c18_outbox: "aios_c18_outbox_worker",
  g1_c18_recovery: "aios_c18_recovery_reader",
  g1_c18_restore: "aios_c18_recovery_writer",
  g1_c18_retention: "aios_c18_retention_worker",
  g1_c19_writer: "aios_c19_writer",
  g1_c19_reader: "aios_c19_reader",
});
const stableTables = Object.freeze([
  "aios_core.tenant_registry",
  "aios_core.identity_account",
  "aios_core.principal_registry",
  "aios_core.principal_delegation",
  "aios_data.tenant_data_lifecycle",
  "aios_state.aios_run",
  "aios_knowledge.knowledge_document",
  "aios_rag.document_projection",
  "aios_model.model_route",
  "aios_decision.synthetic_test_decision",
  "aios_tool.tool_call",
  "aios_orchestration.task_state",
  "aios_orchestration.command_receipt",
  "aios_audit.audit_event",
  "aios_observability.telemetry_signal",
  "aios_observability.quota_account",
  "aios_observability.quota_reservation",
  "aios_observability.usage_ledger",
]);

function config(user = process.env.G1_TEST_PGUSER, max = 40) {
  if (process.env.G1_TEST_EPHEMERAL !== "1") {
    throw new Error("G1_TEST_EPHEMERAL=1 is required.");
  }
  for (const name of [
    "G1_TEST_PGHOST",
    "G1_TEST_PGPORT",
    "G1_TEST_PGDATABASE",
    "G1_TEST_PGUSER",
    "G1_TEST_FILE_ROOT",
  ]) {
    if (!process.env[name]) throw new Error(`${name} is required.`);
  }
  return {
    host: process.env.G1_TEST_PGHOST,
    port: Number(process.env.G1_TEST_PGPORT),
    database: process.env.G1_TEST_PGDATABASE,
    user,
    max,
  };
}

async function createRuntimeRoles(adminPool) {
  await adminPool.query(`
    CREATE ROLE g1_c03 LOGIN
      NOSUPERUSER NOCREATEDB NOCREATEROLE INHERIT NOREPLICATION NOBYPASSRLS;
    GRANT USAGE ON SCHEMA aios_core TO g1_c03;
    GRANT SELECT,INSERT,UPDATE,DELETE ON TABLE
      aios_core.tenant_registry,
      aios_core.tenant_command_receipt,
      aios_core.tenant_projection,
      aios_core.tenant_lifecycle_event,
      aios_core.tenant_outbox
    TO g1_c03;
  `);
  for (const [login, role] of Object.entries(roleBindings)) {
    await adminPool.query(`
      CREATE ROLE ${login} LOGIN
        NOSUPERUSER NOCREATEDB NOCREATEROLE INHERIT
        NOREPLICATION NOBYPASSRLS;
      GRANT ${role} TO ${login};
    `);
  }
}

async function counts(adminPool) {
  const result = {};
  for (const tableName of stableTables) {
    const value = await adminPool.query(
      `SELECT count(*)::bigint AS count FROM ${tableName}`,
    );
    result[tableName] = Number(value.rows[0].count);
  }
  for (const tableName of [
    "aios_core.identity_login_transaction",
    "aios_core.identity_session",
    "aios_core.authorization_decision",
  ]) {
    const value = await adminPool.query(
      `SELECT count(*)::bigint AS count FROM ${tableName}`,
    );
    result[tableName] = Number(value.rows[0].count);
  }
  return result;
}

async function c19AttributionSnapshot(adminPool) {
  const [accounts, reservations, ledger] = await Promise.all([
    adminPool.query(
      `SELECT tenant_id,quota_scope,quota_subject_id,principal_id,
              quota_period,quota_limit_micros::text,
              quota_threshold_basis_points,reserved_micros::text,
              consumed_micros::text,denied_count::text
         FROM aios_observability.quota_account
        ORDER BY tenant_id,quota_scope,quota_subject_id,quota_period`,
    ),
    adminPool.query(
      `SELECT tenant_id,reservation_id,principal_id,task_ref,
              dimension_type,resource_ref,meter_type,unit,
              max_quantity::text,rate_version,unit_rate_micros::text,
              reserved_cost_micros::text,state,receipt_ref,meter_key,
              quantity::text,booked_cost_micros::text,
              supplier_cost_micros::text,variance_micros::text,
              source_module,source_evidence_ref,source_evidence_sha256,
              audit_evidence_ref,audit_evidence_sha256,settle_trace_id
         FROM aios_observability.quota_reservation
        WHERE state='SETTLED'
        ORDER BY tenant_id,dimension_type,reservation_id`,
    ),
    adminPool.query(
      `SELECT tenant_id,event_id,reservation_id,principal_id,task_ref,
              dimension_type,resource_ref,meter_type,unit,quantity::text,
              cost_micros::text,rate_version,receipt_ref,meter_key,
              supplier_cost_micros::text,variance_micros::text,trace_id
         FROM aios_observability.usage_ledger
        WHERE event_type='USAGE_SETTLED'
        ORDER BY tenant_id,dimension_type,event_id`,
    ),
  ]);
  return {
    accounts: accounts.rows,
    reservations: reservations.rows,
    ledger: ledger.rows,
  };
}

async function runWorker(mode, identityInstancePrefix) {
  const workerPath = new URL(
    "./g1-postgres-runtime-worker.mjs",
    import.meta.url,
  );
  const { stdout } = await execFileAsync(
    process.execPath,
    [workerPath.pathname],
    {
      env: {
        ...process.env,
        G1_RUNTIME_MODE: mode,
        G1_IDENTITY_INSTANCE_PREFIX: identityInstancePrefix,
      },
      maxBuffer: 10 * 1024 * 1024,
    },
  );
  return JSON.parse(stdout);
}

test("G1 persistent runtime deploys and replays across two Node processes", async (t) => {
  const adminPool = new Pool(config());
  t.after(() => adminPool.end());

  const safety = await adminPool.query(
    `SELECT current_database() AS database,
            to_regnamespace('aios_orchestration') AS orchestration_schema`,
  );
  assert.match(safety.rows[0].database, /^g1_runtime_test_[0-9]+$/);
  assert.equal(safety.rows[0].orchestration_schema, null);

  for (const migration of migrations) await adminPool.query(migration);
  await createRuntimeRoles(adminPool);

  const first = await runWorker("FIRST", "a100");
  const firstCounts = await counts(adminPool);
  const firstC19 = await c19AttributionSnapshot(adminPool);
  const replay = await runWorker("REPLAY", "b100");
  const replayCounts = await counts(adminPool);
  const replayC19 = await c19AttributionSnapshot(adminPool);

  assert.equal(first.deployment.tenants.length, 3);
  assert.equal(replay.deployment.tenants.length, 3);
  assert.deepEqual(
    first.deployment.tenants.map(({ tenantId }) => tenantId),
    replay.deployment.tenants.map(({ tenantId }) => tenantId),
  );
  assert.equal(
    g1DeploymentSha256(first.deployment),
    EXPECTED_DEPLOYMENT_SHA256,
  );
  assert.equal(
    g1DeploymentSha256(replay.deployment),
    EXPECTED_DEPLOYMENT_SHA256,
  );
  assert.equal(
    first.deployment.tenants.flatMap(({ users }) => users).length,
    9,
  );
  assert.equal(
    new Set(
      replay.deployment.tenants.flatMap(({ users }) =>
        users.map(({ sessionId }) => sessionId),
      ),
    ).size,
    9,
  );
  assert.notDeepEqual(
    first.deployment.tenants.flatMap(({ users }) =>
      users.map(({ sessionId }) => sessionId),
    ),
    replay.deployment.tenants.flatMap(({ users }) =>
      users.map(({ sessionId }) => sessionId),
    ),
  );
  assert.deepEqual(
    first.deployment.tenants.flatMap(({ users }) =>
      users.map(({ principalId }) => principalId),
    ),
    replay.deployment.tenants.flatMap(({ users }) =>
      users.map(({ principalId }) => principalId),
    ),
  );

  assert.equal(first.results.length, 3);
  assert.equal(replay.results.length, 3);
  assert.equal(first.modelProviderNewExecutionCount, 6);
  assert.equal(replay.modelProviderNewExecutionCount, 0);
  for (let index = 0; index < first.results.length; index += 1) {
    const initial = first.results[index].modules;
    const repeated = replay.results[index].modules;
    assert.equal(initial.C12.status, "COMPLETED");
    assert.equal(repeated.C12.replayed, true);
    assert.equal(repeated.C08.replayed, true);
    assert.equal(repeated.C18.replayed, true);
    assert.equal(repeated.C19.replayed, true);
    assert.equal(repeated.C16.adapterNewExecutionCount, 0);
    assert.equal(repeated.C16.networkRequestCount, 0);
    assert.equal(repeated.C16.externalEffectCount, 0);
    assert.equal(repeated.C15.effectExecuted, false);
    assert.equal(repeated.C15.externalEffectCount, 0);
    assert.equal(repeated.C12.toolExternalEffectCount, 0);
    assert.equal(repeated.C12.humanDecisionProductionReusable, false);
    for (const path of [
      ["C12", "taskId"],
      ["C12", "stateSha256"],
      ["C08", "runId"],
      ["C08", "reconstructionHash"],
      ["C18", "eventHash"],
      ["C19", "traceId"],
      ["C19", "bookedCostMicros"],
      ["C19", "supplierCostMicros"],
    ]) {
      assert.equal(initial[path[0]][path[1]], repeated[path[0]][path[1]]);
    }
  }

  for (const tableName of stableTables) {
    assert.equal(
      replayCounts[tableName],
      firstCounts[tableName],
      `${tableName} changed during replay`,
    );
  }
  assert.deepEqual(replayC19, firstC19);
  assert.equal(firstC19.accounts.length, 6);
  assert.equal(firstC19.reservations.length, 6);
  assert.equal(firstC19.ledger.length, 6);
  assert.equal(
    new Set(firstC19.reservations.map(({ meter_key }) => meter_key)).size,
    6,
  );
  assert.equal(
    new Set(firstC19.ledger.map(({ meter_key }) => meter_key)).size,
    6,
  );
  for (const result of first.results) {
    const tenantId = result.tenantId;
    const principalId = result.modules.C05.humanPrincipalId;
    const taskRef = result.modules.C19.taskRef;
    const reservations = firstC19.reservations.filter(
      (row) => row.tenant_id === tenantId,
    );
    const ledger = firstC19.ledger.filter(
      (row) => row.tenant_id === tenantId,
    );
    const accounts = firstC19.accounts.filter(
      (row) => row.tenant_id === tenantId,
    );
    assert.equal(reservations.length, 2);
    assert.equal(ledger.length, 2);
    assert.equal(accounts.length, 2);
    assert.deepEqual(
      reservations.map(({ dimension_type }) => dimension_type),
      ["MODEL", "TOOL"],
    );
    assert.deepEqual(
      reservations.map(({ resource_ref }) => resource_ref),
      [
        "model://g1/local-secure/v1",
        "tool://g1/c16/order-get/v1",
      ],
    );
    assert.deepEqual(
      reservations.map(({ meter_type, unit }) => ({
        meterType: meter_type,
        unit,
      })),
      [
        { meterType: "MODEL_TOKEN", unit: "TOKEN" },
        { meterType: "TOOL_CALL", unit: "CALL" },
      ],
    );
    assert.ok(
      reservations.every(
        (row) =>
          row.principal_id === principalId &&
          row.task_ref === taskRef &&
          row.settle_trace_id === result.modules.C19.traceId,
      ),
    );
    assert.ok(
      ledger.every(
        (row) =>
          row.principal_id === principalId &&
          row.task_ref === taskRef &&
          row.trace_id === result.modules.C19.traceId,
      ),
    );
    const bookedCostMicros = reservations.reduce(
      (total, row) => total + BigInt(row.booked_cost_micros),
      0n,
    );
    assert.equal(
      bookedCostMicros,
      BigInt(result.modules.C19.bookedCostMicros),
    );
    assert.ok(
      accounts.every(
        (row) =>
          row.reserved_micros === "0" &&
          BigInt(row.consumed_micros) === bookedCostMicros,
      ),
    );
    const principalAccount = accounts.find(
      ({ quota_scope }) => quota_scope === "PRINCIPAL",
    );
    assert.equal(principalAccount.principal_id, principalId);
    assert.equal(principalAccount.quota_subject_id, principalId);
  }
  assert.equal(
    replayCounts["aios_core.identity_login_transaction"],
    firstCounts["aios_core.identity_login_transaction"] + 9,
  );
  assert.equal(
    replayCounts["aios_core.identity_session"],
    firstCounts["aios_core.identity_session"] + 9,
  );
  assert.equal(firstCounts["aios_core.authorization_decision"], 114);
  assert.equal(
    replayCounts["aios_core.authorization_decision"],
    firstCounts["aios_core.authorization_decision"] + 114,
  );
});
