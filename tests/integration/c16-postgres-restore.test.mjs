import assert from "node:assert/strict";
import test from "node:test";
import pg from "pg";
import {
  createPostgresToolGatewayStore,
} from "../../lib/postgres-tool-gateway-store.mjs";

const { Pool } = pg;
const TENANT_IDS = [
  "stn_018f0000-0000-7000-8000-000000000010",
  "stn_018f0000-0000-7000-8000-000000000011",
  "stn_018f0000-0000-7000-8000-000000000012",
];
const RUNTIME_LOGIN = "c16_restore_runtime_login";
const TOOL_WORKER_LOGIN = "c16_restore_tool_worker_login";
const AUDIT_LOGIN = "c16_restore_audit_login";
const RECOVERY_LOGIN = "c16_restore_recovery_login";
const SCOPE_LOGIN = "c16_restore_scope_login";

function config(user = process.env.C16_RESTORE_PGUSER) {
  if (process.env.C16_RESTORE_EPHEMERAL !== "1") {
    throw new Error("C16_RESTORE_EPHEMERAL=1 is required.");
  }
  for (const name of [
    "C16_RESTORE_PGHOST",
    "C16_RESTORE_PGPORT",
    "C16_RESTORE_PGDATABASE",
    "C16_RESTORE_PGUSER",
  ]) {
    if (!process.env[name]) throw new Error(`${name} is required.`);
  }
  return {
    host: process.env.C16_RESTORE_PGHOST,
    port: Number(process.env.C16_RESTORE_PGPORT),
    database: process.env.C16_RESTORE_PGDATABASE,
    user,
    max: 10,
  };
}

function scope(tenantId, suffix) {
  return {
    trustSource: "C07_VERIFIED_TENANT_SCOPE",
    tenantId,
    tenantKind: "SYNTHETIC",
    lifecycleVersion: 2,
    correlationId: `c16-restore-${suffix}`,
    decisionId: `c16-restore-${suffix}`,
    evidenceRef: `evidence://c16/restore/${suffix}`,
    policyVersion: "c16-restore-v1",
  };
}

test("C16 restores into a distinct PostgreSQL system and resumes audit delivery", async (t) => {
  const sourceSystemIdentifier =
    process.env.C16_RESTORE_SOURCE_SYSTEM_IDENTIFIER;
  const targetSystemIdentifier =
    process.env.C16_RESTORE_TARGET_SYSTEM_IDENTIFIER;
  assert.match(sourceSystemIdentifier ?? "", /^\d+$/);
  assert.match(targetSystemIdentifier ?? "", /^\d+$/);
  assert.notEqual(sourceSystemIdentifier, targetSystemIdentifier);

  const admin = new Pool(config());
  const pools = {
    runtime: new Pool(config(RUNTIME_LOGIN)),
    toolWorker: new Pool(config(TOOL_WORKER_LOGIN)),
    audit: new Pool(config(AUDIT_LOGIN)),
    recovery: new Pool(config(RECOVERY_LOGIN)),
    scope: new Pool(config(SCOPE_LOGIN)),
  };
  t.after(async () => {
    await Promise.all(Object.values(pools).map((pool) => pool.end()));
    await admin.end();
  });

  const restoredSystem = await admin.query(
    "SELECT system_identifier::text FROM pg_control_system()",
  );
  assert.equal(
    restoredSystem.rows[0].system_identifier,
    targetSystemIdentifier,
  );
  assert.notEqual(
    restoredSystem.rows[0].system_identifier,
    sourceSystemIdentifier,
  );

  const restoredTables = await admin.query(
    `SELECT c.relname,
            pg_get_userbyid(c.relowner) AS owner,
            c.relrowsecurity,
            c.relforcerowsecurity
       FROM pg_class AS c
       JOIN pg_namespace AS n ON n.oid=c.relnamespace
      WHERE n.nspname='aios_tool' AND c.relkind='r'
      ORDER BY c.relname`,
  );
  assert.deepEqual(
    restoredTables.rows.map((row) => row.relname),
    [
      "audit_intent",
      "audit_outbox",
      "tool_call",
      "tool_confirmation",
    ],
  );
  for (const row of restoredTables.rows) {
    assert.equal(row.owner, "aios_c16_owner");
    assert.equal(row.relrowsecurity, true);
    assert.equal(row.relforcerowsecurity, true);
  }

  await admin.query(
    `CREATE ROLE ${RUNTIME_LOGIN} LOGIN;
     CREATE ROLE ${TOOL_WORKER_LOGIN} LOGIN;
     CREATE ROLE ${AUDIT_LOGIN} LOGIN;
     CREATE ROLE ${RECOVERY_LOGIN} LOGIN;
     CREATE ROLE ${SCOPE_LOGIN} LOGIN;
     GRANT aios_c16_runtime TO ${RUNTIME_LOGIN};
     GRANT aios_c16_worker TO ${TOOL_WORKER_LOGIN};
     GRANT aios_c16_audit_worker TO ${AUDIT_LOGIN};
     GRANT aios_c16_recovery_reader TO ${RECOVERY_LOGIN};
     GRANT aios_c07_scope_runtime TO ${SCOPE_LOGIN};`,
  );

  const store = createPostgresToolGatewayStore({
    runtimePool: pools.runtime,
    toolWorkerPool: pools.toolWorker,
    auditWorkerPool: pools.audit,
    recoveryPool: pools.recovery,
    scopePool: pools.scope,
  });
  const snapshots = [];
  for (const [index, tenantId] of TENANT_IDS.entries()) {
    const snapshot = await store.readRecoverySnapshot(
      scope(tenantId, `snapshot-${index}`),
    );
    assert.equal(snapshot.confirmations.length, 1);
    assert.equal(snapshot.calls.length, 1);
    assert.equal(snapshot.calls[0].status, "SUCCEEDED");
    assert.ok(snapshot.auditOutbox.length >= 2);
    const serialized = JSON.stringify(snapshot);
    assert.equal(serialized.includes("normalizedParams"), false);
    assert.equal(serialized.includes("cap_"), false);
    snapshots.push(snapshot);
  }

  const pendingIndex = snapshots.findIndex((snapshot) =>
    snapshot.auditOutbox.some((item) =>
      ["PENDING", "FAILED"].includes(item.status),
    ),
  );
  assert.notEqual(pendingIndex, -1);
  const tenantId = TENANT_IDS[pendingIndex];
  const claimed = await store.claimAudit(
    scope(tenantId, "claim"),
    {
      workerId: "c16-restored-audit-worker",
      limit: 1,
      leaseDurationSeconds: 30,
    },
  );
  assert.equal(claimed.length, 1);
  const published = await store.completeAudit(
    scope(tenantId, "complete"),
    {
      intentId: claimed[0].intentId,
      workerId: "c16-restored-audit-worker",
      leaseVersion: claimed[0].leaseVersion,
      ackIntentId: claimed[0].intentId,
    },
  );
  assert.equal(published.status, "PUBLISHED");

  const resumed = await store.readRecoverySnapshot(
    scope(tenantId, "resumed"),
  );
  assert.equal(
    resumed.auditOutbox.find(
      (item) => item.intentId === claimed[0].intentId,
    ).status,
    "PUBLISHED",
  );
  const cleared = await pools.audit.query(
    `SELECT current_setting('aios.tenant_id', true) AS tenant_id,
            current_setting('aios.scope_signature', true)
              AS scope_signature`,
  );
  assert.ok(
    Object.values(cleared.rows[0]).every(
      (value) => value === null || value === "",
    ),
  );
});
