import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import test from "node:test";
import pg from "pg";
import {
  createPostgresAiosStateStore,
} from "../../lib/postgres-aios-state-store.mjs";

const { Pool } = pg;
const migrations = await Promise.all(
  [
    "../../implementation/p1/c03/postgresql/0001_tenant_registry.sql",
    "../../implementation/p1/c07/postgresql/0011_tenant_data_isolation.sql",
    "../../implementation/p1/c07/postgresql/0012_tenant_data_runtime_roles.sql",
    "../../implementation/p1/c08/postgresql/0013_aios_state_core.sql",
    "../../implementation/p1/c08/postgresql/0014_aios_state_runtime_roles.sql",
  ].map((path) => readFile(new URL(path, import.meta.url), "utf8")),
);

const RUNTIME_ROLE = "aios_c08_runtime";
const OUTBOX_ROLE = "aios_c08_outbox_worker";
const OWNER_ROLE = "aios_c08_owner";
const RUNTIME_LOGIN = "c08_roles_runtime_login";
const OUTBOX_LOGIN = "c08_roles_outbox_login";
const SCOPE_LOGIN = "c08_roles_scope_login";
const COMBINED_LOGIN = "c08_roles_combined_login";
const PUBLIC_LOGIN = "c08_roles_public_login";
const TENANT_ID = "stn_01984910-4000-7000-8000-000000000001";
const TABLES = [
  "aios_case",
  "aios_thread",
  "aios_artifact",
  "aios_run",
  "aios_tool_call",
  "domain_event",
  "outbox",
  "command_receipt",
];

function config(user = process.env.C08_ROLES_TEST_PGUSER) {
  if (process.env.C08_ROLES_TEST_EPHEMERAL !== "1") {
    throw new Error("C08_ROLES_TEST_EPHEMERAL=1 is required.");
  }
  for (const name of [
    "C08_ROLES_TEST_PGHOST",
    "C08_ROLES_TEST_PGPORT",
    "C08_ROLES_TEST_PGDATABASE",
    "C08_ROLES_TEST_PGUSER",
  ]) {
    if (!process.env[name]) throw new Error(`${name} is required.`);
  }
  return {
    host: process.env.C08_ROLES_TEST_PGHOST,
    port: Number(process.env.C08_ROLES_TEST_PGPORT),
    database: process.env.C08_ROLES_TEST_PGDATABASE,
    user,
    max: 4,
  };
}

function digest(value) {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

async function rejectsPermission(operation) {
  await assert.rejects(operation, (error) => error?.code === "42501");
}

async function seedTenant(adminPool) {
  const time = "2026-07-26T14:00:00.000Z";
  await adminPool.query(
    `INSERT INTO aios_core.tenant_registry (
       tenant_id, tenant_kind, state, lifecycle_version, generation,
       creation_key, origin_ref, origin_hash, config_refs,
       resource_namespace_id, operation_id, created_at, updated_at
     ) VALUES (
       $1,'SYNTHETIC','PROVISIONING',1,1,$2,$3,$4,'[]'::jsonb,
       $5,$6,$7,$7
     )`,
    [
      TENANT_ID,
      "c08-roles-creation",
      "fixture://c08/roles",
      digest("c08-roles-origin"),
      "sns_01984910-4000-7000-8000-000000000011",
      "op_01984910-4000-7000-8000-000000000021",
      time,
    ],
  );
  for (const projection of [
    "AUTHORIZATION",
    "IDENTITY",
    "KNOWLEDGE",
    "SECRET_REFS",
    "STORAGE",
  ]) {
    await adminPool.query(
      `INSERT INTO aios_core.tenant_projection (
         tenant_id,generation,projection,desired_action,status,
         attempt_count,source_event_id,updated_at
       ) VALUES ($1,1,$2,'PROVISION','READY',1,$3,$4)`,
      [TENANT_ID, projection, `c08-roles-${projection}`, time],
    );
  }
  await adminPool.query(
    `UPDATE aios_core.tenant_registry
        SET state='ACTIVE',lifecycle_version=2,updated_at=$2
      WHERE tenant_id=$1`,
    [TENANT_ID, "2026-07-26T14:01:00.000Z"],
  );
  await adminPool.query(
    `INSERT INTO aios_data.tenant_data_lifecycle (
       tenant_id,tenant_kind,lifecycle_version,generation,operation_id,
       state,last_event_id,updated_at
     ) VALUES (
       $1,'SYNTHETIC',2,1,$2,'ACTIVE',$3,$4
     )`,
    [
      TENANT_ID,
      "op_01984910-4000-7000-8000-000000000021",
      "c08-roles-active",
      "2026-07-26T14:01:00.000Z",
    ],
  );
}

test("C08 PostgreSQL roles enforce least privilege and FORCE RLS", async (t) => {
  const adminPool = new Pool(config());
  const pools = [];
  const pool = (user) => {
    const value = new Pool(config(user));
    pools.push(value);
    return value;
  };
  t.after(async () => {
    await Promise.all(pools.map((value) => value.end()));
    await adminPool.end();
  });

  const safety = await adminPool.query(
    `SELECT current_database() AS database,
            to_regnamespace('aios_state') AS state_schema`,
  );
  assert.match(safety.rows[0].database, /^c08_roles_test_[0-9]+$/);
  assert.equal(safety.rows[0].state_schema, null);
  for (const migration of migrations) await adminPool.query(migration);
  await seedTenant(adminPool);

  await adminPool.query(`CREATE ROLE ${RUNTIME_LOGIN} LOGIN`);
  await adminPool.query(`CREATE ROLE ${OUTBOX_LOGIN} LOGIN`);
  await adminPool.query(`CREATE ROLE ${SCOPE_LOGIN} LOGIN`);
  await adminPool.query(`CREATE ROLE ${COMBINED_LOGIN} LOGIN`);
  await adminPool.query(`CREATE ROLE ${PUBLIC_LOGIN} LOGIN`);
  await adminPool.query(
    `GRANT ${RUNTIME_ROLE} TO ${RUNTIME_LOGIN};
     GRANT ${OUTBOX_ROLE} TO ${OUTBOX_LOGIN};
     GRANT aios_c07_scope_runtime TO ${SCOPE_LOGIN};
     GRANT ${RUNTIME_ROLE},aios_c07_scope_runtime TO ${COMBINED_LOGIN};`,
  );

  const attributes = await adminPool.query(
    `SELECT rolname,rolsuper,rolcreatedb,rolcreaterole,rolcanlogin,
            rolinherit,rolreplication,rolbypassrls
       FROM pg_roles
      WHERE rolname=ANY($1::text[])
      ORDER BY rolname`,
    [[OWNER_ROLE, OUTBOX_ROLE, RUNTIME_ROLE]],
  );
  assert.equal(attributes.rows.length, 3);
  for (const row of attributes.rows) {
    assert.equal(row.rolsuper, false);
    assert.equal(row.rolcreatedb, false);
    assert.equal(row.rolcreaterole, false);
    assert.equal(row.rolcanlogin, false);
    assert.equal(row.rolinherit, false);
    assert.equal(row.rolreplication, false);
    assert.equal(row.rolbypassrls, false);
  }

  const rls = await adminPool.query(
    `SELECT relname,relrowsecurity,relforcerowsecurity
       FROM pg_class
       JOIN pg_namespace ON pg_namespace.oid=pg_class.relnamespace
      WHERE nspname='aios_state' AND relname=ANY($1::text[])
      ORDER BY relname`,
    [TABLES],
  );
  assert.equal(rls.rows.length, 8);
  assert.equal(
    rls.rows.every((row) => row.relrowsecurity && row.relforcerowsecurity),
    true,
  );

  const outboxPrivileges = await adminPool.query(
    `SELECT
       has_table_privilege($1,'aios_state.outbox','SELECT') AS runtime_select,
       has_table_privilege($1,'aios_state.outbox','INSERT') AS runtime_insert,
       has_table_privilege($1,'aios_state.outbox','UPDATE') AS runtime_update,
       has_table_privilege($1,'aios_state.aios_case','UPDATE') AS case_update,
       has_table_privilege($1,'aios_state.aios_thread','UPDATE') AS thread_update,
       has_table_privilege($1,'aios_state.aios_run','UPDATE') AS run_update,
       has_table_privilege($1,'aios_state.aios_tool_call','UPDATE') AS tool_update,
       has_table_privilege($2,'aios_state.outbox','SELECT') AS worker_select,
       has_table_privilege($2,'aios_state.outbox','INSERT') AS worker_insert,
       has_table_privilege($2,'aios_state.outbox','UPDATE') AS worker_update`,
    [RUNTIME_ROLE, OUTBOX_ROLE],
  );
  assert.deepEqual(outboxPrivileges.rows[0], {
    runtime_select: true,
    runtime_insert: true,
    runtime_update: false,
    case_update: false,
    thread_update: false,
    run_update: true,
    tool_update: true,
    worker_select: true,
    worker_insert: false,
    worker_update: true,
  });

  const runtimePool = pool(RUNTIME_LOGIN);
  const runtime = await runtimePool.connect();
  try {
    const hidden = await runtime.query(
      "SELECT count(*)::integer AS count FROM aios_state.aios_case",
    );
    assert.equal(hidden.rows[0].count, 0);
    await rejectsPermission(() =>
      runtime.query(
        `INSERT INTO aios_state.aios_case (
           tenant_id,tenant_kind,case_id,state,version,goal_ref,
           created_at,updated_at
         ) VALUES (
           $1,'SYNTHETIC','forged-case','OPEN',1,'synthetic://forged',
           statement_timestamp(),statement_timestamp()
         )`,
        [TENANT_ID],
      ),
    );
    await rejectsPermission(() =>
      runtime.query(
        `SELECT aios_data.issue_runtime_scope_signature(
           $1,'SYNTHETIC',2,'forged','forged','evidence://forged',
           'forged',pg_backend_pid(),pg_current_xact_id(),15,
           '00000000-0000-4000-8000-000000000000'::uuid
         )`,
        [TENANT_ID],
      ),
    );
    await rejectsPermission(() => runtime.query(`SET ROLE ${OWNER_ROLE}`));
  } finally {
    runtime.release();
  }

  const outboxPool = pool(OUTBOX_LOGIN);
  const outbox = await outboxPool.connect();
  try {
    await rejectsPermission(() =>
      outbox.query("SELECT * FROM aios_state.aios_case"),
    );
    await rejectsPermission(() =>
      outbox.query(
        `INSERT INTO aios_state.outbox (
           tenant_id,tenant_kind,event_id,idempotency_key,request_hash,
           effect_key,event,created_at
         ) VALUES (
           $1,'SYNTHETIC','forged','forged',$2,$3,'{}'::jsonb,now()
         )`,
        [TENANT_ID, digest("request"), digest("effect")],
      ),
    );
  } finally {
    outbox.release();
  }

  const publicPool = pool(PUBLIC_LOGIN);
  const publicClient = await publicPool.connect();
  try {
    await rejectsPermission(() =>
      publicClient.query("SELECT * FROM aios_state.aios_case"),
    );
  } finally {
    publicClient.release();
  }

  const combinedPool = pool(COMBINED_LOGIN);
  const combinedOutboxPool = pool(COMBINED_LOGIN);
  const scopePool = pool(SCOPE_LOGIN);
  const unsafe = createPostgresAiosStateStore({
    runtimePool: combinedPool,
    scopePool,
    outboxPool: combinedOutboxPool,
  });
  await assert.rejects(
    unsafe.readTenantSnapshot({
      trustSource: "C07_VERIFIED_TENANT_SCOPE",
      tenantId: TENANT_ID,
      tenantKind: "SYNTHETIC",
      lifecycleVersion: 2,
      correlationId: "c08-roles",
      decisionId: "c08-roles-decision",
      evidenceRef: "evidence://c08/roles",
      policyVersion: "c08-roles-v1",
    }),
    (error) => error?.code === "INVALID_CONFIGURATION",
  );
});
