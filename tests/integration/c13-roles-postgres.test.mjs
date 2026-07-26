import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import test from "node:test";
import pg from "pg";
import {
  createPostgresSkillRegistryStore,
} from "../../lib/postgres-skill-registry-store.mjs";

const { Pool } = pg;
const migrations = await Promise.all(
  [
    "../../implementation/p1/c03/postgresql/0001_tenant_registry.sql",
    "../../implementation/p1/c07/postgresql/0011_tenant_data_isolation.sql",
    "../../implementation/p1/c07/postgresql/0012_tenant_data_runtime_roles.sql",
    "../../implementation/p1/c13/postgresql/0019_skill_registry.sql",
    "../../implementation/p1/c13/postgresql/0020_skill_registry_runtime_roles.sql",
  ].map((path) => readFile(new URL(path, import.meta.url), "utf8")),
);
const TENANT_ID = "stn_018f0000-0000-7000-8000-000000000010";
const RUNTIME_ROLE = "aios_c13_runtime";
const OWNER_ROLE = "aios_c13_owner";
const RUNTIME_LOGIN = "c13_roles_runtime_login";
const SCOPE_LOGIN = "c13_roles_scope_login";
const COMBINED_LOGIN = "c13_roles_combined_login";
const PUBLIC_LOGIN = "c13_roles_public_login";
const TABLES = [
  "skill_release",
  "skill_channel",
  "skill_event",
  "command_receipt",
];

function config(user = process.env.C13_ROLES_TEST_PGUSER) {
  if (process.env.C13_ROLES_TEST_EPHEMERAL !== "1") {
    throw new Error("C13_ROLES_TEST_EPHEMERAL=1 is required.");
  }
  return {
    host: process.env.C13_ROLES_TEST_PGHOST,
    port: Number(process.env.C13_ROLES_TEST_PGPORT),
    database: process.env.C13_ROLES_TEST_PGDATABASE,
    user,
    max: 4,
  };
}

function digest(value) {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

async function seedTenant(pool) {
  const time = "2026-07-26T17:00:00.000Z";
  await pool.query(
    `INSERT INTO aios_core.tenant_registry (
       tenant_id,tenant_kind,state,lifecycle_version,generation,
       creation_key,origin_ref,origin_hash,config_refs,
       resource_namespace_id,operation_id,created_at,updated_at
     ) VALUES (
       $1,'SYNTHETIC','PROVISIONING',1,1,'c13-roles-create',
       'fixture://c13/roles',$2,'[]'::jsonb,$3,$4,$5,$5
     )`,
    [
      TENANT_ID,
      digest("c13-roles"),
      "sns_018f0000-0000-7000-8000-000000000100",
      "op_018f0000-0000-7000-8000-000000000200",
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
    await pool.query(
      `INSERT INTO aios_core.tenant_projection (
         tenant_id,generation,projection,desired_action,status,
         attempt_count,source_event_id,updated_at
       ) VALUES ($1,1,$2,'PROVISION','READY',1,$3,$4)`,
      [TENANT_ID, projection, `c13-roles-${projection}`, time],
    );
  }
  await pool.query(
    `UPDATE aios_core.tenant_registry
        SET state='ACTIVE',lifecycle_version=2
      WHERE tenant_id=$1`,
    [TENANT_ID],
  );
  await pool.query(
    `INSERT INTO aios_data.tenant_data_lifecycle (
       tenant_id,tenant_kind,lifecycle_version,generation,operation_id,
       state,last_event_id,updated_at
     ) VALUES ($1,'SYNTHETIC',2,1,$2,'ACTIVE','c13-roles-active',$3)`,
    [
      TENANT_ID,
      "op_018f0000-0000-7000-8000-000000000200",
      time,
    ],
  );
}

async function rejectsPermission(operation) {
  await assert.rejects(operation, (error) => error?.code === "42501");
}

test("C13 PostgreSQL roles enforce least privilege, FORCE RLS and immutable evidence", async (t) => {
  const admin = new Pool(config());
  const pools = [];
  const pool = (user) => {
    const value = new Pool(config(user));
    pools.push(value);
    return value;
  };
  t.after(async () => {
    await Promise.all(pools.map((value) => value.end()));
    await admin.end();
  });
  const safety = await admin.query(
    `SELECT current_database() AS database,
            to_regnamespace('aios_skill') AS skill_schema`,
  );
  assert.match(safety.rows[0].database, /^c13_roles_test_[0-9]+$/);
  assert.equal(safety.rows[0].skill_schema, null);
  for (const migration of migrations) await admin.query(migration);
  await seedTenant(admin);
  await admin.query(`CREATE ROLE ${RUNTIME_LOGIN} LOGIN`);
  await admin.query(`CREATE ROLE ${SCOPE_LOGIN} LOGIN`);
  await admin.query(`CREATE ROLE ${COMBINED_LOGIN} LOGIN`);
  await admin.query(`CREATE ROLE ${PUBLIC_LOGIN} LOGIN`);
  await admin.query(
    `GRANT ${RUNTIME_ROLE} TO ${RUNTIME_LOGIN};
     GRANT aios_c07_scope_runtime TO ${SCOPE_LOGIN};
     GRANT ${RUNTIME_ROLE},aios_c07_scope_runtime TO ${COMBINED_LOGIN};`,
  );

  const attributes = await admin.query(
    `SELECT rolname,rolsuper,rolcreatedb,rolcreaterole,rolcanlogin,
            rolinherit,rolreplication,rolbypassrls
       FROM pg_roles
      WHERE rolname=ANY($1::text[])
      ORDER BY rolname`,
    [[OWNER_ROLE, RUNTIME_ROLE]],
  );
  assert.equal(attributes.rows.length, 2);
  for (const row of attributes.rows) {
    assert.equal(row.rolsuper, false);
    assert.equal(row.rolcreatedb, false);
    assert.equal(row.rolcreaterole, false);
    assert.equal(row.rolcanlogin, false);
    assert.equal(row.rolinherit, false);
    assert.equal(row.rolreplication, false);
    assert.equal(row.rolbypassrls, false);
  }

  const rls = await admin.query(
    `SELECT relname,relrowsecurity,relforcerowsecurity
       FROM pg_class
       JOIN pg_namespace ON pg_namespace.oid=pg_class.relnamespace
      WHERE nspname='aios_skill' AND relname=ANY($1::text[])
      ORDER BY relname`,
    [TABLES],
  );
  assert.equal(rls.rows.length, 4);
  assert.equal(
    rls.rows.every((row) => row.relrowsecurity && row.relforcerowsecurity),
    true,
  );

  const privileges = await admin.query(
    `SELECT
       has_table_privilege($1,'aios_skill.skill_release','SELECT') AS release_select,
       has_table_privilege($1,'aios_skill.skill_release','INSERT') AS release_insert,
       has_table_privilege($1,'aios_skill.skill_release','UPDATE') AS release_update,
       has_table_privilege($1,'aios_skill.skill_release','DELETE') AS release_delete,
       has_table_privilege($1,'aios_skill.skill_channel','UPDATE') AS channel_update,
       has_table_privilege($1,'aios_skill.skill_event','INSERT') AS event_insert,
       has_table_privilege($1,'aios_skill.skill_event','UPDATE') AS event_update,
       has_table_privilege($1,'aios_skill.command_receipt','INSERT') AS receipt_insert,
       has_table_privilege($1,'aios_skill.command_receipt','UPDATE') AS receipt_update`,
    [RUNTIME_ROLE],
  );
  assert.deepEqual(privileges.rows[0], {
    release_select: true,
    release_insert: true,
    release_update: true,
    release_delete: false,
    channel_update: true,
    event_insert: true,
    event_update: false,
    receipt_insert: true,
    receipt_update: false,
  });

  const runtime = pool(RUNTIME_LOGIN);
  assert.equal(
    (
      await runtime.query(
        "SELECT count(*)::integer AS count FROM aios_skill.skill_release",
      )
    ).rows[0].count,
    0,
  );
  await rejectsPermission(() =>
    runtime.query(
      `INSERT INTO aios_skill.skill_channel (
         tenant_id,tenant_kind,skill_id,channel,generation,updated_at
       ) VALUES (
         $1,'SYNTHETIC','skl_018f0000-0000-7000-8000-000000000001',
         'PILOT',1,statement_timestamp()
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

  const publicPool = pool(PUBLIC_LOGIN);
  await rejectsPermission(() =>
    publicPool.query("SELECT * FROM aios_skill.skill_release"),
  );

  const combinedPool = pool(COMBINED_LOGIN);
  const scopePool = pool(SCOPE_LOGIN);
  const unsafeStore = createPostgresSkillRegistryStore({
    runtimePool: combinedPool,
    scopePool,
  });
  await assert.rejects(
    unsafeStore.readTenantSnapshot(
      {
        trustSource: "C07_VERIFIED_TENANT_SCOPE",
        tenantId: TENANT_ID,
        tenantKind: "SYNTHETIC",
        lifecycleVersion: 2,
        correlationId: "c13-roles",
        decisionId: "c13-roles",
        evidenceRef: "evidence://c13/roles",
        policyVersion: "c13-roles-v1",
      },
    ),
    { code: "INVALID_CONFIGURATION" },
  );
});
