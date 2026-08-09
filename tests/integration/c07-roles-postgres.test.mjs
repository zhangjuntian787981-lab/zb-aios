import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import pg from "pg";
import { createPostgresTenantDataAdapter } from "../../lib/postgres-tenant-data-adapter.mjs";

const { Pool } = pg;
const migrations = await Promise.all(
  [
    "../../implementation/p1/c03/postgresql/0001_tenant_registry.sql",
    "../../implementation/p1/c07/postgresql/0011_tenant_data_isolation.sql",
    "../../implementation/p1/c07/postgresql/0012_tenant_data_runtime_roles.sql",
    "../../implementation/p1/c07/postgresql/0013_tenant_data_lifecycle_projection_hardening.sql",
  ].map((path) => readFile(new URL(path, import.meta.url), "utf8")),
);

const DATA_ROLE = "aios_c07_data_runtime";
const LIFECYCLE_ROLE = "aios_c07_lifecycle_runtime";
const OWNER_ROLE = "aios_c07_owner";
const RESTORE_ROLE = "aios_c07_restore_runtime";
const SCOPE_ROLE = "aios_c07_scope_runtime";
const COMBINED_LOGIN = "c07_roles_combined_login";
const DATA_LOGIN = "c07_roles_data_login";
const LIFECYCLE_LOGIN = "c07_roles_lifecycle_login";
const RESTORE_LOGIN = "c07_roles_restore_login";
const SCOPE_LOGIN = "c07_roles_scope_login";
const TENANT_A = "stn_01984910-2000-7000-8000-000000000001";
const TENANT_B = "stn_01984910-2000-7000-8000-000000000002";
const DATA_TABLES = [
  "tenant_sql_record",
  "tenant_vector_record",
  "tenant_search_record",
  "tenant_cache_record",
];
const TENANT_TABLES = [
  "tenant_data_lifecycle",
  "tenant_data_event_receipt",
  ...DATA_TABLES,
];
const PRIVATE_TABLES = [
  ...TENANT_TABLES,
  "runtime_scope_signing_secret",
];

function config(user = process.env.C07_ROLES_TEST_PGUSER) {
  if (process.env.C07_ROLES_TEST_EPHEMERAL !== "1") {
    throw new Error("C07_ROLES_TEST_EPHEMERAL=1 is required.");
  }
  for (const name of [
    "C07_ROLES_TEST_PGHOST",
    "C07_ROLES_TEST_PGPORT",
    "C07_ROLES_TEST_PGDATABASE",
    "C07_ROLES_TEST_PGUSER",
  ]) {
    if (!process.env[name]) throw new Error(`${name} is required.`);
  }
  return {
    host: process.env.C07_ROLES_TEST_PGHOST,
    port: Number(process.env.C07_ROLES_TEST_PGPORT),
    database: process.env.C07_ROLES_TEST_PGDATABASE,
    user,
    max: 2,
  };
}

async function rejectsPermission(operation) {
  await assert.rejects(operation, (error) => error?.code === "42501");
}

async function seedTenant(adminPool, tenantId, suffix) {
  await adminPool.query(
    `INSERT INTO aios_core.tenant_registry (
       tenant_id,
       tenant_kind,
       state,
       lifecycle_version,
       generation,
       creation_key,
       origin_ref,
       origin_hash,
       config_refs,
       resource_namespace_id,
       operation_id,
       created_at,
       updated_at
     ) VALUES (
       $1, 'SYNTHETIC', 'PROVISIONING', 1, 1,
       $2, $3, $4, '[]'::jsonb, $5, $6,
       '2026-07-26T11:00:00.000Z',
       '2026-07-26T11:00:00.000Z'
     )`,
    [
      tenantId,
      `c07-roles-${suffix}`,
      `fixture://c07/roles/${suffix}`,
      `sha256:${suffix.repeat(64)}`,
      `sns_01984910-2000-7000-8000-00000000001${suffix}`,
      `op_01984910-2000-7000-8000-00000000002${suffix}`,
    ],
  );
  await adminPool.query(
    `INSERT INTO aios_data.tenant_data_lifecycle (
       tenant_id,
       tenant_kind,
       lifecycle_version,
       generation,
       operation_id,
       state,
       last_event_id,
       updated_at
     ) VALUES (
       $1, 'SYNTHETIC', 2, 1, $2, 'ACTIVE', $3,
       '2026-07-26T11:01:00.000Z'
     )`,
    [
      tenantId,
      `op_01984910-2000-7000-8000-00000000002${suffix}`,
      `evt-c07-roles-active-${suffix}`,
    ],
  );
  await adminPool.query(
    `INSERT INTO aios_data.tenant_sql_record (
       tenant_id, tenant_kind, resource_id, value
     ) VALUES ($1, 'SYNTHETIC', $2, $3::jsonb)`,
    [tenantId, `record_${suffix}`, JSON.stringify({ owner: suffix })],
  );
}

async function setScope(client, tenantId, correlationId = "c07-roles") {
  await client.query(
    `SELECT set_config('aios.tenant_id', $1, true),
            set_config('aios.tenant_kind', 'SYNTHETIC', true),
            set_config('aios.lifecycle_version', '2', true),
            set_config('aios.correlation_id', $2, true)`,
    [tenantId, correlationId],
  );
}

async function rejectsForgedLifecycleRead(client, tenantId, statement) {
  await client.query("BEGIN");
  try {
    await setScope(client, tenantId);
    await rejectsPermission(client.query(statement, [tenantId]));
  } finally {
    await client.query("ROLLBACK");
  }
}

async function setForgedSignature(client) {
  await client.query(
    `SELECT set_config('aios.decision_id', 'forged-decision', true),
            set_config('aios.evidence_ref', 'evidence://forged', true),
            set_config('aios.policy_version', 'forged-policy', true),
            set_config('aios.backend_pid', pg_backend_pid()::text, true),
            set_config(
              'aios.transaction_id',
              pg_current_xact_id()::text,
              true
            ),
            set_config(
              'aios.expires_epoch_ms',
              (
                floor(extract(epoch FROM clock_timestamp()) * 1000)
                + 15000
              )::bigint::text,
              true
            ),
            set_config(
              'aios.scope_nonce',
              '00000000-0000-4000-8000-000000000000',
              true
            ),
            set_config('aios.scope_signature', $1, true)`,
    ["0".repeat(64)],
  );
}

async function setSignedEvidence(
  client,
  signed,
  {
    decisionId = "signed-decision",
    evidenceRef = "evidence://signed",
    policyVersion = "signed-policy",
  } = {},
) {
  await client.query(
    `SELECT set_config('aios.decision_id', $1, true),
            set_config('aios.evidence_ref', $2, true),
            set_config('aios.policy_version', $3, true),
            set_config('aios.backend_pid', $4, true),
            set_config('aios.transaction_id', $5, true),
            set_config('aios.expires_epoch_ms', $6, true),
            set_config('aios.scope_nonce', $7, true),
            set_config('aios.scope_signature', $8, true)`,
    [
      decisionId,
      evidenceRef,
      policyVersion,
      String(signed.backendPid),
      signed.transactionId,
      String(signed.expiresEpochMs),
      signed.nonce,
      signed.signature,
    ],
  );
}

test("C07 PostgreSQL runtime roles enforce RLS and least privilege", async (t) => {
  const adminPool = new Pool(config());
  const runtimePools = [];
  t.after(async () => {
    await Promise.all(runtimePools.map((pool) => pool.end()));
    await adminPool.end();
  });

  const safety = await adminPool.query(
    "SELECT current_database() AS database, to_regnamespace('aios_data') AS schema",
  );
  assert.match(safety.rows[0].database, /^c07_roles_test_[0-9]+$/);
  assert.equal(safety.rows[0].schema, null);
  for (const migration of migrations) await adminPool.query(migration);

  const versions = await adminPool.query(
    `SELECT current_setting('server_version_num')::integer AS server_version,
            extname,
            extversion
       FROM pg_extension
      WHERE extname = ANY(ARRAY['pgcrypto', 'vector'])
      ORDER BY extname`,
  );
  assert.deepEqual(versions.rows, [
    { server_version: 170010, extname: "pgcrypto", extversion: "1.3" },
    { server_version: 170010, extname: "vector", extversion: "0.8.5" },
  ]);

  const attributes = await adminPool.query(
    `SELECT
       rolname,
       rolcanlogin,
       rolsuper,
       rolcreatedb,
       rolcreaterole,
       rolinherit,
       rolreplication,
       rolbypassrls
       FROM pg_roles
      WHERE rolname = ANY($1::text[])
      ORDER BY rolname`,
    [[DATA_ROLE, LIFECYCLE_ROLE, OWNER_ROLE, RESTORE_ROLE, SCOPE_ROLE]],
  );
  assert.equal(attributes.rowCount, 5);
  for (const role of attributes.rows) {
    assert.deepEqual(
      {
        rolcanlogin: role.rolcanlogin,
        rolsuper: role.rolsuper,
        rolcreatedb: role.rolcreatedb,
        rolcreaterole: role.rolcreaterole,
        rolinherit: role.rolinherit,
        rolreplication: role.rolreplication,
        rolbypassrls: role.rolbypassrls,
      },
      {
        rolcanlogin: false,
        rolsuper: false,
        rolcreatedb: false,
        rolcreaterole: false,
        rolinherit: false,
        rolreplication: false,
        rolbypassrls: false,
      },
    );
  }

  const tableSecurity = await adminPool.query(
    `SELECT
       relation.relname,
       pg_get_userbyid(relation.relowner) AS owner,
       relation.relrowsecurity,
       relation.relforcerowsecurity
       FROM pg_class AS relation
       JOIN pg_namespace AS namespace
         ON namespace.oid = relation.relnamespace
      WHERE namespace.nspname = 'aios_data'
        AND relation.relname = ANY($1::text[])
      ORDER BY relation.relname`,
    [TENANT_TABLES],
  );
  assert.equal(tableSecurity.rowCount, 6);
  for (const relation of tableSecurity.rows) {
    assert.deepEqual(
      {
        owner: relation.owner,
        rls: relation.relrowsecurity,
        forceRls: relation.relforcerowsecurity,
      },
      { owner: OWNER_ROLE, rls: true, forceRls: true },
    );
  }

  const projectionFunction = await adminPool.query(
    `SELECT
       pg_get_userbyid(function.proowner) AS owner,
       function.prosecdef AS security_definer,
       function.proconfig AS configuration
       FROM pg_proc AS function
      WHERE function.oid =
        'aios_data.project_tenant_lifecycle_event(text)'::regprocedure`,
  );
  assert.deepEqual(projectionFunction.rows, [
    {
      owner: OWNER_ROLE,
      security_definer: true,
      configuration: ["search_path=pg_catalog"],
    },
  ]);

  const publicPrivileges = await adminPool.query(
    `SELECT
       (
         SELECT count(*)::integer
           FROM pg_namespace AS namespace,
                LATERAL aclexplode(
                  COALESCE(
                    namespace.nspacl,
                    acldefault('n', namespace.nspowner)
                  )
                ) AS privilege
          WHERE namespace.nspname = 'aios_data'
            AND privilege.grantee = 0
       ) AS schema_count,
       (
         SELECT count(*)::integer
           FROM pg_class AS relation
           JOIN pg_namespace AS namespace
             ON namespace.oid = relation.relnamespace,
                LATERAL aclexplode(
                  COALESCE(
                    relation.relacl,
                    acldefault('r', relation.relowner)
                  )
                ) AS privilege
          WHERE namespace.nspname = 'aios_data'
            AND relation.relname = ANY($1::text[])
            AND privilege.grantee = 0
       ) AS table_count`,
    [PRIVATE_TABLES],
  );
  assert.deepEqual(publicPrivileges.rows[0], {
    schema_count: 0,
    table_count: 0,
  });

  await adminPool.query(
    `CREATE ROLE ${DATA_LOGIN}
       LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
     CREATE ROLE ${LIFECYCLE_LOGIN}
       LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
     CREATE ROLE ${SCOPE_LOGIN}
       LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
     CREATE ROLE ${RESTORE_LOGIN}
       LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
     CREATE ROLE ${COMBINED_LOGIN}
       LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
     GRANT ${DATA_ROLE} TO ${DATA_LOGIN};
     GRANT ${LIFECYCLE_ROLE} TO ${LIFECYCLE_LOGIN};
     GRANT ${RESTORE_ROLE} TO ${RESTORE_LOGIN};
     GRANT ${SCOPE_ROLE} TO ${SCOPE_LOGIN};
     GRANT ${DATA_ROLE}, ${SCOPE_ROLE} TO ${COMBINED_LOGIN};
     ALTER ROLE ${RESTORE_LOGIN}
       SET default_transaction_read_only = on;`,
  );
  await seedTenant(adminPool, TENANT_A, "1");
  await seedTenant(adminPool, TENANT_B, "2");

  const dataPool = new Pool(config(DATA_LOGIN));
  const lifecyclePool = new Pool(config(LIFECYCLE_LOGIN));
  const restorePool = new Pool(config(RESTORE_LOGIN));
  const scopePool = new Pool(config(SCOPE_LOGIN));
  const maskedCombinedPool = new Pool({
    ...config(COMBINED_LOGIN),
    options: `-c role=${DATA_ROLE}`,
  });
  runtimePools.push(
    dataPool,
    lifecyclePool,
    restorePool,
    scopePool,
    maskedCombinedPool,
  );

  for (const tableName of TENANT_TABLES) {
    const privileges = await adminPool.query(
      `SELECT
         has_table_privilege($1, $2, 'SELECT') AS can_select,
         has_any_column_privilege($1, $2, 'SELECT') AS can_select_any_column,
         has_table_privilege($1, $2, 'INSERT') AS can_insert,
         has_table_privilege($1, $2, 'UPDATE') AS can_update,
         has_table_privilege($1, $2, 'DELETE') AS can_delete`,
      [LIFECYCLE_LOGIN, `aios_data.${tableName}`],
    );
    assert.deepEqual(privileges.rows[0], {
      can_select: false,
      can_select_any_column: false,
      can_insert: false,
      can_update: false,
      can_delete: false,
    });
  }
  const functionPrivileges = await adminPool.query(
    `SELECT
       has_function_privilege(
         $1,
         'aios_data.project_tenant_lifecycle_event(text)',
         'EXECUTE'
       ) AS lifecycle_execute,
       has_function_privilege(
         $2,
         'aios_data.project_tenant_lifecycle_event(text)',
         'EXECUTE'
       ) AS data_execute,
       has_function_privilege(
         $3,
         'aios_data.project_tenant_lifecycle_event(text)',
         'EXECUTE'
       ) AS scope_execute,
       has_function_privilege(
         $4,
         'aios_data.project_tenant_lifecycle_event(text)',
         'EXECUTE'
       ) AS restore_execute,
       has_function_privilege(
         $1,
         'aios_data.lifecycle_scope_matches(text,text)',
         'EXECUTE'
       ) AS legacy_scope_execute`,
    [LIFECYCLE_LOGIN, DATA_LOGIN, SCOPE_LOGIN, RESTORE_LOGIN],
  );
  assert.deepEqual(functionPrivileges.rows[0], {
    lifecycle_execute: true,
    data_execute: false,
    scope_execute: false,
    restore_execute: false,
    legacy_scope_execute: false,
  });
  await rejectsPermission(
    dataPool.query(
      "SELECT aios_data.project_tenant_lifecycle_event('forged-event')",
    ),
  );
  await rejectsPermission(
    scopePool.query(
      "SELECT aios_data.project_tenant_lifecycle_event('forged-event')",
    ),
  );
  await rejectsPermission(
    restorePool.query(
      "SELECT aios_data.project_tenant_lifecycle_event('forged-event')",
    ),
  );
  await assert.rejects(
    lifecyclePool.query(
      "SELECT aios_data.project_tenant_lifecycle_event('forged-event')",
    ),
    (error) => error?.code === "P0701",
  );
  await rejectsPermission(
    lifecyclePool.query(
      `SELECT aios_data.lifecycle_scope_matches($1, 'SYNTHETIC')`,
      [TENANT_B],
    ),
  );

  const noScope = await dataPool.query(
    "SELECT count(*)::integer AS count FROM aios_data.tenant_sql_record",
  );
  assert.equal(noScope.rows[0].count, 0);

  const adapterScope = {
    trustSource: "C07_VERIFIED_TENANT_SCOPE",
    tenantId: TENANT_A,
    tenantKind: "SYNTHETIC",
    lifecycleVersion: 2,
    correlationId: "c07-roles-adapter",
    decisionId: "azd-c07-roles-adapter",
    evidenceRef: "evidence://c07/roles/adapter",
    policyVersion: "c07-roles-policy-v1",
  };
  const readOperation = {
    kind: "SQL_GET",
    mode: "READ",
    resourceId: "record_1",
    input: { resourceId: "record_1" },
  };
  const maskedAdapter = createPostgresTenantDataAdapter({
    runtimePool: maskedCombinedPool,
    scopePool,
    lifecyclePool,
  });
  await assert.rejects(
    maskedAdapter.execute(adapterScope, readOperation),
    { code: "INVALID_CONFIGURATION" },
  );
  const retiredSnapshotAdapter = createPostgresTenantDataAdapter({
    runtimePool: dataPool,
    scopePool,
    lifecyclePool,
  });
  await assert.rejects(
    retiredSnapshotAdapter.snapshot({ tenantId: TENANT_B }),
    { code: "STORE_UNAVAILABLE" },
  );

  const readOnlyAdapter = createPostgresTenantDataAdapter({
    runtimePool: restorePool,
    scopePool,
    readOnly: true,
  });
  assert.equal(
    (await readOnlyAdapter.execute(adapterScope, readOperation)).value.owner,
    "1",
  );
  await assert.rejects(
    readOnlyAdapter.project({}),
    { code: "STORE_UNAVAILABLE" },
  );
  await assert.rejects(
    readOnlyAdapter.snapshot({ tenantId: TENANT_A }),
    { code: "STORE_UNAVAILABLE" },
  );

  const restoreClient = await restorePool.connect();
  try {
    await restoreClient.query("SET default_transaction_read_only = off");
    await rejectsPermission(
      restoreClient.query(
        `INSERT INTO aios_data.tenant_sql_record (
           tenant_id, tenant_kind, resource_id, value
         ) VALUES ($1, 'SYNTHETIC', 'restore_write', '{}'::jsonb)`,
        [TENANT_A],
      ),
    );
    await restoreClient.query("SET default_transaction_read_only = on");
  } finally {
    restoreClient.release();
  }

  const dataClient = await dataPool.connect();
  try {
    await dataClient.query("BEGIN");
    await setScope(dataClient, TENANT_A);
    await setForgedSignature(dataClient);
    const ownRows = await dataClient.query(
      "SELECT tenant_id, resource_id FROM aios_data.tenant_sql_record",
    );
    assert.deepEqual(ownRows.rows, []);
    await rejectsPermission(
      dataClient.query(
        `INSERT INTO aios_data.tenant_sql_record (
           tenant_id, tenant_kind, resource_id, value
         ) VALUES ($1, 'SYNTHETIC', 'foreign', '{}'::jsonb)`,
        [TENANT_B],
      ),
    );
    await dataClient.query("ROLLBACK");

    await dataClient.query("BEGIN");
    const transaction = await dataClient.query(
      `SELECT pg_backend_pid() AS backend_pid,
              pg_current_xact_id()::text AS transaction_id`,
    );
    const nonce = "11111111-1111-4111-8111-111111111111";
    const issued = await scopePool.query(
      `SELECT aios_data.issue_runtime_scope_signature(
         $1, 'SYNTHETIC', 2, 'c07-roles', 'signed-decision',
         'evidence://signed', 'signed-policy', $2, $3::xid8, 15, $4::uuid
       ) AS value`,
      [
        TENANT_A,
        transaction.rows[0].backend_pid,
        transaction.rows[0].transaction_id,
        nonce,
      ],
    );
    const signedScope = {
      backendPid: transaction.rows[0].backend_pid,
      transactionId: transaction.rows[0].transaction_id,
      expiresEpochMs: issued.rows[0].value.expires_epoch_ms,
      nonce,
      signature: issued.rows[0].value.signature,
    };
    await setScope(dataClient, TENANT_A);
    await setSignedEvidence(dataClient, signedScope);
    const signedRows = await dataClient.query(
      "SELECT resource_id FROM aios_data.tenant_sql_record",
    );
    assert.deepEqual(signedRows.rows, [{ resource_id: "record_1" }]);
    await dataClient.query("COMMIT");

    await dataClient.query("BEGIN");
    await setScope(dataClient, TENANT_A);
    await setSignedEvidence(dataClient, signedScope);
    const replayedRows = await dataClient.query(
      "SELECT resource_id FROM aios_data.tenant_sql_record",
    );
    assert.deepEqual(replayedRows.rows, []);
    await dataClient.query("ROLLBACK");

    await dataClient.query("BEGIN");
    const collisionTransaction = await dataClient.query(
      `SELECT pg_backend_pid() AS backend_pid,
              pg_current_xact_id()::text AS transaction_id`,
    );
    const collisionNonce = "22222222-2222-4222-8222-222222222222";
    const collisionIssued = await scopePool.query(
      `SELECT aios_data.issue_runtime_scope_signature(
         $1, 'SYNTHETIC', 2, $2, 'signed-decision',
         'evidence://signed', 'signed-policy', $3, $4::xid8, 15, $5::uuid
       ) AS value`,
      [
        TENANT_A,
        "c07\u001froles",
        collisionTransaction.rows[0].backend_pid,
        collisionTransaction.rows[0].transaction_id,
        collisionNonce,
      ],
    );
    await setScope(dataClient, TENANT_A, "c07");
    await setSignedEvidence(
      dataClient,
      {
        backendPid: collisionTransaction.rows[0].backend_pid,
        transactionId: collisionTransaction.rows[0].transaction_id,
        expiresEpochMs:
          collisionIssued.rows[0].value.expires_epoch_ms,
        nonce: collisionNonce,
        signature: collisionIssued.rows[0].value.signature,
      },
      { decisionId: "roles\u001fsigned-decision" },
    );
    const collisionRows = await dataClient.query(
      "SELECT resource_id FROM aios_data.tenant_sql_record",
    );
    assert.deepEqual(collisionRows.rows, []);
    await dataClient.query("ROLLBACK");
  } finally {
    dataClient.release();
  }

  await rejectsPermission(
    dataPool.query("SELECT * FROM aios_data.tenant_data_lifecycle"),
  );
  await rejectsPermission(
    dataPool.query("DELETE FROM aios_data.tenant_sql_record"),
  );
  await rejectsPermission(
    dataPool.query("TRUNCATE aios_data.tenant_sql_record"),
  );
  await rejectsPermission(
    dataPool.query(
      "ALTER TABLE aios_data.tenant_sql_record ADD COLUMN forbidden integer",
    ),
  );
  await rejectsPermission(dataPool.query(`SET ROLE ${OWNER_ROLE}`));
  await rejectsPermission(dataPool.query(`SET ROLE ${LIFECYCLE_ROLE}`));
  await rejectsPermission(
    dataPool.query(
      `SELECT aios_data.issue_runtime_scope_signature(
         $1, 'SYNTHETIC', 2, 'data-forbidden', 'decision',
         'evidence://forbidden', 'policy', pg_backend_pid(),
         pg_current_xact_id(), 15, gen_random_uuid()
       )`,
      [TENANT_A],
    ),
  );
  await rejectsPermission(
    scopePool.query(
      `SELECT aios_data.issue_runtime_scope_signature(
         $1, 'SYNTHETIC', 2, NULL, 'decision',
         'evidence://null', 'policy', pg_backend_pid(),
         pg_current_xact_id(), 15, gen_random_uuid()
       )`,
      [TENANT_A],
    ),
  );

  const signed = await scopePool.query(
    `SELECT aios_data.issue_runtime_scope_signature(
       $1, 'SYNTHETIC', 2, 'scope-allowed', 'decision',
       'evidence://allowed', 'policy', pg_backend_pid(),
       pg_current_xact_id(), 15, gen_random_uuid()
     ) AS value`,
    [TENANT_A],
  );
  assert.match(signed.rows[0].value.signature, /^[a-f0-9]{64}$/);
  await rejectsPermission(
    scopePool.query("SELECT * FROM aios_data.tenant_sql_record"),
  );
  await rejectsPermission(scopePool.query(`SET ROLE ${OWNER_ROLE}`));
  await rejectsPermission(scopePool.query(`SET ROLE ${DATA_ROLE}`));

  const lifecycleClient = await lifecyclePool.connect();
  try {
    await rejectsForgedLifecycleRead(
      lifecycleClient,
      TENANT_B,
      `SELECT tenant_id, state, operation_id
         FROM aios_data.tenant_data_lifecycle
        WHERE tenant_id = $1`,
    );
    await rejectsForgedLifecycleRead(
      lifecycleClient,
      TENANT_B,
      `SELECT event_id, event
         FROM aios_data.tenant_data_event_receipt
        WHERE tenant_id = $1`,
    );
    for (const tableName of DATA_TABLES) {
      await rejectsForgedLifecycleRead(
        lifecycleClient,
        TENANT_B,
        `SELECT tenant_id, tenant_kind
           FROM aios_data.${tableName}
          WHERE tenant_id = $1`,
      );
    }

    await lifecycleClient.query("BEGIN");
    await setScope(lifecycleClient, TENANT_B);
    await rejectsPermission(
      lifecycleClient.query(
        "DELETE FROM aios_data.tenant_sql_record WHERE tenant_id = $1",
        [TENANT_B],
      ),
    );
    await lifecycleClient.query("ROLLBACK");
  } finally {
    lifecycleClient.release();
  }
  await rejectsPermission(
    lifecyclePool.query(
      `INSERT INTO aios_data.tenant_sql_record (
         tenant_id, tenant_kind, resource_id, value
       ) VALUES ($1, 'SYNTHETIC', 'forbidden', '{}'::jsonb)`,
      [TENANT_A],
    ),
  );
  await rejectsPermission(
    lifecyclePool.query(
      "SELECT value FROM aios_data.tenant_sql_record",
    ),
  );
  await rejectsPermission(
    lifecyclePool.query(
      "UPDATE aios_data.tenant_data_event_receipt SET event_type = 'forbidden'",
    ),
  );
  await rejectsPermission(
    lifecyclePool.query(
      "DELETE FROM aios_data.tenant_data_event_receipt",
    ),
  );
  await rejectsPermission(lifecyclePool.query(`SET ROLE ${DATA_ROLE}`));

  const ownerClient = await adminPool.connect();
  try {
    await ownerClient.query("BEGIN");
    await ownerClient.query(`SET LOCAL ROLE ${OWNER_ROLE}`);
    const ownerRows = await ownerClient.query(
      "SELECT count(*)::integer AS count FROM aios_data.tenant_sql_record",
    );
    assert.equal(ownerRows.rows[0].count, 2);
    await ownerClient.query("ROLLBACK");
  } finally {
    ownerClient.release();
  }
});
