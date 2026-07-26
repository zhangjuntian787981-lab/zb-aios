import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import pg from "pg";

const { Pool } = pg;
const migrationUrls = [
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
].map((path) => new URL(path, import.meta.url));
const migrations = await Promise.all(
  migrationUrls.map((url) => readFile(url, "utf8")),
);

const CONTROL_ROLE = "aios_c06_control_runtime";
const DECISION_ROLE = "aios_c06_decision_runtime";
const OUTBOX_ROLE = "aios_c06_outbox_worker";
const C06_ROLES = [CONTROL_ROLE, DECISION_ROLE, OUTBOX_ROLE];
const UPSTREAM_ROLES = [
  "aios_c04_core_runtime",
  "aios_c04_outbox_worker",
  "aios_c04_scim_checkpoint_runtime",
  "aios_c05_core_runtime",
  "aios_c05_outbox_worker",
];
const LOGIN_ROLES = {
  [CONTROL_ROLE]: "c06_roles_test_control_login",
  [DECISION_ROLE]: "c06_roles_test_decision_login",
  [OUTBOX_ROLE]: "c06_roles_test_outbox_login",
};

const TENANT_ID = "stn_01984910-0000-7000-8000-000000000001";
const RELEASE_ONE = "azr_01984910-0000-7000-8000-000000000002";
const RELEASE_TWO = "azr_01984910-0000-7000-8000-000000000003";
const ACTIVATION_ONE = "aza_01984910-0000-7000-8000-000000000004";
const DECISION_ID = "azd_01984910-0000-7000-8000-000000000005";
const DECISION_EVENT_ID =
  "evt_01984910-0000-7000-8000-000000000006";
const CONTROL_EVENT_ID =
  "evt_01984910-0000-7000-8000-000000000007";
const HUMAN_ID = "prn_01984910-0000-7000-8000-000000000008";
const ACTOR_ID = "prn_01984910-0000-7000-8000-000000000009";
const DELEGATION_ID =
  "dlg_01984910-0000-7000-8000-00000000000a";
const STORE_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAV";
const MODEL_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAW";
const STORE_TWO = "01ARZ3NDEKTSV4RRFFQ69G5FAX";
const MODEL_TWO = "01ARZ3NDEKTSV4RRFFQ69G5FAY";
const NOW = "2026-07-26T08:00:00.000Z";
const LATER = "2026-07-26T08:01:00.000Z";
const HASH_ONE = `sha256:${"1".repeat(64)}`;
const HASH_TWO = `sha256:${"2".repeat(64)}`;
const HASH_THREE = `sha256:${"3".repeat(64)}`;
const HASH_FOUR = `sha256:${"4".repeat(64)}`;
const PROJECTIONS = [
  "AUTHORIZATION",
  "IDENTITY",
  "KNOWLEDGE",
  "SECRET_REFS",
  "STORAGE",
];

function postgresConfig(user = process.env.C06_ROLES_TEST_PGUSER) {
  if (process.env.C06_ROLES_TEST_EPHEMERAL !== "1") {
    throw new Error("C06_ROLES_TEST_EPHEMERAL=1 is required.");
  }
  for (const name of [
    "C06_ROLES_TEST_PGHOST",
    "C06_ROLES_TEST_PGPORT",
    "C06_ROLES_TEST_PGDATABASE",
    "C06_ROLES_TEST_PGUSER",
  ]) {
    if (!process.env[name]) throw new Error(`${name} is required.`);
  }
  return {
    host: process.env.C06_ROLES_TEST_PGHOST,
    port: Number(process.env.C06_ROLES_TEST_PGPORT),
    database: process.env.C06_ROLES_TEST_PGDATABASE,
    user,
    max: 4,
  };
}

async function rejectsPermission(operation) {
  await assert.rejects(operation, (error) => error?.code === "42501");
}

async function asRole(pool, role, operation) {
  const client = await pool.connect();
  try {
    await client.query(`SET ROLE ${role}`);
    return await operation(client);
  } finally {
    try {
      await client.query("RESET ROLE");
    } finally {
      client.release();
    }
  }
}

function event({
  id,
  type,
  subject,
  correlationId,
  time,
  data = {},
}) {
  return {
    specversion: "1.0",
    id,
    source: "/product-core/authorization",
    type,
    subject,
    time,
    datacontenttype: "application/json",
    tenantkind: "SYNTHETIC",
    correlationid: correlationId,
    synthetic: true,
    data: {
      tenant_id: TENANT_ID,
      ...data,
    },
  };
}

function controlEvent() {
  return event({
    id: CONTROL_EVENT_ID,
    type: "product.authorization.policy-projection-recorded.v1",
    subject: RELEASE_TWO,
    correlationId: "c06-roles-control",
    time: NOW,
    data: {
      policy_release_id: RELEASE_TWO,
      projection_outcome: "READY",
      bundle_sha256: HASH_TWO,
    },
  });
}

function decisionEvent() {
  return event({
    id: DECISION_EVENT_ID,
    type: "product.authorization.decision-recorded.v1",
    subject: DECISION_ID,
    correlationId: "c06-roles-decision",
    time: LATER,
    data: {
      decision_id: DECISION_ID,
      policy_release_id: RELEASE_ONE,
      tuple_bundle_sha256: HASH_THREE,
      authorization_model_id: MODEL_ID,
      activation_version: 1,
      effect: "ALLOW",
      reason_code: "ALL_FACTORS_ALLOWED",
      input_sha256: HASH_THREE,
    },
  });
}

async function seedActiveTenant(adminPool) {
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
       'c06:roles:test',
       'fixture://c06/roles/tenant',
       $2,
       '[]'::jsonb,
       'sns_01984910-0000-7000-8000-00000000000b',
       'op_01984910-0000-7000-8000-00000000000c',
       $3,
       $3
     )`,
    [TENANT_ID, HASH_ONE, NOW],
  );
  for (const projection of PROJECTIONS) {
    await adminPool.query(
      `INSERT INTO aios_core.tenant_projection (
         tenant_id,
         generation,
         projection,
         desired_action,
         status,
         attempt_count,
         updated_at
       ) VALUES ($1, 1, $2, 'PROVISION', 'READY', 1, $3)`,
      [TENANT_ID, projection, NOW],
    );
  }
  await adminPool.query(
    `UPDATE aios_core.tenant_registry
        SET state = 'ACTIVE',
            lifecycle_version = 2,
            updated_at = $2
      WHERE tenant_id = $1`,
    [TENANT_ID, LATER],
  );
}

async function seedActivePolicy(adminPool) {
  await adminPool.query(
    `INSERT INTO aios_core.authorization_policy_release (
       policy_release_id,
       tenant_id,
       tenant_kind,
       tenant_lifecycle_version,
       fixture_id,
       template_ref,
       template_sequence,
       bundle_sha256,
       model_sha256,
       operation_catalog_version,
       fixture_version,
       state,
       created_at,
       updated_at
     ) VALUES (
       $1, $2, 'SYNTHETIC', 2,
       'synthetic-tenant-c06-roles',
       'fixture://c06/roles/release-1',
       1, $3, $4,
       'c06-protected-operations-v1',
       'c06-fixtures-v1',
       'STAGED', $5, $5
     )`,
    [RELEASE_ONE, TENANT_ID, HASH_ONE, HASH_TWO, NOW],
  );
  await adminPool.query(
    `UPDATE aios_core.authorization_policy_release
        SET state = 'READY',
            projection_operation_id = 'c06-roles-project-1',
            openfga_store_id = $2,
            authorization_model_id = $3,
            tuple_bundle_sha256 = $4,
            fixture_report_ref = 'evidence://c06/roles/projection-1',
            fixture_report_sha256 = $5,
            fixture_pass_count = 30,
            fixture_fail_count = 0,
            updated_at = $6
      WHERE policy_release_id = $1`,
    [
      RELEASE_ONE,
      STORE_ID,
      MODEL_ID,
      HASH_THREE,
      HASH_FOUR,
      LATER,
    ],
  );
  await adminPool.query(
    `INSERT INTO aios_core.authorization_activation (
       activation_id,
       tenant_id,
       tenant_kind,
       policy_release_id,
       previous_policy_release_id,
       template_sequence,
       activation_version,
       activation_kind,
       reason_ref,
       activated_at
     ) VALUES (
       $1, $2, 'SYNTHETIC', $3, NULL,
       1, 1, 'ACTIVATE',
       'fixture://c06/roles/activation-1',
       $4
     )`,
    [ACTIVATION_ONE, TENANT_ID, RELEASE_ONE, LATER],
  );
  await adminPool.query(
    `INSERT INTO aios_core.authorization_active_policy (
       tenant_id,
       tenant_kind,
       policy_release_id,
       activation_id,
       activation_version,
       updated_at
     ) VALUES ($1, 'SYNTHETIC', $2, $3, 1, $4)`,
    [TENANT_ID, RELEASE_ONE, ACTIVATION_ONE, LATER],
  );
}

async function insertEvidencePair(client, value) {
  const payload = JSON.stringify(value);
  await client.query(
    `INSERT INTO aios_core.authorization_event (
       event_id, tenant_id, tenant_kind, event, created_at
     ) VALUES ($1, $2, 'SYNTHETIC', $3::jsonb, $4)`,
    [value.id, TENANT_ID, payload, value.time],
  );
  await client.query(
    `INSERT INTO aios_core.authorization_outbox (
       event_id, tenant_id, tenant_kind, event, created_at
     ) VALUES ($1, $2, 'SYNTHETIC', $3::jsonb, $4)`,
    [value.id, TENANT_ID, payload, value.time],
  );
}

test("C06 PostgreSQL runtime roles enforce cross-module least privilege", async (t) => {
  const adminPool = new Pool(postgresConfig());
  const runtimePools = [];
  t.after(async () => {
    await Promise.all(runtimePools.map((pool) => pool.end()));
    await adminPool.end();
  });

  const safety = await adminPool.query(
    "SELECT current_database() AS database, to_regnamespace('aios_core') AS schema",
  );
  assert.match(safety.rows[0].database, /^c06_roles_test_[0-9]+$/);
  assert.equal(safety.rows[0].schema, null);
  for (const migration of migrations) {
    await adminPool.query(migration);
  }
  const serverVersion = await adminPool.query("SHOW server_version_num");
  assert.equal(Number(serverVersion.rows[0].server_version_num), 170010);

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
    [C06_ROLES],
  );
  assert.equal(attributes.rowCount, 3);
  for (const role of attributes.rows) {
    assert.deepEqual(
      {
        canLogin: role.rolcanlogin,
        superuser: role.rolsuper,
        createDatabase: role.rolcreatedb,
        createRole: role.rolcreaterole,
        inherit: role.rolinherit,
        replication: role.rolreplication,
        bypassRls: role.rolbypassrls,
      },
      {
        canLogin: false,
        superuser: false,
        createDatabase: false,
        createRole: false,
        inherit: false,
        replication: false,
        bypassRls: false,
      },
    );
  }

  const ownerMembership = await adminPool.query(
    `SELECT granted.rolname
       FROM pg_auth_members AS membership
       JOIN pg_roles AS granted ON granted.oid = membership.roleid
       JOIN pg_roles AS member ON member.oid = membership.member
      WHERE member.rolname = current_user
        AND granted.rolname = ANY($1::text[])`,
    [C06_ROLES],
  );
  assert.equal(ownerMembership.rowCount, 0);

  const expectedPrivileges = {
    [CONTROL_ROLE]: {
      authorization_policy_release: ["SELECT", "INSERT", "UPDATE"],
      authorization_activation: ["SELECT", "INSERT"],
      authorization_active_policy: ["SELECT", "INSERT", "UPDATE"],
      authorization_decision: ["SELECT"],
      authorization_command_receipt: ["SELECT", "INSERT"],
      authorization_event: ["SELECT", "INSERT"],
      authorization_outbox: ["SELECT", "INSERT"],
    },
    [DECISION_ROLE]: {
      authorization_policy_release: ["SELECT"],
      authorization_activation: ["SELECT"],
      authorization_active_policy: ["SELECT"],
      authorization_decision: ["SELECT", "INSERT"],
      authorization_event: ["SELECT", "INSERT"],
      authorization_outbox: ["SELECT", "INSERT"],
    },
    [OUTBOX_ROLE]: {
      authorization_outbox: ["SELECT", "UPDATE"],
    },
  };
  const tableNames = (
    await adminPool.query(
      `SELECT tablename
         FROM pg_tables
        WHERE schemaname = 'aios_core'
        ORDER BY tablename`,
    )
  ).rows.map(({ tablename }) => tablename);
  const privilegeKinds = [
    "SELECT",
    "INSERT",
    "UPDATE",
    "DELETE",
    "TRUNCATE",
    "REFERENCES",
    "TRIGGER",
  ];
  for (const role of C06_ROLES) {
    const schemaPrivileges = await adminPool.query(
      `SELECT
         has_schema_privilege($1, 'aios_core', 'USAGE') AS usage,
         has_schema_privilege($1, 'aios_core', 'CREATE') AS create`,
      [role],
    );
    assert.equal(schemaPrivileges.rows[0].usage, true);
    assert.equal(schemaPrivileges.rows[0].create, false);
    for (const tableName of tableNames) {
      for (const privilege of privilegeKinds) {
        const result = await adminPool.query(
          `SELECT has_table_privilege(
             $1,
             format('%I.%I', 'aios_core', $2::text),
             $3::text
           ) AS allowed`,
          [role, tableName, privilege],
        );
        assert.equal(
          result.rows[0].allowed,
          expectedPrivileges[role][tableName]?.includes(privilege) ??
            false,
          `${role} ${privilege} on ${tableName}`,
        );
      }
    }
  }
  for (const role of UPSTREAM_ROLES) {
    for (const tableName of Object.keys(
      expectedPrivileges[CONTROL_ROLE],
    )) {
      const result = await adminPool.query(
        `SELECT has_table_privilege(
           $1,
           format('%I.%I', 'aios_core', $2::text),
           'SELECT,INSERT,UPDATE,DELETE'
         ) AS allowed`,
        [role, tableName],
      );
      assert.equal(result.rows[0].allowed, false, `${role} on ${tableName}`);
    }
  }

  await adminPool.query(
    `CREATE ROLE c06_roles_test_control_login LOGIN NOINHERIT;
     CREATE ROLE c06_roles_test_decision_login LOGIN NOINHERIT;
     CREATE ROLE c06_roles_test_outbox_login LOGIN NOINHERIT;
     CREATE ROLE c06_roles_test_unprivileged LOGIN NOINHERIT;
     GRANT ${CONTROL_ROLE} TO c06_roles_test_control_login;
     GRANT ${DECISION_ROLE} TO c06_roles_test_decision_login;
     GRANT ${OUTBOX_ROLE} TO c06_roles_test_outbox_login;`,
  );
  const pools = Object.fromEntries(
    Object.entries(LOGIN_ROLES).map(([role, login]) => {
      const runtimePool = new Pool(postgresConfig(login));
      runtimePools.push(runtimePool);
      return [role, runtimePool];
    }),
  );
  const unprivilegedPool = new Pool(
    postgresConfig("c06_roles_test_unprivileged"),
  );
  runtimePools.push(unprivilegedPool);

  const guardFunctions = await adminPool.query(
    `SELECT
       procedure.proname,
       procedure.prosecdef,
       procedure.proconfig,
       owner.rolname AS owner,
       has_function_privilege($1, procedure.oid, 'EXECUTE')
         AS control_execute,
       has_function_privilege($2, procedure.oid, 'EXECUTE')
         AS decision_execute,
       has_function_privilege($3, procedure.oid, 'EXECUTE')
         AS outbox_execute,
       has_function_privilege(
         'c06_roles_test_unprivileged',
         procedure.oid,
         'EXECUTE'
       ) AS untrusted_execute
       FROM pg_proc AS procedure
       JOIN pg_namespace AS namespace
         ON namespace.oid = procedure.pronamespace
       JOIN pg_roles AS owner
         ON owner.oid = procedure.proowner
      WHERE namespace.nspname = 'aios_core'
        AND procedure.proname = ANY($4::text[])
      ORDER BY procedure.proname`,
    [
      CONTROL_ROLE,
      DECISION_ROLE,
      OUTBOX_ROLE,
      [
        "enforce_authorization_activation_insert",
        "enforce_authorization_active_policy",
        "enforce_authorization_decision_insert",
        "enforce_authorization_release_insert",
        "enforce_authorization_release_update",
      ],
    ],
  );
  assert.equal(guardFunctions.rowCount, 5);
  for (const routine of guardFunctions.rows) {
    assert.equal(routine.prosecdef, true);
    assert.equal(
      routine.proconfig.includes("search_path=pg_catalog, aios_core"),
      true,
    );
    assert.equal(routine.owner, process.env.C06_ROLES_TEST_PGUSER);
    assert.equal(routine.control_execute, false);
    assert.equal(routine.decision_execute, false);
    assert.equal(routine.outbox_execute, false);
    assert.equal(routine.untrusted_execute, false);
  }

  await seedActiveTenant(adminPool);
  await seedActivePolicy(adminPool);

  await rejectsPermission(
    unprivilegedPool.query(
      "SELECT * FROM aios_core.authorization_policy_release",
    ),
  );
  await rejectsPermission(
    unprivilegedPool.query(
      "CREATE TABLE aios_core.untrusted_probe(id integer)",
    ),
  );

  await asRole(pools[CONTROL_ROLE], CONTROL_ROLE, async (client) => {
    await client.query(
      `INSERT INTO aios_core.authorization_policy_release (
         policy_release_id,
         tenant_id,
         tenant_kind,
         tenant_lifecycle_version,
         fixture_id,
         template_ref,
         template_sequence,
         bundle_sha256,
         model_sha256,
         operation_catalog_version,
         fixture_version,
         state,
         created_at,
         updated_at
       ) VALUES (
         $1, $2, 'SYNTHETIC', 2,
         'synthetic-tenant-c06-roles',
         'fixture://c06/roles/release-2',
         2, $3, $4,
         'c06-protected-operations-v1',
         'c06-fixtures-v1',
         'STAGED', $5, $5
       )`,
      [RELEASE_TWO, TENANT_ID, HASH_TWO, HASH_THREE, NOW],
    );
    await client.query(
      `INSERT INTO aios_core.authorization_command_receipt (
         tenant_id,
         tenant_kind,
         idempotency_key,
         command_hash,
         result,
         created_at
       ) VALUES (
         $1, 'SYNTHETIC',
         'c06-roles-control-command',
         $2,
         '{"accepted":true}',
         $3
       )`,
      [TENANT_ID, HASH_ONE, NOW],
    );
    await client.query(
      `UPDATE aios_core.authorization_policy_release
          SET state = 'READY',
              projection_operation_id = 'c06-roles-project-2',
              openfga_store_id = $2,
              authorization_model_id = $3,
              tuple_bundle_sha256 = $4,
              fixture_report_ref = 'evidence://c06/roles/projection-2',
              fixture_report_sha256 = $5,
              fixture_pass_count = 30,
              fixture_fail_count = 0,
              updated_at = $6
        WHERE policy_release_id = $1`,
      [
        RELEASE_TWO,
        STORE_TWO,
        MODEL_TWO,
        HASH_THREE,
        HASH_FOUR,
        LATER,
      ],
    );
    await client.query("BEGIN");
    try {
      await insertEvidencePair(client, controlEvent());
      await client.query("COMMIT");
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    }
    await rejectsPermission(
      client.query(
        "SELECT * FROM aios_core.tenant_registry WHERE tenant_id = $1",
        [TENANT_ID],
      ),
    );
    await rejectsPermission(
      client.query("SELECT * FROM aios_core.identity_account"),
    );
    await rejectsPermission(
      client.query("SELECT * FROM aios_core.principal_registry"),
    );
    await rejectsPermission(
      client.query(
        `INSERT INTO aios_core.authorization_decision (
           decision_id
         ) VALUES ($1)`,
        [DECISION_ID],
      ),
    );
    await rejectsPermission(
      client.query(
        `UPDATE aios_core.authorization_outbox
            SET status = 'PROCESSING'
          WHERE event_id = $1`,
        [CONTROL_EVENT_ID],
      ),
    );
  });

  await asRole(
    pools[DECISION_ROLE],
    DECISION_ROLE,
    async (client) => {
      const policy = await client.query(
        `SELECT
           release.policy_release_id,
           activation.activation_version,
           activation.activation_kind
           FROM aios_core.authorization_policy_release AS release
           JOIN aios_core.authorization_active_policy AS active
             ON active.policy_release_id = release.policy_release_id
           JOIN aios_core.authorization_activation AS activation
             ON activation.activation_id = active.activation_id
          WHERE release.policy_release_id = $1`,
        [RELEASE_ONE],
      );
      assert.deepEqual(policy.rows[0], {
        policy_release_id: RELEASE_ONE,
        activation_version: "1",
        activation_kind: "ACTIVATE",
      });
      await client.query("BEGIN");
      try {
        await client.query(
          `INSERT INTO aios_core.authorization_decision (
             decision_id,
             tenant_id,
             tenant_kind,
             correlation_id,
             surface,
             resource_type,
             resource_id,
             resource_authorization_version,
             human_principal_id,
             human_security_epoch,
             workload_actor_principal_id,
             workload_actor_security_epoch,
             leaf_delegation_id,
             delegation_chain_sha256,
             purpose_ref,
             policy_release_id,
             bundle_sha256,
             openfga_store_id,
             authorization_model_id,
             activation_version,
             consistency,
             effect,
             authorization_status,
             reason_code,
             input_sha256,
             check_tuples,
             check_results,
             check_result_sha256,
             evaluated_at,
             evidence_ref
           ) VALUES (
             $1, $2, 'SYNTHETIC',
             'c06-roles-decision',
             'READ',
             'protected_resource',
             'c06-roles-read',
             1, $3, 1, $4, 1, $5, $6,
             'fixture://c06/roles/purpose',
             $7, $8, $9, $10, 1,
             'HIGHER_CONSISTENCY',
             'ALLOW',
             'ALLOWED',
             'ALL_FACTORS_ALLOWED',
             $11,
             '{"human":{"allowed":true}}',
             '{"human":true,"actor":true,"purpose":true}',
             $12,
             $13,
             $14
           )`,
          [
            DECISION_ID,
            TENANT_ID,
            HUMAN_ID,
            ACTOR_ID,
            DELEGATION_ID,
            HASH_TWO,
            RELEASE_ONE,
            HASH_ONE,
            STORE_ID,
            MODEL_ID,
            HASH_THREE,
            HASH_FOUR,
            LATER,
            `evidence://c06/roles/decisions/${DECISION_ID}`,
          ],
        );
        await insertEvidencePair(client, decisionEvent());
        await client.query("COMMIT");
      } catch (error) {
        await client.query("ROLLBACK");
        throw error;
      }
      await rejectsPermission(
        client.query(
          `UPDATE aios_core.authorization_policy_release
              SET updated_at = updated_at
            WHERE policy_release_id = $1`,
          [RELEASE_ONE],
        ),
      );
      await rejectsPermission(
        client.query(
          "INSERT INTO aios_core.authorization_activation (activation_id) VALUES ($1)",
          [ACTIVATION_ONE],
        ),
      );
      await rejectsPermission(
        client.query(
          "SELECT * FROM aios_core.tenant_registry WHERE tenant_id = $1",
          [TENANT_ID],
        ),
      );
      await rejectsPermission(
        client.query("SELECT * FROM aios_core.principal_registry"),
      );
    },
  );

  await asRole(pools[CONTROL_ROLE], CONTROL_ROLE, async (client) => {
    const recorded = await client.query(
      `SELECT decision_id
         FROM aios_core.authorization_decision
        WHERE decision_id = $1`,
      [DECISION_ID],
    );
    assert.equal(recorded.rows[0].decision_id, DECISION_ID);
  });

  await asRole(pools[OUTBOX_ROLE], OUTBOX_ROLE, async (client) => {
    const claim = await client.query(
      `WITH candidates AS (
         SELECT event_id
           FROM aios_core.authorization_outbox
          WHERE status = 'PENDING'
            AND available_at <= statement_timestamp()
          ORDER BY created_at, event_id
          FOR UPDATE SKIP LOCKED
          LIMIT 1
       )
       UPDATE aios_core.authorization_outbox AS outbox
          SET status = 'PROCESSING',
              attempt_count = attempt_count + 1,
              lease_version = lease_version + 1,
              leased_by = 'c06-roles-outbox-worker',
              lease_until = statement_timestamp() + interval '30 seconds',
              last_error_code = NULL
         FROM candidates
        WHERE outbox.event_id = candidates.event_id
       RETURNING outbox.event_id, outbox.status, outbox.lease_version`,
    );
    assert.deepEqual(claim.rows[0], {
      event_id: CONTROL_EVENT_ID,
      status: "PROCESSING",
      lease_version: "1",
    });
    const completion = await client.query(
      `UPDATE aios_core.authorization_outbox
          SET status = 'PUBLISHED',
              leased_by = NULL,
              lease_until = NULL,
              last_error_code = NULL,
              published_at = statement_timestamp()
        WHERE event_id = $1
          AND status = 'PROCESSING'
          AND leased_by = 'c06-roles-outbox-worker'
          AND lease_version = 1
      RETURNING status`,
      [CONTROL_EVENT_ID],
    );
    assert.equal(completion.rows[0].status, "PUBLISHED");
    for (const forbiddenTable of [
      "authorization_policy_release",
      "authorization_activation",
      "authorization_active_policy",
      "authorization_decision",
      "authorization_command_receipt",
      "authorization_event",
      "tenant_registry",
      "identity_account",
      "principal_registry",
    ]) {
      await rejectsPermission(
        client.query(`SELECT * FROM aios_core.${forbiddenTable}`),
      );
    }
    await rejectsPermission(
      client.query(
        `INSERT INTO aios_core.authorization_outbox (
           event_id, tenant_id, tenant_kind, event, created_at
         ) VALUES (
           $1, $2, 'SYNTHETIC', '{}'::jsonb, $3
         )`,
        [CONTROL_EVENT_ID, TENANT_ID, NOW],
      ),
    );
    await rejectsPermission(
      client.query(
        "DELETE FROM aios_core.authorization_outbox WHERE event_id = $1",
        [CONTROL_EVENT_ID],
      ),
    );
  });

  for (const role of C06_ROLES) {
    await asRole(pools[role], role, async (client) => {
      await rejectsPermission(
        client.query(`CREATE TABLE aios_core.${role}_probe(id integer)`),
      );
    });
  }
});
