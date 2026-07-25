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
].map((path) => new URL(path, import.meta.url));

const migrations = await Promise.all(
  migrationUrls.map((url) => readFile(url, "utf8")),
);

const C05_CORE_ROLE = "aios_c05_core_runtime";
const C05_OUTBOX_ROLE = "aios_c05_outbox_worker";
const C05_ROLES = [C05_CORE_ROLE, C05_OUTBOX_ROLE];
const C04_ROLES = [
  "aios_c04_core_runtime",
  "aios_c04_outbox_worker",
  "aios_c04_scim_checkpoint_runtime",
];

const LOGIN_ROLES = {
  [C05_CORE_ROLE]: "c05_roles_test_core_login",
  [C05_OUTBOX_ROLE]: "c05_roles_test_outbox_login",
  aios_c04_core_runtime: "c05_roles_test_c04_login",
};

const TENANT_ID = "stn_01984720-0000-7000-8000-000000000001";
const PROVIDER_ID = "idp_01984720-0000-7000-8000-000000000002";
const ACCOUNT_ID = "sia_01984720-0000-7000-8000-000000000003";
const PRINCIPAL_ID = "prn_01984720-0000-7000-8000-000000000004";
const LINK_ID = "lnk_01984720-0000-7000-8000-000000000005";
const EVENT_ID = "c05-roles-event-1";
const NOW = "2026-07-26T08:00:00.000Z";
const LATER = "2026-07-26T08:01:00.000Z";
const HASH_ONE = `sha256:${"1".repeat(64)}`;
const HASH_TWO = `sha256:${"2".repeat(64)}`;

function postgresConfig(user = process.env.C05_ROLES_TEST_PGUSER) {
  if (process.env.C05_ROLES_TEST_EPHEMERAL !== "1") {
    throw new Error("C05_ROLES_TEST_EPHEMERAL=1 is required.");
  }
  for (const name of [
    "C05_ROLES_TEST_PGHOST",
    "C05_ROLES_TEST_PGPORT",
    "C05_ROLES_TEST_PGDATABASE",
    "C05_ROLES_TEST_PGUSER",
  ]) {
    if (!process.env[name]) throw new Error(`${name} is required.`);
  }
  return {
    host: process.env.C05_ROLES_TEST_PGHOST,
    port: Number(process.env.C05_ROLES_TEST_PGPORT),
    database: process.env.C05_ROLES_TEST_PGDATABASE,
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

function syntheticEvent() {
  return {
    specversion: "1.0",
    id: EVENT_ID,
    source: "/product-core/stable-principal",
    type: "product.principal.roles-test.v1",
    subject: PRINCIPAL_ID,
    time: NOW,
    datacontenttype: "application/json",
    dataschema:
      "https://contracts.example/c05/stable-principal-event.v1.json",
    tenantkind: "SYNTHETIC",
    correlationid: "c05-roles-test",
    synthetic: true,
    data: { tenant_id: TENANT_ID },
  };
}

async function seedC04(adminPool) {
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
       $1,
       'SYNTHETIC',
       'PROVISIONING',
       1,
       1,
       'c05:roles:test',
       'fixture://c05/roles-test',
       $2,
       '[]'::jsonb,
       'sns_01984720-0000-7000-8000-000000000006',
       'op_01984720-0000-7000-8000-000000000007',
       $3,
       $3
     )`,
    [TENANT_ID, HASH_ONE, NOW],
  );
  await adminPool.query(
    `INSERT INTO aios_core.identity_provider (
       provider_connection_id,
       tenant_id,
       tenant_kind,
       protocol,
       issuer,
       client_id,
       redirect_routes,
       configuration_version,
       allowed_algorithms,
       allowed_key_ids,
       required_authentication_methods,
       max_authentication_age_seconds,
       upstream_protocols,
       policy,
       status,
       created_at,
       updated_at
     ) VALUES (
       $1, $2, 'SYNTHETIC', 'OIDC',
       'https://idp.synthetic.example/realms/c05',
       'c05-roles-client',
       '{"PORTAL_HOME":"https://portal.synthetic.example/auth/callback"}',
       1, '["RS256"]', '["synthetic-k1"]', '["mfa"]',
       3600, '["OIDC"]', 'SCIM_REQUIRED', 'ACTIVE', $3, $3
     )`,
    [PROVIDER_ID, TENANT_ID, NOW],
  );
  await adminPool.query(
    `INSERT INTO aios_core.identity_provider_configuration (
       provider_connection_id,
       tenant_id,
       configuration_version,
       redirect_routes,
       allowed_algorithms,
       allowed_key_ids,
       required_authentication_methods,
       max_authentication_age_seconds,
       upstream_protocols,
       state,
       activated_at
     ) VALUES (
       $1, $2, 1,
       '{"PORTAL_HOME":"https://portal.synthetic.example/auth/callback"}',
       '["RS256"]', '["synthetic-k1"]', '["mfa"]',
       3600, '["OIDC"]', 'CURRENT', $3
     )`,
    [PROVIDER_ID, TENANT_ID, NOW],
  );
  await adminPool.query(
    `INSERT INTO aios_core.identity_account (
       account_id,
       tenant_id,
       tenant_kind,
       provider_connection_id,
       issuer,
       subject,
       directory_object_id,
       fixture_user_id,
       state,
       lifecycle_version,
       source_revision,
       source_payload_hash,
       revocation_epoch,
       incarnation,
       profile_ref,
       created_at,
       updated_at
     ) VALUES (
       $1, $2, 'SYNTHETIC', $3,
       'https://idp.synthetic.example/realms/c05',
       'c05-roles-subject',
       'c05-roles-directory-object',
       'c05-roles-fixture-user',
       'ACTIVE', 1, 1, $4, 1, 1,
       'fixture://c05/roles-test/users/one',
       $5, $5
     )`,
    [ACCOUNT_ID, TENANT_ID, PROVIDER_ID, HASH_ONE, NOW],
  );
  const client = await adminPool.connect();
  try {
    await client.query("BEGIN");
    await client.query("SET LOCAL session_replication_role = 'replica'");
    await client.query(
      `UPDATE aios_core.tenant_registry
          SET state = 'ACTIVE',
              lifecycle_version = 2,
              updated_at = $2
        WHERE tenant_id = $1`,
      [TENANT_ID, LATER],
    );
    await client.query("COMMIT");
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
}

test("C05 PostgreSQL runtime roles enforce cross-module least privilege", async (t) => {
  const adminPool = new Pool(postgresConfig());
  const runtimePools = [];
  t.after(async () => {
    await Promise.all(runtimePools.map((pool) => pool.end()));
    await adminPool.end();
  });

  const safety = await adminPool.query(
    "SELECT current_database() AS database, to_regnamespace('aios_core') AS schema",
  );
  assert.match(safety.rows[0].database, /^c05_roles_test_[0-9]+$/);
  assert.equal(safety.rows[0].schema, null);

  for (const migration of migrations) {
    await adminPool.query(migration);
  }

  const serverVersion = await adminPool.query("SHOW server_version_num");
  assert.equal(Number(serverVersion.rows[0].server_version_num), 170010);

  const roleAttributes = await adminPool.query(
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
    [C05_ROLES],
  );
  assert.equal(roleAttributes.rowCount, 2);
  for (const role of roleAttributes.rows) {
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
    [C05_ROLES],
  );
  assert.equal(ownerMembership.rowCount, 0);

  const tableNames = (
    await adminPool.query(
      `SELECT tablename
         FROM pg_tables
        WHERE schemaname = 'aios_core'
        ORDER BY tablename`,
    )
  ).rows.map(({ tablename }) => tablename);
  const expectedPrivileges = {
    [C05_CORE_ROLE]: {
      principal_registry: ["SELECT", "INSERT", "UPDATE"],
      principal_identity_link: ["SELECT", "INSERT", "UPDATE"],
      principal_delegation: ["SELECT", "INSERT", "UPDATE"],
      principal_command_receipt: ["SELECT", "INSERT"],
      principal_event: ["SELECT", "INSERT"],
      principal_outbox: ["SELECT", "INSERT"],
    },
    [C05_OUTBOX_ROLE]: {
      principal_outbox: ["SELECT", "UPDATE"],
    },
  };
  const privilegeKinds = [
    "SELECT",
    "INSERT",
    "UPDATE",
    "DELETE",
    "TRUNCATE",
    "REFERENCES",
    "TRIGGER",
  ];
  for (const role of C05_ROLES) {
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
          expectedPrivileges[role][tableName]?.includes(privilege) ?? false,
          `${role} ${privilege} on ${tableName}`,
        );
      }
    }
  }

  for (const role of C04_ROLES) {
    for (const tableName of Object.keys(expectedPrivileges[C05_CORE_ROLE])) {
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
    `CREATE ROLE c05_roles_test_core_login LOGIN NOINHERIT;
     CREATE ROLE c05_roles_test_outbox_login LOGIN NOINHERIT;
     CREATE ROLE c05_roles_test_c04_login LOGIN NOINHERIT;
     CREATE ROLE c05_roles_test_unprivileged LOGIN NOINHERIT;
     GRANT ${C05_CORE_ROLE} TO c05_roles_test_core_login;
     GRANT ${C05_OUTBOX_ROLE} TO c05_roles_test_outbox_login;
     GRANT aios_c04_core_runtime TO c05_roles_test_c04_login;`,
  );

  const pools = Object.fromEntries(
    Object.entries(LOGIN_ROLES).map(([role, login]) => {
      const pool = new Pool(postgresConfig(login));
      runtimePools.push(pool);
      return [role, pool];
    }),
  );
  const unprivilegedPool = new Pool(
    postgresConfig("c05_roles_test_unprivileged"),
  );
  runtimePools.push(unprivilegedPool);

  const triggerFunctions = await adminPool.query(
    `SELECT
       procedure.proname,
       procedure.prosecdef,
       procedure.proconfig,
       owner.rolname AS owner,
       has_function_privilege($1, procedure.oid, 'EXECUTE') AS core_execute,
       has_function_privilege($2, procedure.oid, 'EXECUTE') AS outbox_execute,
       has_function_privilege(
         'c05_roles_test_unprivileged',
         procedure.oid,
         'EXECUTE'
       ) AS untrusted_execute
       FROM pg_proc AS procedure
       JOIN pg_namespace AS namespace
         ON namespace.oid = procedure.pronamespace
       JOIN pg_roles AS owner
         ON owner.oid = procedure.proowner
      WHERE namespace.nspname = 'aios_core'
        AND procedure.proname = ANY($3::text[])
      ORDER BY procedure.proname`,
    [
      C05_CORE_ROLE,
      C05_OUTBOX_ROLE,
      [
        "enforce_principal_identity_link_insert",
        "enforce_principal_identity_link_update",
      ],
    ],
  );
  assert.equal(triggerFunctions.rowCount, 2);
  for (const routine of triggerFunctions.rows) {
    assert.equal(routine.prosecdef, true);
    assert.equal(
      routine.proconfig.includes("search_path=pg_catalog, aios_core"),
      true,
    );
    assert.equal(routine.owner, process.env.C05_ROLES_TEST_PGUSER);
    assert.equal(routine.core_execute, false);
    assert.equal(routine.outbox_execute, false);
    assert.equal(routine.untrusted_execute, false);
  }

  await seedC04(adminPool);

  await rejectsPermission(
    unprivilegedPool.query(
      "SELECT * FROM aios_core.principal_registry LIMIT 1",
    ),
  );
  await rejectsPermission(
    unprivilegedPool.query(
      "CREATE TABLE aios_core.untrusted_probe(id integer)",
    ),
  );

  await asRole(
    pools.aios_c04_core_runtime,
    "aios_c04_core_runtime",
    async (client) => {
      const account = await client.query(
        `SELECT account_id
           FROM aios_core.identity_account
          WHERE account_id = $1`,
        [ACCOUNT_ID],
      );
      assert.equal(account.rows[0].account_id, ACCOUNT_ID);
      await rejectsPermission(
        client.query("SELECT * FROM aios_core.principal_registry"),
      );
      await rejectsPermission(
        client.query(
          `INSERT INTO aios_core.principal_registry (
             principal_id,
             tenant_id,
             tenant_kind,
             principal_kind,
             creation_key,
             state,
             lifecycle_version,
             security_epoch,
             created_at,
             updated_at
           ) VALUES (
             $1, $2, 'SYNTHETIC', 'HUMAN', 'c04-forbidden',
             'ACTIVE', 1, 1, $3, $3
           )`,
          [PRINCIPAL_ID, TENANT_ID, NOW],
        ),
      );
      await rejectsPermission(client.query(`SET ROLE ${C05_CORE_ROLE}`));
    },
  );

  await asRole(pools[C05_CORE_ROLE], C05_CORE_ROLE, async (client) => {
    await client.query(
      `INSERT INTO aios_core.principal_registry (
         principal_id,
         tenant_id,
         tenant_kind,
         principal_kind,
         creation_key,
         state,
         lifecycle_version,
         security_epoch,
         created_at,
         updated_at
       ) VALUES (
         $1, $2, 'SYNTHETIC', 'HUMAN',
         'fixture://c05/roles-test/principals/human',
         'ACTIVE', 1, 1, $3, $3
       )`,
      [PRINCIPAL_ID, TENANT_ID, NOW],
    );
    await client.query(
      `INSERT INTO aios_core.principal_identity_link (
         identity_link_id,
         tenant_id,
         tenant_kind,
         identity_account_id,
         provider_connection_id,
         principal_id,
         principal_kind,
         link_evidence_ref,
         state,
         lifecycle_version,
         account_lifecycle_version,
         account_revocation_epoch,
         created_at,
         updated_at,
         retired_at
       ) VALUES (
         $1, $2, 'SYNTHETIC', $3, $4, $5, 'HUMAN',
         'synthetic://c05/roles-test/link',
         'ACTIVE', 1, 1, 1, $6, $6, NULL
       )`,
      [LINK_ID, TENANT_ID, ACCOUNT_ID, PROVIDER_ID, PRINCIPAL_ID, NOW],
    );
    const link = await client.query(
      `SELECT identity_link_id, state
         FROM aios_core.principal_identity_link
        WHERE identity_link_id = $1`,
      [LINK_ID],
    );
    assert.deepEqual(link.rows[0], {
      identity_link_id: LINK_ID,
      state: "ACTIVE",
    });

    await rejectsPermission(
      client.query(
        `SELECT account_id, state
           FROM aios_core.identity_account
          WHERE account_id = $1`,
        [ACCOUNT_ID],
      ),
    );
    await rejectsPermission(
      client.query(
        `SELECT tenant_id, state
           FROM aios_core.tenant_registry
          WHERE tenant_id = $1`,
        [TENANT_ID],
      ),
    );
    await rejectsPermission(
      client.query("SELECT * FROM aios_core.identity_provider"),
    );
    await rejectsPermission(
      client.query(
        "DELETE FROM aios_core.principal_registry WHERE principal_id = $1",
        [PRINCIPAL_ID],
      ),
    );

    const event = JSON.stringify(syntheticEvent());
    await client.query("BEGIN");
    try {
      await client.query(
        `INSERT INTO aios_core.principal_command_receipt (
           tenant_id,
           tenant_kind,
           idempotency_key,
           command_hash,
           result,
           created_at
         ) VALUES (
           $1, 'SYNTHETIC', 'c05-roles-command-1',
           $2, '{"accepted":true}', $3
         )`,
        [TENANT_ID, HASH_ONE, NOW],
      );
      await client.query(
        `INSERT INTO aios_core.principal_event (
           event_id, tenant_id, tenant_kind, event, created_at
         ) VALUES ($1, $2, 'SYNTHETIC', $3::jsonb, $4)`,
        [EVENT_ID, TENANT_ID, event, NOW],
      );
      await client.query(
        `INSERT INTO aios_core.principal_outbox (
           event_id, tenant_id, tenant_kind, event, created_at
         ) VALUES ($1, $2, 'SYNTHETIC', $3::jsonb, $4)`,
        [EVENT_ID, TENANT_ID, event, NOW],
      );
      await client.query("COMMIT");
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    }
    await rejectsPermission(
      client.query(
        `UPDATE aios_core.principal_outbox
            SET status = 'PROCESSING'
          WHERE event_id = $1`,
        [EVENT_ID],
      ),
    );
  });

  await adminPool.query(
    `UPDATE aios_core.identity_account
        SET state = 'SUSPENDED',
            lifecycle_version = 2,
            source_revision = 2,
            source_payload_hash = $2,
            revocation_epoch = 2,
            updated_at = $3
      WHERE account_id = $1`,
    [ACCOUNT_ID, HASH_TWO, LATER],
  );

  await asRole(pools[C05_CORE_ROLE], C05_CORE_ROLE, async (client) => {
    const synchronized = await client.query(
      `UPDATE aios_core.principal_identity_link
          SET state = 'SUSPENDED',
              lifecycle_version = 2,
              account_lifecycle_version = 2,
              account_revocation_epoch = 2,
              updated_at = $2
        WHERE identity_link_id = $1
      RETURNING state, lifecycle_version, account_lifecycle_version`,
      [LINK_ID, LATER],
    );
    assert.deepEqual(synchronized.rows[0], {
      state: "SUSPENDED",
      lifecycle_version: "2",
      account_lifecycle_version: "2",
    });
  });

  await asRole(pools[C05_OUTBOX_ROLE], C05_OUTBOX_ROLE, async (client) => {
    const claim = await client.query(
      `WITH candidates AS (
         SELECT event_id
           FROM aios_core.principal_outbox
          WHERE status = 'PENDING'
            AND available_at <= statement_timestamp()
          ORDER BY created_at, event_id
          FOR UPDATE SKIP LOCKED
          LIMIT 1
       )
       UPDATE aios_core.principal_outbox AS outbox
          SET status = 'PROCESSING',
              attempt_count = attempt_count + 1,
              lease_version = lease_version + 1,
              leased_by = 'c05-roles-outbox-worker',
              lease_until = statement_timestamp() + interval '30 seconds',
              last_error_code = NULL
         FROM candidates
        WHERE outbox.event_id = candidates.event_id
       RETURNING outbox.event_id, outbox.status, outbox.lease_version`,
    );
    assert.deepEqual(claim.rows[0], {
      event_id: EVENT_ID,
      status: "PROCESSING",
      lease_version: "1",
    });
    for (const forbiddenTable of [
      "principal_registry",
      "principal_identity_link",
      "principal_delegation",
      "principal_event",
      "principal_command_receipt",
      "identity_account",
    ]) {
      await rejectsPermission(
        client.query(`SELECT * FROM aios_core.${forbiddenTable}`),
      );
    }
    await rejectsPermission(
      client.query(
        "DELETE FROM aios_core.principal_outbox WHERE event_id = $1",
        [EVENT_ID],
      ),
    );
    await rejectsPermission(
      client.query(
        `INSERT INTO aios_core.principal_outbox (
           event_id, tenant_id, tenant_kind, event, created_at
         ) VALUES (
           'c05-roles-forbidden', $1, 'SYNTHETIC', '{}'::jsonb, $2
         )`,
        [TENANT_ID, NOW],
      ),
    );
  });

  for (const role of C05_ROLES) {
    await asRole(pools[role], role, async (client) => {
      await rejectsPermission(
        client.query(`CREATE TABLE aios_core.${role}_probe(id integer)`),
      );
    });
  }
});
