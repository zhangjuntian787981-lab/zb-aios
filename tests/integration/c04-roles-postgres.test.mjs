import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import pg from "pg";

const { Pool } = pg;

const migrationUrls = [
  new URL(
    "../../implementation/p1/c03/postgresql/0001_tenant_registry.sql",
    import.meta.url,
  ),
  new URL(
    "../../implementation/p1/c04/postgresql/0002_identity_federation.sql",
    import.meta.url,
  ),
  new URL(
    "../../implementation/p1/c04/postgresql/0003_identity_outbox_delivery.sql",
    import.meta.url,
  ),
  new URL(
    "../../implementation/p1/c04/postgresql/0004_versioned_provider_configuration.sql",
    import.meta.url,
  ),
  new URL(
    "../../implementation/p1/c04/postgresql/0005_scim_checkpoint.sql",
    import.meta.url,
  ),
  new URL(
    "../../implementation/p1/c04/postgresql/0006_identity_runtime_roles.sql",
    import.meta.url,
  ),
];

const migrations = await Promise.all(
  migrationUrls.map((url) => readFile(url, "utf8")),
);

const CORE_ROLE = "aios_c04_core_runtime";
const OUTBOX_ROLE = "aios_c04_outbox_worker";
const SCIM_ROLE = "aios_c04_scim_checkpoint_runtime";
const RUNTIME_ROLES = [CORE_ROLE, OUTBOX_ROLE, SCIM_ROLE];

const LOGIN_ROLES = {
  [CORE_ROLE]: "c04_roles_test_core_login",
  [OUTBOX_ROLE]: "c04_roles_test_outbox_login",
  [SCIM_ROLE]: "c04_roles_test_scim_login",
};

const TENANT_ID = "stn_01984710-0000-7000-8000-000000000001";
const PROVIDER_ID = "idp_01984710-0000-7000-8000-000000000002";
const ACCOUNT_ID = "sia_01984710-0000-7000-8000-000000000003";
const SESSION_ID = "ses_01984710-0000-7000-8000-000000000004";
const EVENT_ID = "c04-roles-event-1";
const NOW = "2026-07-26T06:00:00.000Z";
const HASH_ONE = `sha256:${"1".repeat(64)}`;
const HASH_TWO = `sha256:${"2".repeat(64)}`;

function postgresConfig(user = process.env.C04_ROLES_TEST_PGUSER) {
  if (process.env.C04_ROLES_TEST_EPHEMERAL !== "1") {
    throw new Error("C04_ROLES_TEST_EPHEMERAL=1 is required.");
  }
  for (const name of [
    "C04_ROLES_TEST_PGHOST",
    "C04_ROLES_TEST_PGPORT",
    "C04_ROLES_TEST_PGDATABASE",
    "C04_ROLES_TEST_PGUSER",
  ]) {
    if (!process.env[name]) throw new Error(`${name} is required.`);
  }
  return {
    host: process.env.C04_ROLES_TEST_PGHOST,
    port: Number(process.env.C04_ROLES_TEST_PGPORT),
    database: process.env.C04_ROLES_TEST_PGDATABASE,
    user,
    max: 4,
  };
}

async function rejectsPermission(operation) {
  await assert.rejects(
    operation,
    (error) => error?.code === "42501",
  );
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
    source: "urn:aios:c04:identity-federation",
    type: "product.identity.roles-test.v1",
    subject: TENANT_ID,
    time: NOW,
    datacontenttype: "application/json",
    dataschema: "https://schemas.synthetic.example/c04/roles-test.v1.json",
    tenantkind: "SYNTHETIC",
    correlationid: "c04-roles-test",
    synthetic: true,
    data: { tenant_id: TENANT_ID },
  };
}

test("C04 PostgreSQL runtime roles enforce least privilege", async (t) => {
  const adminPool = new Pool(postgresConfig());
  const runtimePools = [];
  t.after(async () => {
    await Promise.all(runtimePools.map((pool) => pool.end()));
    await adminPool.end();
  });

  const safety = await adminPool.query(
    "SELECT current_database() AS database, to_regnamespace('aios_core') AS schema",
  );
  assert.match(safety.rows[0].database, /^c04_roles_test_[0-9]+$/);
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
    [RUNTIME_ROLES],
  );
  assert.equal(roleAttributes.rowCount, 3);
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
    [RUNTIME_ROLES],
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
    [CORE_ROLE]: {
      identity_tenant_projection: ["SELECT", "INSERT", "UPDATE"],
      identity_provider: ["SELECT", "INSERT", "UPDATE"],
      identity_provider_configuration: ["SELECT", "INSERT", "UPDATE"],
      identity_account: ["SELECT", "INSERT", "UPDATE"],
      identity_login_transaction: ["SELECT", "INSERT", "UPDATE"],
      identity_session: ["SELECT", "INSERT", "UPDATE"],
      identity_source_receipt: ["SELECT", "INSERT"],
      identity_command_receipt: ["SELECT", "INSERT"],
      identity_event: ["SELECT", "INSERT"],
      identity_outbox: ["SELECT", "INSERT"],
    },
    [OUTBOX_ROLE]: {
      identity_outbox: ["SELECT", "UPDATE"],
    },
    [SCIM_ROLE]: {
      scim_provisioning_checkpoint: ["SELECT", "INSERT", "UPDATE"],
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
  for (const role of RUNTIME_ROLES) {
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

  await adminPool.query(
    `CREATE ROLE c04_roles_test_core_login LOGIN NOINHERIT;
     CREATE ROLE c04_roles_test_outbox_login LOGIN NOINHERIT;
     CREATE ROLE c04_roles_test_scim_login LOGIN NOINHERIT;
     CREATE ROLE c04_roles_test_unprivileged LOGIN NOINHERIT;
     GRANT ${CORE_ROLE} TO c04_roles_test_core_login;
     GRANT ${OUTBOX_ROLE} TO c04_roles_test_outbox_login;
     GRANT ${SCIM_ROLE} TO c04_roles_test_scim_login;`,
  );

  const pools = Object.fromEntries(
    Object.entries(LOGIN_ROLES).map(([role, login]) => {
      const pool = new Pool(postgresConfig(login));
      runtimePools.push(pool);
      return [role, pool];
    }),
  );
  const unprivilegedPool = new Pool(
    postgresConfig("c04_roles_test_unprivileged"),
  );
  runtimePools.push(unprivilegedPool);

  await rejectsPermission(
    unprivilegedPool.query(
      "SELECT * FROM aios_core.identity_account LIMIT 1",
    ),
  );
  await rejectsPermission(
    unprivilegedPool.query(
      "CREATE TABLE aios_core.public_privilege_probe(id integer)",
    ),
  );

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
       'c04:roles:test',
       'fixture://c04/roles-test',
       $2,
       '[]'::jsonb,
       'sns_01984710-0000-7000-8000-000000000005',
       'op_01984710-0000-7000-8000-000000000006',
       $3,
       $3
     )`,
    [TENANT_ID, HASH_ONE, NOW],
  );

  await asRole(pools[CORE_ROLE], CORE_ROLE, async (client) => {
    await client.query(
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
         'https://idp.synthetic.example/realms/c04',
         'c04-roles-client',
         '{"PORTAL_HOME":"https://portal.synthetic.example/auth/callback"}',
         1, '["RS256"]', '["synthetic-k1"]', '["mfa"]',
         3600, '["OIDC"]', 'SCIM_REQUIRED', 'ACTIVE', $3, $3
       )`,
      [PROVIDER_ID, TENANT_ID, NOW],
    );
    await client.query(
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
    await client.query(
      `INSERT INTO aios_core.identity_tenant_projection (
         tenant_id,
         tenant_kind,
         fixture_id,
         fixture_hash,
         provider_connection_id,
         state,
         generation,
         operation_id,
         revocation_epoch,
         updated_at
       ) VALUES (
         $1, 'SYNTHETIC', 'c04-roles-fixture', $2, $3,
         'READY', 1,
         'op_01984710-0000-7000-8000-000000000006',
         1, $4
       )`,
      [TENANT_ID, HASH_ONE, PROVIDER_ID, NOW],
    );
    await client.query(
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
         'https://idp.synthetic.example/realms/c04',
         'c04-roles-subject',
         'c04-roles-directory-object',
         'c04-roles-fixture-user',
         'ACTIVE', 1, 1, $4, 1, 1,
         'fixture://c04/roles-test/users/one',
         $5, $5
       )`,
      [ACCOUNT_ID, TENANT_ID, PROVIDER_ID, HASH_ONE, NOW],
    );
    const accountUpdate = await client.query(
      `UPDATE aios_core.identity_account
          SET state = 'SUSPENDED',
              lifecycle_version = 2,
              source_revision = 2,
              source_payload_hash = $2,
              revocation_epoch = 2,
              updated_at = $3
        WHERE account_id = $1
      RETURNING state, lifecycle_version`,
      [ACCOUNT_ID, HASH_TWO, "2026-07-26T06:01:00.000Z"],
    );
    assert.deepEqual(accountUpdate.rows[0], {
      state: "SUSPENDED",
      lifecycle_version: "2",
    });
    await client.query(
      `INSERT INTO aios_core.identity_session (
         session_id,
         tenant_id,
         tenant_kind,
         account_id,
         provider_connection_id,
         provider_configuration_version,
         token_hash,
         account_revocation_epoch,
         tenant_revocation_epoch,
         status,
         authentication_time,
         authentication_methods,
         issued_at,
         expires_at,
         revoked_at
       ) VALUES (
         $1, $2, 'SYNTHETIC', $3, $4, 1, $5,
         2, 1, 'ACTIVE', $6, '["mfa"]', $6,
         '2026-07-26T07:00:00.000Z', NULL
       )`,
      [SESSION_ID, TENANT_ID, ACCOUNT_ID, PROVIDER_ID, HASH_ONE, NOW],
    );
    const sessionUpdate = await client.query(
      `UPDATE aios_core.identity_session
          SET status = 'REVOKED',
              revoked_at = $2
        WHERE session_id = $1
      RETURNING status`,
      [SESSION_ID, "2026-07-26T06:02:00.000Z"],
    );
    assert.equal(sessionUpdate.rows[0].status, "REVOKED");

    await client.query(
      `INSERT INTO aios_core.identity_source_receipt (
         tenant_id, source_event_id, payload_hash, result
       ) VALUES ($1, 'c04-roles-source-1', $2, '{"accepted":true}')`,
      [TENANT_ID, HASH_ONE],
    );
    await client.query(
      `INSERT INTO aios_core.identity_command_receipt (
         idempotency_key, command_hash, result
       ) VALUES ('c04-roles-command-1', $1, '{"accepted":true}')`,
      [HASH_ONE],
    );

    const event = JSON.stringify(syntheticEvent());
    await client.query("BEGIN");
    try {
      await client.query(
        `INSERT INTO aios_core.identity_event (
           event_id, tenant_id, tenant_kind, event, created_at
         ) VALUES ($1, $2, 'SYNTHETIC', $3::jsonb, $4)`,
        [EVENT_ID, TENANT_ID, event, NOW],
      );
      await client.query(
        `INSERT INTO aios_core.identity_outbox (
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
        `UPDATE aios_core.identity_event
            SET created_at = created_at
          WHERE event_id = $1`,
        [EVENT_ID],
      ),
    );
    await rejectsPermission(
      client.query(
        `UPDATE aios_core.identity_outbox
            SET status = 'PROCESSING'
          WHERE event_id = $1`,
        [EVENT_ID],
      ),
    );
    await rejectsPermission(
      client.query(
        "SELECT * FROM aios_core.scim_provisioning_checkpoint",
      ),
    );
    await rejectsPermission(
      client.query(
        "UPDATE aios_core.tenant_command_receipt SET result = result",
      ),
    );
    await rejectsPermission(
      client.query(
        "DELETE FROM aios_core.identity_account WHERE account_id = $1",
        [ACCOUNT_ID],
      ),
    );
  });

  await asRole(pools[OUTBOX_ROLE], OUTBOX_ROLE, async (client) => {
    const claim = await client.query(
      `WITH candidates AS (
         SELECT event_id
           FROM aios_core.identity_outbox
          WHERE status = 'PENDING'
            AND available_at <= statement_timestamp()
          ORDER BY created_at, event_id
          FOR UPDATE SKIP LOCKED
          LIMIT 1
       )
       UPDATE aios_core.identity_outbox AS outbox
          SET status = 'PROCESSING',
              attempt_count = attempt_count + 1,
              lease_version = lease_version + 1,
              leased_by = 'c04-roles-outbox-worker',
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
    await rejectsPermission(
      client.query("SELECT * FROM aios_core.identity_account"),
    );
    await rejectsPermission(
      client.query("SELECT * FROM aios_core.identity_event"),
    );
    await rejectsPermission(
      client.query(
        "SELECT * FROM aios_core.scim_provisioning_checkpoint",
      ),
    );
    await rejectsPermission(
      client.query(
        "DELETE FROM aios_core.identity_outbox WHERE event_id = $1",
        [EVENT_ID],
      ),
    );
  });

  await asRole(pools[SCIM_ROLE], SCIM_ROLE, async (client) => {
    await client.query(
      `INSERT INTO aios_core.scim_provisioning_checkpoint (
         tenant_id,
         provider_connection_id,
         external_id,
         user_name,
         source_revision,
         desired_state,
         profile,
         status,
         resource_id,
         created_at,
         updated_at
       ) VALUES (
         $1,
         $2,
         'c04-roles-directory-object',
         'c04-roles-user',
         1,
         'ACTIVE',
         '{"givenName":"C04","familyName":"Roles","email":"roles@synthetic.example"}',
         'PENDING',
         NULL,
         $3,
         $3
       )`,
      [TENANT_ID, PROVIDER_ID, NOW],
    );
    const checkpoint = await client.query(
      `UPDATE aios_core.scim_provisioning_checkpoint
          SET status = 'CONFIRMED',
              resource_id = 'c04-roles-resource-1',
              updated_at = $3
        WHERE tenant_id = $1
          AND provider_connection_id = $2
          AND external_id = 'c04-roles-directory-object'
      RETURNING source_revision, status, resource_id`,
      [
        TENANT_ID,
        PROVIDER_ID,
        "2026-07-26T06:03:00.000Z",
      ],
    );
    assert.deepEqual(checkpoint.rows[0], {
      source_revision: "1",
      status: "CONFIRMED",
      resource_id: "c04-roles-resource-1",
    });
    const readback = await client.query(
      `SELECT external_id
         FROM aios_core.scim_provisioning_checkpoint
        WHERE tenant_id = $1
          AND provider_connection_id = $2
          AND external_id = 'c04-roles-directory-object'`,
      [TENANT_ID, PROVIDER_ID],
    );
    assert.equal(readback.rows[0].external_id, "c04-roles-directory-object");

    await rejectsPermission(
      client.query("SELECT * FROM aios_core.identity_account"),
    );
    await rejectsPermission(
      client.query("SELECT * FROM aios_core.identity_outbox"),
    );
    await rejectsPermission(
      client.query(
        `DELETE FROM aios_core.scim_provisioning_checkpoint
          WHERE tenant_id = $1
            AND provider_connection_id = $2
            AND external_id = 'c04-roles-directory-object'`,
        [TENANT_ID, PROVIDER_ID],
      ),
    );
  });

  const forbiddenRoleTargets = {
    [CORE_ROLE]: OUTBOX_ROLE,
    [OUTBOX_ROLE]: SCIM_ROLE,
    [SCIM_ROLE]: CORE_ROLE,
  };
  for (const role of RUNTIME_ROLES) {
    await asRole(pools[role], role, async (client) => {
      await rejectsPermission(
        client.query(`SET ROLE ${forbiddenRoleTargets[role]}`),
      );
      await rejectsPermission(
        client.query(
          `CREATE TABLE aios_core.${role}_ddl_probe(id integer)`,
        ),
      );
    });
  }
});
