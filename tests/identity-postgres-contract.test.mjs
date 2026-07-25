import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { createPostgresIdentityStore } from "../lib/postgres-identity-store.mjs";

const migrationUrl = new URL(
  "../implementation/p1/c04/postgresql/0002_identity_federation.sql",
  import.meta.url,
);
const providerConfigurationMigrationUrl = new URL(
  "../implementation/p1/c04/postgresql/0004_versioned_provider_configuration.sql",
  import.meta.url,
);

function scriptedPool(responder) {
  const queries = [];
  const client = {
    async query(sql, parameters = []) {
      queries.push({ sql, parameters });
      return responder(sql, parameters);
    },
    release() {},
  };
  return {
    queries,
    pool: {
      async connect() {
        return client;
      },
    },
  };
}

test("the C04 migration creates the nine identity persistence tables", async () => {
  const sql = await readFile(migrationUrl, "utf8");
  const tables = [
    "identity_provider",
    "identity_tenant_projection",
    "identity_account",
    "identity_source_receipt",
    "identity_login_transaction",
    "identity_session",
    "identity_command_receipt",
    "identity_event",
    "identity_outbox",
  ];

  for (const table of tables) {
    assert.match(sql, new RegExp(`CREATE TABLE aios_core\\.${table}`));
  }
  assert.equal(
    Array.from(sql.matchAll(/CREATE TABLE aios_core\.identity_/g)).length,
    9,
  );
  assert.match(sql, /identity_account_directory_key[\s\S]*UNIQUE/);
  assert.match(sql, /identity_account_subject_key[\s\S]*UNIQUE/);
  assert.match(sql, /identity_session_token_hash_key UNIQUE/);
  assert.match(sql, /identity_account_terminal_guard/);
  assert.match(sql, /identity_provider_terminal_guard/);
  assert.match(sql, /identity_projection_terminal_guard/);
  assert.match(sql, /identity_session_terminal_guard/);
  assert.match(sql, /identity_source_receipt_no_update/);
  assert.match(sql, /identity_command_receipt_no_update/);
  assert.match(sql, /identity_event_no_update/);
  assert.match(
    sql,
    /event #>> '\{data,tenant_id\}'\) IS NOT DISTINCT FROM tenant_id/,
  );
  assert.match(
    sql,
    /CREATE CONSTRAINT TRIGGER identity_event_requires_outbox[\s\S]*DEFERRABLE INITIALLY DEFERRED/,
  );
  assert.match(
    sql,
    /CREATE CONSTRAINT TRIGGER identity_outbox_requires_event[\s\S]*DEFERRABLE INITIALLY DEFERRED/,
  );
  assert.match(sql, /paired_event IS DISTINCT FROM NEW\.event/);
  assert.match(sql, /database owner and migration role are trusted/);
});

test("login and session persistence stores hashes instead of bearer secrets", async () => {
  const sql = await readFile(migrationUrl, "utf8");
  const loginTable = sql.slice(
    sql.indexOf("CREATE TABLE aios_core.identity_login_transaction"),
    sql.indexOf("CREATE TABLE aios_core.identity_session"),
  );
  const sessionTable = sql.slice(
    sql.indexOf("CREATE TABLE aios_core.identity_session"),
    sql.indexOf("CREATE TABLE aios_core.identity_command_receipt"),
  );

  assert.match(loginTable, /^\s+state_hash text NOT NULL/m);
  assert.match(loginTable, /^\s+nonce_hash text NOT NULL/m);
  assert.match(loginTable, /^\s+pkce_verifier_hash text NOT NULL/m);
  assert.doesNotMatch(loginTable, /^\s+state text/m);
  assert.doesNotMatch(loginTable, /^\s+nonce text/m);
  assert.doesNotMatch(loginTable, /^\s+pkce_verifier text/m);
  assert.match(sessionTable, /^\s+token_hash text NOT NULL/m);
  assert.doesNotMatch(sessionTable, /^\s+session_token text/m);
});

test("provider configuration is versioned with one-way rotation states", async () => {
  const sql = await readFile(providerConfigurationMigrationUrl, "utf8");

  assert.match(
    sql,
    /CREATE TABLE aios_core\.identity_provider_configuration/,
  );
  assert.match(sql, /PRIMARY KEY \(provider_connection_id, configuration_version\)/);
  assert.match(
    sql,
    /WHERE state = 'CURRENT'/,
  );
  assert.match(sql, /state IN \('CURRENT', 'GRACE', 'RETIRED'\)/);
  assert.match(
    sql,
    /identity_provider_configuration_state_guard/,
  );
  assert.match(sql, /identity_provider_configuration_no_delete/);
  assert.match(sql, /identity_login_provider_configuration_fkey/);
  assert.match(sql, /identity_session_provider_configuration_fkey/);
});

test("the PostgreSQL adapter preserves the narrow four-method Store seam", () => {
  const { pool } = scriptedPool(() => ({ rows: [], rowCount: 1 }));
  const store = createPostgresIdentityStore({ pool });

  assert.deepEqual(Object.keys(store).sort(), [
    "readSessionSnapshot",
    "readTenantSnapshot",
    "runCommand",
    "transact",
  ]);
});

test("runCommand exposes every existing transaction method in one serializable transaction", async () => {
  const { pool, queries } = scriptedPool((sql) => {
    if (sql.includes("SELECT command_hash")) {
      return { rows: [], rowCount: 0 };
    }
    return { rows: [], rowCount: 1 };
  });
  const store = createPostgresIdentityStore({ pool });
  const result = await store.runCommand(
    {
      idempotencyKey: "identity-contract-001",
      commandHash: `sha256:${"a".repeat(64)}`,
    },
    async (transaction) => {
      assert.deepEqual(Object.keys(transaction).sort(), [
        "appendEvent",
        "appendOutbox",
        "findAccountByDirectory",
        "findAccountBySubject",
        "insertLoginTransaction",
        "insertSession",
        "listAccounts",
        "loadAccountForUpdate",
        "loadLoginTransactionForUpdate",
        "loadProjectionForUpdate",
        "loadProvider",
        "loadProviderConfiguration",
        "loadSessionByIdForUpdate",
        "loadSourceReceipt",
        "putAccount",
        "putLoginTransaction",
        "putProjection",
        "putProvider",
        "putSession",
        "putSourceReceipt",
        "retireProviderConfiguration",
        "revokeSessionsForAccount",
        "revokeSessionsForTenant",
        "rotateProviderConfiguration",
      ]);
      return { tenantId: "stn_contract" };
    },
  );

  assert.deepEqual(result, {
    duplicate: false,
    value: { tenantId: "stn_contract" },
  });
  assert.equal(queries[0].sql, "BEGIN ISOLATION LEVEL SERIALIZABLE");
  assert.ok(
    queries.some(({ sql }) => sql.includes("identity_command_receipt")),
  );
  assert.equal(queries.at(-1).sql, "COMMIT");
});

test("event and outbox payloads use the same transaction and exact event", async () => {
  const { pool, queries } = scriptedPool((sql) => {
    if (sql.includes("SELECT command_hash")) {
      return { rows: [], rowCount: 0 };
    }
    return { rows: [], rowCount: 1 };
  });
  const store = createPostgresIdentityStore({ pool });
  const event = {
    specversion: "1.0",
    id: "evt_contract",
    tenantkind: "SYNTHETIC",
    synthetic: true,
    time: "2026-07-26T00:00:00.000Z",
    data: { tenant_id: "stn_contract" },
  };

  await store.runCommand(
    {
      idempotencyKey: "identity-event-contract",
      commandHash: `sha256:${"b".repeat(64)}`,
    },
    async (transaction) => {
      await transaction.appendEvent(event);
      await transaction.appendOutbox(event);
      return { emitted: true };
    },
  );

  const eventInsertIndex = queries.findIndex(({ sql }) =>
    sql.includes('"identity_event"'),
  );
  const outboxInsertIndex = queries.findIndex(({ sql }) =>
    sql.includes('"identity_outbox"'),
  );
  assert.ok(eventInsertIndex > 0);
  assert.ok(outboxInsertIndex > eventInsertIndex);
  assert.equal(
    queries[eventInsertIndex].parameters[3],
    queries[outboxInsertIndex].parameters[3],
  );
  assert.equal(queries.at(-1).sql, "COMMIT");
});

test("login completion locks the login transaction before the projection", async () => {
  const { pool, queries } = scriptedPool(() => ({
    rows: [],
    rowCount: 1,
  }));
  const store = createPostgresIdentityStore({ pool });

  await store.transact(async (transaction) => {
    await transaction.loadLoginTransactionForUpdate("lgn_contract");
    await transaction.loadProjectionForUpdate("stn_contract");
    return { claimed: true };
  });

  const loginLock = queries.findIndex(({ sql }) =>
    sql.includes('"identity_login_transaction"'),
  );
  const projectionLock = queries.findIndex(({ sql }) =>
    sql.includes('"identity_tenant_projection"'),
  );
  assert.ok(loginLock > 0);
  assert.ok(projectionLock > loginLock);
  assert.match(queries[loginLock].sql, /FOR UPDATE/);
  assert.match(queries[projectionLock].sql, /FOR UPDATE/);
  assert.equal(queries[0].sql, "BEGIN ISOLATION LEVEL SERIALIZABLE");
  assert.equal(queries.at(-1).sql, "COMMIT");
});

test("stored command receipts replay safely and conflicting reuse fails closed", async () => {
  const commandHash = `sha256:${"c".repeat(64)}`;
  const existing = scriptedPool((sql) => {
    if (sql.includes("SELECT command_hash")) {
      return {
        rows: [
          {
            command_hash: commandHash,
            result: { tenantId: "stn_existing" },
          },
        ],
        rowCount: 1,
      };
    }
    return { rows: [], rowCount: 1 };
  });
  const store = createPostgresIdentityStore({ pool: existing.pool });
  const replay = await store.runCommand(
    { idempotencyKey: "identity-replay", commandHash },
    async () => {
      throw new Error("reducer must not run for a replay");
    },
  );
  assert.deepEqual(replay, {
    duplicate: true,
    value: { tenantId: "stn_existing" },
  });

  await assert.rejects(
    store.runCommand(
      {
        idempotencyKey: "identity-replay",
        commandHash: `sha256:${"d".repeat(64)}`,
      },
      async () => ({}),
    ),
    (error) => error.code === "IDEMPOTENCY_CONFLICT",
  );
});

test("binding conflicts and random identifier collisions have stable error codes", async () => {
  const binding = scriptedPool((sql) => {
    if (sql.includes("SELECT command_hash")) {
      return { rows: [], rowCount: 0 };
    }
    if (sql.includes('INSERT INTO "aios_core"."identity_account"')) {
      throw {
        code: "23505",
        constraint: "identity_account_subject_key",
      };
    }
    return { rows: [], rowCount: 1 };
  });
  const bindingStore = createPostgresIdentityStore({
    pool: binding.pool,
    maxSerializableRetries: 0,
  });
  await assert.rejects(
    bindingStore.runCommand(
      {
        idempotencyKey: "identity-binding-conflict",
        commandHash: `sha256:${"e".repeat(64)}`,
      },
      async (transaction) => {
        await transaction.putAccount({
          accountId: "sia_contract",
          tenantId: "stn_contract",
          tenantKind: "SYNTHETIC",
          providerConnectionId: "idp_contract",
          issuer: "https://idp.example",
          subject: "subject",
          directoryObjectId: "directory",
          fixtureUserId: "fixture-user",
          state: "ACTIVE",
          lifecycleVersion: 1,
          sourceRevision: 1,
          sourcePayloadHash: `sha256:${"f".repeat(64)}`,
          revocationEpoch: 1,
          incarnation: 1,
          profileRef: "fixture://user",
          createdAt: "2026-07-26T00:00:00.000Z",
          updatedAt: "2026-07-26T00:00:00.000Z",
        });
        return {};
      },
    ),
    (error) => error.code === "IDENTITY_BINDING_CONFLICT",
  );

  const collision = scriptedPool((sql) => {
    if (sql.includes("identity_session")) {
      throw {
        code: "23505",
        constraint: "identity_session_pkey",
      };
    }
    return { rows: [], rowCount: 1 };
  });
  const collisionStore = createPostgresIdentityStore({
    pool: collision.pool,
    maxSerializableRetries: 0,
  });
  await assert.rejects(
    collisionStore.transact(async (transaction) => {
      await transaction.insertSession({
        sessionId: "ses_contract",
        tenantId: "stn_contract",
        tenantKind: "SYNTHETIC",
        accountId: "sia_contract",
        providerConnectionId: "idp_contract",
        providerConfigurationVersion: 1,
        tokenHash: `sha256:${"1".repeat(64)}`,
        accountRevocationEpoch: 1,
        tenantRevocationEpoch: 1,
        status: "ACTIVE",
        authenticationTime: "2026-07-26T00:00:00.000Z",
        authenticationMethods: ["mfa"],
        issuedAt: "2026-07-26T00:00:00.000Z",
        expiresAt: "2026-07-26T01:00:00.000Z",
        revokedAt: null,
      });
    }),
    (error) => error.code === "ID_COLLISION",
  );
});

test("tenant snapshots use one repeatable-read, read-only database view", async () => {
  const projectionRow = {
    tenant_id: "stn_contract",
    tenant_kind: "SYNTHETIC",
    fixture_id: "fixture-contract",
    fixture_hash: `sha256:${"2".repeat(64)}`,
    provider_connection_id: "idp_contract",
    state: "READY",
    generation: "3",
    operation_id: "op_contract",
    revocation_epoch: "4",
    updated_at: "2026-07-26T00:00:00.000Z",
  };
  const providerRow = {
    provider_connection_id: "idp_contract",
    tenant_id: "stn_contract",
    tenant_kind: "SYNTHETIC",
    protocol: "OIDC",
    issuer: "https://idp.example",
    client_id: "client",
    redirect_routes: { PORTAL: "https://portal.example/callback" },
    configuration_version: "1",
    allowed_algorithms: ["RS256"],
    allowed_key_ids: ["k1"],
    required_authentication_methods: ["mfa"],
    max_authentication_age_seconds: 3600,
    upstream_protocols: ["OIDC"],
    policy: "SCIM_REQUIRED",
    status: "ACTIVE",
    created_at: "2026-07-26T00:00:00.000Z",
    updated_at: "2026-07-26T00:00:00.000Z",
  };
  const event = { id: "evt_contract" };
  const { pool, queries } = scriptedPool((sql) => {
    if (sql.includes("identity_tenant_projection")) {
      return { rows: [projectionRow], rowCount: 1 };
    }
    if (sql.includes("identity_provider")) {
      return { rows: [providerRow], rowCount: 1 };
    }
    if (sql.includes("identity_event")) {
      return { rows: [{ event }], rowCount: 1 };
    }
    if (sql.includes("identity_outbox")) {
      return { rows: [{ event }], rowCount: 1 };
    }
    return { rows: [], rowCount: 0 };
  });
  const store = createPostgresIdentityStore({ pool });
  const snapshot = await store.readTenantSnapshot("stn_contract");

  assert.equal(
    queries[0].sql,
    "BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY",
  );
  assert.equal(queries.at(-1).sql, "COMMIT");
  assert.equal(snapshot.projection.generation, 3);
  assert.equal(snapshot.projection.revocationEpoch, 4);
  assert.deepEqual(snapshot.provider.upstreamProtocols, ["OIDC"]);
  assert.deepEqual(snapshot.events, [event]);
  assert.deepEqual(snapshot.outbox, [event]);
});

test("unsafe schemas and unknown database failures fail closed", async () => {
  assert.throws(
    () =>
      createPostgresIdentityStore({
        pool: { connect() {} },
        schema: "aios_core; DROP SCHEMA public",
      }),
    (error) => error.code === "INVALID_STORE",
  );

  const store = createPostgresIdentityStore({
    pool: {
      async connect() {
        throw new Error("secret database host");
      },
    },
  });
  await assert.rejects(
    store.readTenantSnapshot("stn_contract"),
    (error) =>
      error.code === "STORE_UNAVAILABLE" &&
      !error.message.includes("secret database host"),
  );
});
