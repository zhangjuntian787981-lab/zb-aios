import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import {
  createPostgresScimCheckpointStore,
  PostgresScimCheckpointStoreError,
} from "../lib/postgres-scim-checkpoint-store.mjs";

const migrationUrl = new URL(
  "../implementation/p1/c04/postgresql/0005_scim_checkpoint.sql",
  import.meta.url,
);
const TENANT_ID =
  "stn_01984710-0000-7000-8000-000000000001";
const PROVIDER_CONNECTION_ID =
  "idp_01984710-0000-7000-8000-000000000001";

const CHECKPOINT = Object.freeze({
  externalId: "synthetic-directory-001",
  userName: "synthetic-user",
  sourceRevision: 1,
  desiredState: "ACTIVE",
  profile: {
    givenName: "Synthetic",
    familyName: "User",
    email: "synthetic-user@c04-synthetic.example",
  },
  status: "PENDING",
  resourceId: null,
});

function scriptedPool(responder) {
  const queries = [];
  const releases = [];
  let connections = 0;
  const client = {
    async query(sql, parameters = []) {
      queries.push({ sql, parameters });
      return responder(sql, parameters);
    },
    release(destroy = false) {
      releases.push(destroy);
    },
  };
  return {
    queries,
    releases,
    get connections() {
      return connections;
    },
    pool: {
      async connect() {
        connections += 1;
        return client;
      },
    },
  };
}

function defaultResponder(sql) {
  if (sql.includes("pg_advisory_unlock")) {
    return { rows: [{ unlocked: true }], rowCount: 1 };
  }
  if (sql.includes("FROM \"aios_core\".\"scim_provisioning_checkpoint\"")) {
    return { rows: [], rowCount: 0 };
  }
  return { rows: [], rowCount: 1 };
}

function createStore(pool, overrides = {}) {
  return createPostgresScimCheckpointStore({
    pool,
    tenantId: TENANT_ID,
    providerConnectionId: PROVIDER_CONNECTION_ID,
    ...overrides,
  });
}

test("the checkpoint store exposes the exact adapter Port", () => {
  const scripted = scriptedPool(defaultResponder);
  const store = createStore(scripted.pool);

  assert.deepEqual(Object.keys(store).sort(), [
    "runExclusive",
    "transact",
  ]);
  assert.throws(
    () =>
      createStore(scripted.pool, {
        schema: "aios_core; DROP SCHEMA public",
      }),
    (error) =>
      error instanceof PostgresScimCheckpointStoreError &&
      error.code === "INVALID_CHECKPOINT_STORE",
  );
  assert.throws(
    () =>
      createStore(scripted.pool, {
        tenantId: "etn_01984710-0000-7000-8000-000000000001",
      }),
    (error) =>
      error instanceof PostgresScimCheckpointStoreError &&
      error.code === "INVALID_CHECKPOINT_STORE",
  );
});

test("transact fails closed outside its advisory-lock context", async () => {
  const scripted = scriptedPool(defaultResponder);
  const store = createStore(scripted.pool);

  await assert.rejects(
    store.transact(CHECKPOINT.externalId, () => ({
      next: CHECKPOINT,
      value: null,
    })),
    (error) =>
      error instanceof PostgresScimCheckpointStoreError &&
      error.code === "CHECKPOINT_LOCK_REQUIRED",
  );
  assert.equal(scripted.connections, 0);
});

test("a locked reducer atomically inserts its checkpoint", async () => {
  const scripted = scriptedPool(defaultResponder);
  const store = createStore(scripted.pool);

  const result = await store.runExclusive(
    CHECKPOINT.externalId,
    () =>
      store.transact(CHECKPOINT.externalId, (current) => {
        assert.equal(current, null);
        return {
          next: CHECKPOINT,
          value: { action: "APPLY" },
        };
      }),
  );

  assert.deepEqual(result, { action: "APPLY" });
  assert.match(scripted.queries[0].sql, /pg_advisory_lock/);
  assert.equal(scripted.queries[1].sql, "BEGIN");
  assert.match(scripted.queries[2].sql, /FOR UPDATE/);
  assert.match(scripted.queries[3].sql, /INSERT INTO/);
  assert.deepEqual(scripted.queries[2].parameters, [
    TENANT_ID,
    PROVIDER_CONNECTION_ID,
    CHECKPOINT.externalId,
  ]);
  assert.deepEqual(scripted.queries[3].parameters.slice(0, 3), [
    TENANT_ID,
    PROVIDER_CONNECTION_ID,
    CHECKPOINT.externalId,
  ]);
  assert.equal(scripted.queries[4].sql, "COMMIT");
  assert.match(scripted.queries[5].sql, /pg_advisory_unlock/);
  assert.deepEqual(
    scripted.queries[0].parameters,
    scripted.queries[5].parameters,
  );
  assert.deepEqual(scripted.releases, [false]);
});

test("a reducer exception rolls back and releases the session lock", async () => {
  const scripted = scriptedPool(defaultResponder);
  const store = createStore(scripted.pool);
  const expected = new Error("synthetic reducer failure");

  await assert.rejects(
    store.runExclusive(CHECKPOINT.externalId, () =>
      store.transact(CHECKPOINT.externalId, () => {
        throw expected;
      }),
    ),
    (error) => error === expected,
  );

  assert.ok(scripted.queries.some(({ sql }) => sql === "ROLLBACK"));
  assert.match(scripted.queries.at(-1).sql, /pg_advisory_unlock/);
  assert.deepEqual(scripted.releases, [false]);
});

test("an async child cannot transact after its lock callback returns", async () => {
  const scripted = scriptedPool(defaultResponder);
  const store = createStore(scripted.pool);
  let releaseChild;
  const childGate = new Promise((resolve) => {
    releaseChild = resolve;
  });
  let child;

  await store.runExclusive(CHECKPOINT.externalId, async () => {
    child = new Promise((resolve) => {
      setImmediate(async () => {
        await childGate;
        try {
          await store.transact(CHECKPOINT.externalId, () => ({
            next: CHECKPOINT,
            value: null,
          }));
        } catch (error) {
          resolve(error);
        }
      });
    });
  });
  releaseChild();
  const error = await child;

  assert.ok(error instanceof PostgresScimCheckpointStoreError);
  assert.equal(error.code, "CHECKPOINT_LOCK_REQUIRED");
  assert.equal(
    scripted.queries.filter(({ sql }) => sql === "BEGIN").length,
    0,
  );
});

test("the migration enforces permanent SCIM identity checkpoints", async () => {
  const sql = await readFile(migrationUrl, "utf8");

  assert.match(
    sql,
    /CREATE TABLE aios_core\.scim_provisioning_checkpoint/,
  );
  assert.match(
    sql,
    /PRIMARY KEY \(tenant_id, provider_connection_id, external_id\)/,
  );
  assert.match(
    sql,
    /scim_checkpoint_user_name_key[\s\S]*UNIQUE \(tenant_id, provider_connection_id, user_name\)/,
  );
  assert.match(sql, /source_revision <= 9007199254740991/);
  assert.match(sql, /tenant_id ~ '\^stn_/);
  assert.doesNotMatch(sql, /etn/);
  assert.match(
    sql,
    /scim_checkpoint_provider_fkey[\s\S]*FOREIGN KEY \(provider_connection_id, tenant_id\)[\s\S]*identity_provider/,
  );
  assert.match(sql, /scim_checkpoint_initial_state_guard/);
  assert.match(sql, /scim_checkpoint_binding_guard/);
  assert.match(sql, /scim_checkpoint_revision_guard/);
  assert.match(sql, /scim_checkpoint_content_guard/);
  assert.match(sql, /scim_checkpoint_terminal_guard/);
  assert.match(sql, /scim_checkpoint_no_delete/);
  assert.doesNotMatch(sql, /CREATE SEQUENCE/i);
});
