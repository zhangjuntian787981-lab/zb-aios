import assert from "node:assert/strict";
import test from "node:test";
import { createPostgresPrincipalStore } from "../lib/postgres-principal-store.mjs";

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

test("the PostgreSQL adapter preserves the three-method C05 Store seam", () => {
  const { pool } = scriptedPool(() => ({ rows: [], rowCount: 1 }));
  const store = createPostgresPrincipalStore({ pool });
  assert.deepEqual(Object.keys(store).sort(), [
    "readActionSnapshot",
    "readTenantSnapshot",
    "runCommand",
  ]);
});

test("C05 checks replay and upstream preflight before its serializable transaction", async () => {
  const { pool, queries } = scriptedPool((sql) => {
    if (sql.includes("SELECT command_hash")) {
      return { rows: [], rowCount: 0 };
    }
    return { rows: [], rowCount: 1 };
  });
  const store = createPostgresPrincipalStore({ pool });
  let preflightQueryCount = null;
  const value = await store.runCommand(
    {
      tenantId: "stn_contract",
      idempotencyKey: "c05-contract",
      commandHash: `sha256:${"a".repeat(64)}`,
    },
    async (transaction) => {
      assert.deepEqual(Object.keys(transaction).sort(), [
        "appendEvent",
        "appendOutbox",
        "findPrincipalByFixture",
        "insertDelegation",
        "insertIdentityLink",
        "insertPrincipal",
        "listDelegations",
        "listIdentityLinks",
        "loadCurrentIdentityLinkForAccount",
        "loadDelegationForUpdate",
        "loadIdentityLinkForUpdate",
        "loadPrincipalForUpdate",
        "putDelegation",
        "putIdentityLink",
        "putPrincipal",
      ]);
      return { applied: true };
    },
    async () => {
      preflightQueryCount = queries.length;
      return { verified: true };
    },
  );
  assert.deepEqual(value, {
    duplicate: false,
    value: { applied: true },
  });
  assert.ok(queries[0].sql.includes("SELECT command_hash"));
  assert.equal(preflightQueryCount, 1);
  assert.equal(queries[1].sql, "BEGIN ISOLATION LEVEL SERIALIZABLE");
  assert.ok(queries[2].sql.includes("SELECT command_hash"));
  assert.ok(
    queries.some(({ sql }) => sql.includes("principal_command_receipt")),
  );
  assert.equal(queries.at(-1).sql, "COMMIT");
});

test("event and outbox inserts use the exact same payload before commit", async () => {
  const { pool, queries } = scriptedPool((sql) => {
    if (sql.includes("SELECT command_hash")) {
      return { rows: [], rowCount: 0 };
    }
    return { rows: [], rowCount: 1 };
  });
  const store = createPostgresPrincipalStore({ pool });
  const event = {
    specversion: "1.0",
    id: "evt_contract",
    tenantkind: "SYNTHETIC",
    time: "2026-07-26T08:00:00.000Z",
    data: { tenant_id: "stn_contract" },
  };
  await store.runCommand(
    {
      tenantId: "stn_contract",
      idempotencyKey: "c05-event",
      commandHash: `sha256:${"b".repeat(64)}`,
    },
    async (transaction) => {
      await transaction.appendEvent(event);
      await transaction.appendOutbox(event);
      return { eventId: event.id };
    },
  );
  const eventInsert = queries.find(({ sql }) =>
    sql.includes('"principal_event"'),
  );
  const outboxInsert = queries.find(({ sql }) =>
    sql.includes('"principal_outbox"'),
  );
  assert.ok(eventInsert);
  assert.ok(outboxInsert);
  assert.equal(eventInsert.parameters[3], outboxInsert.parameters[3]);
});

test("action resolution reads one repeatable snapshot without mutating C05", async () => {
  const { pool, queries } = scriptedPool(() => ({
    rows: [],
    rowCount: 0,
  }));
  const store = createPostgresPrincipalStore({ pool });
  const value = await store.readActionSnapshot({
    tenantId: "stn_contract",
    identityAccountId: "sia_contract",
    workloadActorPrincipalId: "prn_contract",
    delegationId: "dlg_contract",
  });
  assert.deepEqual(value, {
    link: null,
    humanSubject: null,
    workloadActor: null,
    principals: [],
    delegations: [],
  });
  assert.equal(
    queries[0].sql,
    "BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY",
  );
  assert.equal(queries.at(-1).sql, "COMMIT");
  assert.equal(
    queries.some(({ sql }) => /^\s*(INSERT|UPDATE|DELETE)\b/.test(sql)),
    false,
  );
  assert.equal(
    queries.some(({ sql }) =>
      sql.includes("WITH RECURSIVE delegation_chain"),
    ),
    true,
  );
  assert.equal(
    queries.some(
      ({ sql }) =>
        sql.includes('FROM "aios_core"."principal_registry"') &&
        !sql.includes("principal_id = ANY"),
    ),
    false,
  );
});
