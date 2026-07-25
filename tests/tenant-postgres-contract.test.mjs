import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { createPostgresTenantStore } from "../lib/postgres-tenant-store.mjs";

const migrationUrl = new URL(
  "../implementation/p1/c03/postgresql/0001_tenant_registry.sql",
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

test("the PostgreSQL migration enforces immutable namespaces and tombstones", async () => {
  const sql = await readFile(migrationUrl, "utf8");

  for (const table of [
    "tenant_registry",
    "tenant_command_receipt",
    "tenant_projection",
    "tenant_lifecycle_event",
    "tenant_outbox",
  ]) {
    assert.match(sql, new RegExp(`CREATE TABLE aios_core\\.${table}`));
  }
  assert.match(sql, /tenant_kind = 'SYNTHETIC'[\s\S]*tenant_id ~ '\^stn_/);
  assert.match(sql, /tenant_kind = 'ENTERPRISE'[\s\S]*tenant_id ~ '\^etn_/);
  assert.match(sql, /reject_tenant_identity_mutation/);
  assert.match(sql, /tenant_registry_initial_state_guard/);
  assert.match(sql, /new tenant must start at provisioning version one/);
  assert.match(sql, /tenant_registry_lifecycle_guard/);
  assert.match(
    sql,
    /tenant cannot activate before all projections are ready/,
  );
  assert.match(
    sql,
    /tenant cannot finalize deletion before all projections finish/,
  );
  assert.match(sql, /tenant_registry_no_delete/);
  assert.match(sql, /tenant_lifecycle_event_no_update/);
  assert.match(
    sql,
    /FOREIGN KEY \(tenant_id, tenant_kind\)[\s\S]*tenant_registry\(tenant_id, tenant_kind\)/,
  );
  assert.match(sql, /lease_version bigint NOT NULL DEFAULT 0/);
  assert.match(
    sql,
    /CHECK \(\(event ->> 'subject'\) IS NOT DISTINCT FROM tenant_id\)/,
  );
  assert.match(
    sql,
    /CHECK \(jsonb_typeof\(event -> 'data'\) IS NOT DISTINCT FROM 'object'\)/,
  );
  assert.match(
    sql,
    /jsonb_typeof\(event -> 'synthetic'\) IS NOT DISTINCT FROM 'boolean'/,
  );
});

test("the PostgreSQL adapter wraps a new command in a serializable transaction", async () => {
  const { pool, queries } = scriptedPool((sql) => {
    if (sql.includes("SELECT command_hash")) {
      return { rows: [], rowCount: 0 };
    }
    return { rows: [], rowCount: 1 };
  });
  const store = createPostgresTenantStore({ pool });
  const result = await store.runCommand(
    {
      idempotencyKey: "postgres-contract-001",
      commandHash: `sha256:${"a".repeat(64)}`,
    },
    async (transaction) => {
      assert.equal(typeof transaction.loadTenantForUpdate, "function");
      assert.equal(typeof transaction.appendOutbox, "function");
      return { tenantId: "stn_contract" };
    },
  );

  assert.deepEqual(result, {
    duplicate: false,
    value: { tenantId: "stn_contract" },
  });
  assert.match(queries[0].sql, /BEGIN ISOLATION LEVEL SERIALIZABLE/);
  assert.ok(
    queries.some(({ sql }) => sql.includes("tenant_command_receipt")),
  );
  assert.equal(queries.at(-1).sql, "COMMIT");
});

test("a stored PostgreSQL receipt replays safely and conflicts fail closed", async () => {
  const commandHash = `sha256:${"b".repeat(64)}`;
  const first = scriptedPool((sql) => {
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
  const store = createPostgresTenantStore({ pool: first.pool });
  const replay = await store.runCommand(
    { idempotencyKey: "postgres-replay", commandHash },
    async () => {
      throw new Error("reducer must not run for a replay");
    },
  );
  assert.deepEqual(replay, {
    duplicate: true,
    value: { tenantId: "stn_existing" },
  });

  const second = scriptedPool((sql) => {
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
  const conflicting = createPostgresTenantStore({ pool: second.pool });
  await assert.rejects(
    conflicting.runCommand(
      {
        idempotencyKey: "postgres-replay",
        commandHash: `sha256:${"c".repeat(64)}`,
      },
      async () => ({}),
    ),
    (error) => error.code === "IDEMPOTENCY_CONFLICT",
  );
});

test("the PostgreSQL adapter rejects an unsafe schema identifier", () => {
  assert.throws(
    () =>
      createPostgresTenantStore({
        pool: { connect() {} },
        schema: "aios_core; DROP SCHEMA public",
      }),
    (error) => error.code === "INVALID_STORE",
  );
});

test("immutable creation identity lookups do not lock replay readers", async () => {
  const { pool, queries } = scriptedPool((sql) => {
    if (sql.includes("SELECT command_hash")) {
      return { rows: [], rowCount: 0 };
    }
    return { rows: [], rowCount: 1 };
  });
  const store = createPostgresTenantStore({ pool });
  await store.runCommand(
    {
      idempotencyKey: "postgres-read-only-identity",
      commandHash: `sha256:${"d".repeat(64)}`,
    },
    async (transaction) => {
      await transaction.findTenantByCreationKey("p1:synthetic");
      await transaction.findTenantByOrigin({
        fixtureId: "synthetic-fixture",
        sha256: `sha256:${"e".repeat(64)}`,
      });
      return { tenantId: "stn_read_only" };
    },
  );

  const identityLookups = queries.filter(
    ({ sql }) =>
      sql.includes("WHERE creation_key = $1") ||
      sql.includes("WHERE origin_ref = $1"),
  );
  assert.equal(identityLookups.length, 2);
  for (const { sql } of identityLookups) {
    assert.doesNotMatch(sql, /FOR UPDATE/);
  }
});

test("outbox completion is bound to the exact worker and lease version", async () => {
  const { pool, queries } = scriptedPool(() => ({
    rows: [],
    rowCount: 1,
  }));
  const store = createPostgresTenantStore({ pool });
  await store.completeOutbox({
    eventId: "evt_contract",
    workerId: "worker_contract_001",
    leaseVersion: 7,
  });

  const update = queries.find(({ sql }) =>
    sql.includes("status = 'PUBLISHED'"),
  );
  assert.ok(update);
  assert.match(update.sql, /leased_by = \$2/);
  assert.match(update.sql, /lease_version = \$3/);
  assert.match(update.sql, /lease_until >= now\(\)/);
  assert.deepEqual(update.parameters, [
    "evt_contract",
    "worker_contract_001",
    7,
  ]);
});

test("outbox claims reject unbounded leases before touching PostgreSQL", async () => {
  const store = createPostgresTenantStore({
    pool: {
      async connect() {
        throw new Error("must not connect for invalid input");
      },
    },
  });

  await assert.rejects(
    store.claimOutbox({
      workerId: "worker_contract",
      limit: 1,
      leaseSeconds: 301,
    }),
    (error) => error.code === "INVALID_COMMAND",
  );
});

test("outbox claims use a database-bounded duration and incremented lease version", async () => {
  const event = {
    specversion: "1.0",
    id: "evt_claim",
    data: {},
  };
  const { pool, queries } = scriptedPool((sql) => {
    if (sql.includes("RETURNING outbox.event_id")) {
      return {
        rows: [
          {
            event_id: "evt_claim",
            lease_version: "4",
            event,
          },
        ],
        rowCount: 1,
      };
    }
    return { rows: [], rowCount: 1 };
  });
  const store = createPostgresTenantStore({ pool });
  const claimed = await store.claimOutbox({
    workerId: "worker_claim",
    limit: 5,
    leaseSeconds: 30,
  });

  assert.deepEqual(claimed, [
    {
      eventId: "evt_claim",
      workerId: "worker_claim",
      leaseVersion: 4,
      event,
    },
  ]);
  const claimQuery = queries.find(({ sql }) =>
    sql.includes("lease_version = lease_version + 1"),
  );
  assert.ok(claimQuery);
  assert.match(
    claimQuery.sql,
    /now\(\) \+ \(\$3::integer \* interval '1 second'\)/,
  );
  assert.deepEqual(claimQuery.parameters, [5, "worker_claim", 30]);
});

test("PostgreSQL connection failures expose only a stable store error", async () => {
  const store = createPostgresTenantStore({
    pool: {
      async connect() {
        throw new Error("password=must-not-escape");
      },
    },
  });

  await assert.rejects(
    store.readTenantSnapshot("stn_missing"),
    (error) =>
      error.code === "STORE_UNAVAILABLE" &&
      !error.message.includes("password"),
  );
});
