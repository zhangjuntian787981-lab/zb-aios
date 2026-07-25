import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import test from "node:test";
import pg from "pg";
import { createPostgresTenantStore } from "../../lib/postgres-tenant-store.mjs";
import {
  createSyntheticFixtureCatalog,
  createTenantRegistry,
} from "../../lib/tenant-registry.mjs";

const { Pool } = pg;
const migrationUrl = new URL(
  "../../implementation/p1/c03/postgresql/0001_tenant_registry.sql",
  import.meta.url,
);
const migrationSql = await readFile(migrationUrl, "utf8");
const migrationSha256 = `sha256:${createHash("sha256")
  .update(migrationSql)
  .digest("hex")}`;
const expectedMigrationSha256 =
  "sha256:ef8dc0bcebec22ed1dd76f2e3c6839db383b6f2cf6f98de324835514d610e997";
const projections = [
  "AUTHORIZATION",
  "IDENTITY",
  "KNOWLEDGE",
  "SECRET_REFS",
  "STORAGE",
];
const fixtures = [
  {
    fixtureId: "synthetic-tenant-northstar-fasteners",
    sha256:
      "sha256:12693f1bed92c45128e0774ee1ea6c71b63a7edad0eff43cb988e79b6771db26",
    seedId: "SYNTHETIC-SEED-001",
  },
  {
    fixtureId: "synthetic-tenant-blue-harbor-tools",
    sha256:
      "sha256:3408b088ec3d39515e50254ba27ce029f868c38afdac4f903f9bc106915c67e8",
    seedId: "SYNTHETIC-SEED-002",
  },
  {
    fixtureId: "synthetic-tenant-cedar-field-components",
    sha256:
      "sha256:eab6b0bdb40da7f63b732bf64f141d1b8cc3b6d0f989b034e2ccfadcb5418619",
    seedId: "SYNTHETIC-SEED-003",
  },
];
const operator = {
  actorId: "syn_prn_pg_operator",
  capabilities: ["TENANT_LIFECYCLE_MANAGE", "TENANT_LIFECYCLE_READ"],
  synthetic: true,
};
const projectionWorker = {
  actorId: "syn_svc_pg_projection_worker",
  capabilities: ["TENANT_PROJECTION_REPORT"],
  synthetic: true,
};
const reconciler = {
  actorId: "syn_svc_pg_reconciler",
  capabilities: ["TENANT_RECONCILE"],
  synthetic: true,
};

function postgresConfig() {
  if (process.env.C03_TEST_EPHEMERAL !== "1") {
    throw new Error("C03_TEST_EPHEMERAL=1 is required.");
  }
  if (process.env.C03_TEST_DATABASE_URL) {
    return {
      connectionString: process.env.C03_TEST_DATABASE_URL,
      max: 40,
    };
  }
  const required = [
    "C03_TEST_PGHOST",
    "C03_TEST_PGPORT",
    "C03_TEST_PGDATABASE",
    "C03_TEST_PGUSER",
  ];
  for (const name of required) {
    if (!process.env[name]) {
      throw new Error(`${name} is required.`);
    }
  }
  return {
    host: process.env.C03_TEST_PGHOST,
    port: Number(process.env.C03_TEST_PGPORT),
    database: process.env.C03_TEST_PGDATABASE,
    user: process.env.C03_TEST_PGUSER,
    password: process.env.C03_TEST_PGPASSWORD,
    max: 40,
  };
}

const pool = new Pool(postgresConfig());

function registryFor(storePool = pool) {
  const store = createPostgresTenantStore({ pool: storePool });
  const registry = createTenantRegistry({
    store,
    fixtureCatalog: createSyntheticFixtureCatalog(
      fixtures.map((fixture) => ({
        fixtureId: fixture.fixtureId,
        sha256: fixture.sha256,
        allowedConfigRefs: [`fixture://${fixture.seedId}`],
      })),
    ),
    authorize: (context, capability) =>
      context?.synthetic === true &&
      context.capabilities?.includes(capability) === true,
  });
  return { registry, store };
}

function createCommand(fixture, overrides = {}) {
  return {
    kind: "CREATE_SYNTHETIC_TENANT",
    idempotencyKey: `pg-create-${fixture.seedId}`,
    creationKey: `p1:${fixture.seedId}:pg`,
    fixtureRef: {
      fixtureId: fixture.fixtureId,
      sha256: fixture.sha256,
    },
    configRefs: [`fixture://${fixture.seedId}`],
    correlationId: `pg-${fixture.seedId}`,
    ...overrides,
  };
}

async function resetDatabase() {
  await pool.query("DROP SCHEMA IF EXISTS aios_core CASCADE");
  await pool.query(migrationSql);
}

async function counts() {
  const result = await pool.query(`
    SELECT
      (SELECT count(*) FROM aios_core.tenant_registry) AS tenants,
      (SELECT count(*) FROM aios_core.tenant_projection) AS projections,
      (SELECT count(*) FROM aios_core.tenant_lifecycle_event) AS lifecycle,
      (SELECT count(*) FROM aios_core.tenant_outbox) AS outbox,
      (SELECT count(*) FROM aios_core.tenant_command_receipt) AS receipts
  `);
  return Object.fromEntries(
    Object.entries(result.rows[0]).map(([key, value]) => [key, Number(value)]),
  );
}

function assertDatabaseError(expectedCode) {
  return (error) => {
    assert.equal(error.code, expectedCode);
    return true;
  };
}

function delayedTenantLockPool() {
  let delayNextLock = true;
  let serializationFailures = 0;
  return {
    get serializationFailures() {
      return serializationFailures;
    },
    async connect() {
      const client = await pool.connect();
      return {
        async query(sql, parameters = []) {
          try {
            const result = await client.query(sql, parameters);
            if (
              delayNextLock &&
              typeof sql === "string" &&
              sql.includes("WHERE tenant_id = $1") &&
              sql.includes("FOR UPDATE")
            ) {
              delayNextLock = false;
              await new Promise((resolve) => setTimeout(resolve, 200));
            }
            return result;
          } catch (error) {
            if (error.code === "40001") serializationFailures += 1;
            throw error;
          }
        },
        release() {
          client.release();
        },
      };
    },
  };
}

function crashBeforeCommitPool() {
  let terminated = false;
  return {
    async connect() {
      const client = await pool.connect();
      const backend = await client.query("SELECT pg_backend_pid() AS pid");
      const backendPid = backend.rows[0].pid;
      return {
        async query(sql, parameters = []) {
          const result = await client.query(sql, parameters);
          if (
            !terminated &&
            typeof sql === "string" &&
            sql.includes('INSERT INTO "aios_core"."tenant_command_receipt"')
          ) {
            terminated = true;
            const connectionEnded = new Promise((resolve) => {
              client.once("error", resolve);
            });
            const killed = await pool.query(
              "SELECT pg_terminate_backend($1) AS killed",
              [backendPid],
            );
            assert.equal(killed.rows[0].killed, true);
            await connectionEnded;
          }
          return result;
        },
        release() {
          client.release();
        },
      };
    },
  };
}

async function completeDeletion(registry, deleting) {
  for (const [index, projection] of projections.entries()) {
    await registry.execute(projectionWorker, {
      kind: "RECORD_PROJECTION_RESULT",
      idempotencyKey: `pg-delete-${projection}`,
      tenantId: deleting.tenantId,
      generation: deleting.generation,
      operationId: deleting.operationId,
      projection,
      outcome: "SUCCEEDED",
      attempt: 1,
      sourceEventId: `pg-delete-source-${index + 1}`,
      correlationId: "pg-delete-tenant",
    });
  }
  return registry.execute(reconciler, {
    kind: "RECONCILE_TENANT",
    idempotencyKey: "pg-delete-reconcile",
    tenantId: deleting.tenantId,
    correlationId: "pg-delete-tenant",
  });
}

test("C03 passes real PostgreSQL 17 runtime verification", async (t) => {
  t.after(async () => {
    await pool.end();
  });

  const safety = await pool.query(
    "SELECT current_database() AS database, to_regnamespace('aios_core') AS schema",
  );
  assert.match(safety.rows[0].database, /^c03_test_[0-9]+$/);
  assert.equal(safety.rows[0].schema, null);

  await t.test("PG-01 executes the exact migration on an empty database", async () => {
    assert.equal(migrationSha256, expectedMigrationSha256);
    await pool.query(migrationSql);

    const version = await pool.query("SHOW server_version_num");
    const versionNumber = Number(version.rows[0].server_version_num);
    assert.ok(versionNumber >= 170000 && versionNumber < 180000);

    const tables = await pool.query(`
      SELECT table_name
        FROM information_schema.tables
       WHERE table_schema = 'aios_core'
       ORDER BY table_name
    `);
    assert.deepEqual(
      tables.rows.map(({ table_name }) => table_name),
      [
        "tenant_command_receipt",
        "tenant_lifecycle_event",
        "tenant_outbox",
        "tenant_projection",
        "tenant_registry",
      ],
    );

    const triggers = await pool.query(`
      SELECT DISTINCT trigger_name
        FROM information_schema.triggers
       WHERE trigger_schema = 'aios_core'
       ORDER BY trigger_name
    `);
    assert.deepEqual(
      triggers.rows.map(({ trigger_name }) => trigger_name),
      [
        "tenant_command_receipt_no_update",
        "tenant_lifecycle_event_no_update",
        "tenant_registry_identity_immutable",
        "tenant_registry_initial_state_guard",
        "tenant_registry_lifecycle_guard",
        "tenant_registry_no_delete",
      ],
    );
    t.diagnostic(
      `PostgreSQL ${versionNumber}; migration ${migrationSha256}`,
    );
  });

  await t.test("PG-02A replays 32 identical commands as one tenant", async () => {
    await resetDatabase();
    const { registry } = registryFor();
    const command = createCommand(fixtures[1]);
    const settled = await Promise.allSettled(
      Array.from({ length: 32 }, () => registry.execute(operator, command)),
    );
    assert.equal(
      settled.filter(({ status }) => status === "rejected").length,
      0,
    );
    const results = settled.map(({ value }) => value);

    assert.equal(new Set(results.map(({ tenantId }) => tenantId)).size, 1);
    assert.equal(results.filter(({ duplicate }) => !duplicate).length, 1);
    assert.deepEqual(await counts(), {
      tenants: 1,
      projections: 5,
      lifecycle: 1,
      outbox: 1,
      receipts: 1,
    });
  });

  await t.test("PG-02B creation identity survives 32 distinct retry keys", async () => {
    await resetDatabase();
    const { registry } = registryFor();
    const settled = await Promise.allSettled(
      Array.from({ length: 32 }, (_, index) =>
        registry.execute(
          operator,
          createCommand(fixtures[2], {
            idempotencyKey: `pg-create-cedar-${index + 1}`,
          }),
        ),
      ),
    );
    assert.equal(
      settled.filter(({ status }) => status === "rejected").length,
      0,
    );
    const results = settled.map(({ value }) => value);

    assert.equal(new Set(results.map(({ tenantId }) => tenantId)).size, 1);
    assert.equal(
      new Set(results.map(({ resourceNamespaceId }) => resourceNamespaceId))
        .size,
      1,
    );
    assert.equal(results.filter(({ duplicate }) => !duplicate).length, 1);
    assert.deepEqual(await counts(), {
      tenants: 1,
      projections: 5,
      lifecycle: 1,
      outbox: 1,
      receipts: 32,
    });
  });

  await t.test("PG-02C serializable contention retries and closes stale writes", async () => {
    await resetDatabase();
    const contentionPool = delayedTenantLockPool();
    const { registry } = registryFor(contentionPool);
    const created = await registry.execute(
      operator,
      createCommand(fixtures[0]),
    );
    const results = await Promise.allSettled([
      registry.execute(operator, {
        kind: "SUSPEND_TENANT",
        idempotencyKey: "pg-suspend-a",
        tenantId: created.tenantId,
        expectedVersion: created.lifecycleVersion,
        reasonRef: "policy://suspend-a",
        correlationId: "pg-suspend-race",
      }),
      registry.execute(operator, {
        kind: "SUSPEND_TENANT",
        idempotencyKey: "pg-suspend-b",
        tenantId: created.tenantId,
        expectedVersion: created.lifecycleVersion,
        reasonRef: "policy://suspend-b",
        correlationId: "pg-suspend-race",
      }),
    ]);

    assert.equal(results.filter(({ status }) => status === "fulfilled").length, 1);
    const rejected = results.find(({ status }) => status === "rejected");
    assert.equal(rejected.reason.code, "STALE_VERSION");
    assert.ok(contentionPool.serializationFailures >= 1);

    const snapshot = await registry.snapshot(operator, created.tenantId);
    assert.equal(snapshot.state, "SUSPENDED");
    assert.equal(snapshot.lifecycleVersion, 2);
  });

  await t.test("PG-03 backend termination rolls back the whole command", async () => {
    await resetDatabase();
    const crashStore = createPostgresTenantStore({
      pool: crashBeforeCommitPool(),
      maxSerializableRetries: 0,
    });
    const crashRegistry = createTenantRegistry({
      store: crashStore,
      fixtureCatalog: createSyntheticFixtureCatalog([
        {
          fixtureId: fixtures[0].fixtureId,
          sha256: fixtures[0].sha256,
          allowedConfigRefs: [`fixture://${fixtures[0].seedId}`],
        },
      ]),
      authorize: (context, capability) =>
        context?.capabilities?.includes(capability) === true,
    });
    const command = createCommand(fixtures[0]);

    await assert.rejects(
      crashRegistry.execute(operator, command),
      (error) => error.code === "STORE_UNAVAILABLE",
    );
    assert.deepEqual(await counts(), {
      tenants: 0,
      projections: 0,
      lifecycle: 0,
      outbox: 0,
      receipts: 0,
    });

    const { registry } = registryFor();
    const retried = await registry.execute(operator, command);
    assert.equal(retried.duplicate, false);
    assert.deepEqual(await counts(), {
      tenants: 1,
      projections: 5,
      lifecycle: 1,
      outbox: 1,
      receipts: 1,
    });
  });

  await t.test("PG-04 database guards preserve identity and tombstones", async () => {
    await resetDatabase();
    const { registry } = registryFor();
    const created = await registry.execute(
      operator,
      createCommand(fixtures[0]),
    );
    const original = await pool.query(
      "SELECT * FROM aios_core.tenant_registry WHERE tenant_id = $1",
      [created.tenantId],
    );

    await assert.rejects(
      pool.query(
        `INSERT INTO aios_core.tenant_registry (
           tenant_id, tenant_kind, state, lifecycle_version, generation,
           creation_key, origin_ref, origin_hash, config_refs,
           resource_namespace_id, operation_id, created_at, updated_at
         ) VALUES (
           'stn_01984700-0000-7000-8000-00000000d101',
           'SYNTHETIC', 'ACTIVE', 1, 1, 'pg-invalid-active',
           'fixture://invalid-active', $1, '[]'::jsonb,
           'sns_01984700-0000-7000-8000-00000000d102',
           'op_01984700-0000-7000-8000-00000000d103', now(), now()
         )`,
        [`sha256:${"f".repeat(64)}`],
      ),
      assertDatabaseError("23000"),
    );

    for (const [column, value] of [
      ["tenant_id", "stn_01984700-0000-7000-8000-00000000a101"],
      ["tenant_kind", "ENTERPRISE"],
      ["origin_ref", "fixture://forbidden-origin-change"],
      [
        "resource_namespace_id",
        "sns_01984700-0000-7000-8000-00000000a102",
      ],
    ]) {
      await assert.rejects(
        pool.query(
          `UPDATE aios_core.tenant_registry SET ${column} = $1 WHERE tenant_id = $2`,
          [value, created.tenantId],
        ),
        assertDatabaseError("23000"),
      );
    }

    await assert.rejects(
      pool.query(
        `UPDATE aios_core.tenant_registry
            SET state = 'ACTIVE',
                lifecycle_version = lifecycle_version + 1
          WHERE tenant_id = $1`,
        [created.tenantId],
      ),
      assertDatabaseError("23000"),
    );
    await assert.rejects(
      pool.query(
        `UPDATE aios_core.tenant_command_receipt
            SET result = '{}'::jsonb
          WHERE idempotency_key = $1`,
        [createCommand(fixtures[0]).idempotencyKey],
      ),
      assertDatabaseError("23000"),
    );
    await assert.rejects(
      pool.query(
        `DELETE FROM aios_core.tenant_command_receipt
          WHERE idempotency_key = $1`,
        [createCommand(fixtures[0]).idempotencyKey],
      ),
      assertDatabaseError("23000"),
    );
    await assert.rejects(
      pool.query(
        "DELETE FROM aios_core.tenant_lifecycle_event WHERE tenant_id = $1",
        [created.tenantId],
      ),
      assertDatabaseError("23000"),
    );
    await assert.rejects(
      pool.query(
        `INSERT INTO aios_core.tenant_outbox (
           event_id, tenant_id, tenant_kind, event, created_at
         ) VALUES ($1, $2, 'SYNTHETIC', $3::jsonb, now())`,
        [
          "evt_invalid_data_shape",
          created.tenantId,
          JSON.stringify({
            specversion: "1.0",
            subject: created.tenantId,
            tenantkind: "SYNTHETIC",
            synthetic: true,
            data: "not-an-object",
          }),
        ],
      ),
      assertDatabaseError("23514"),
    );

    const afterRejectedWrites = await pool.query(
      "SELECT * FROM aios_core.tenant_registry WHERE tenant_id = $1",
      [created.tenantId],
    );
    for (const field of [
      "tenant_id",
      "tenant_kind",
      "origin_ref",
      "origin_hash",
      "resource_namespace_id",
      "state",
      "lifecycle_version",
      "generation",
    ]) {
      assert.equal(afterRejectedWrites.rows[0][field], original.rows[0][field]);
    }

    const deleting = await registry.execute(operator, {
      kind: "REQUEST_TENANT_DELETION",
      idempotencyKey: "pg-delete-tenant",
      tenantId: created.tenantId,
      expectedVersion: created.lifecycleVersion,
      reasonRef: "policy://synthetic-delete",
      correlationId: "pg-delete-tenant",
    });
    await assert.rejects(
      pool.query(
        `UPDATE aios_core.tenant_registry
            SET state = 'DELETED',
                lifecycle_version = lifecycle_version + 1
          WHERE tenant_id = $1`,
        [created.tenantId],
      ),
      assertDatabaseError("23000"),
    );
    const deleted = await completeDeletion(registry, deleting);
    assert.equal(deleted.state, "DELETED");
    await assert.rejects(
      pool.query(
        "DELETE FROM aios_core.tenant_registry WHERE tenant_id = $1",
        [created.tenantId],
      ),
      assertDatabaseError("23000"),
    );
    await assert.rejects(
      pool.query(
        `INSERT INTO aios_core.tenant_registry (
           tenant_id, tenant_kind, state, lifecycle_version, generation,
           creation_key, origin_ref, origin_hash, config_refs,
           resource_namespace_id, operation_id, created_at, updated_at
         ) VALUES (
           'stn_01984700-0000-7000-8000-00000000b101',
           'SYNTHETIC', 'PROVISIONING', 1, 1, 'pg-reuse-origin',
           $1, $2, '[]'::jsonb,
           'sns_01984700-0000-7000-8000-00000000b102',
           'op_01984700-0000-7000-8000-00000000b103', now(), now()
         )`,
        [`fixture://${fixtures[0].fixtureId}`, fixtures[0].sha256],
      ),
      assertDatabaseError("23505"),
    );
    await assert.rejects(
      pool.query(
        `INSERT INTO aios_core.tenant_registry (
           tenant_id, tenant_kind, state, lifecycle_version, generation,
           creation_key, origin_ref, origin_hash, config_refs,
           resource_namespace_id, operation_id, created_at, updated_at
         ) VALUES (
           'stn_01984700-0000-7000-8000-00000000c101',
           'SYNTHETIC', 'PROVISIONING', 1, 1, 'pg-reuse-namespace',
           'fixture://new-synthetic-origin',
           $1, '[]'::jsonb, $2,
           'op_01984700-0000-7000-8000-00000000c103', now(), now()
         )`,
        [
          `sha256:${"d".repeat(64)}`,
          original.rows[0].resource_namespace_id,
        ],
      ),
      assertDatabaseError("23505"),
    );
    const tombstone = await pool.query(
      "SELECT state FROM aios_core.tenant_registry WHERE tenant_id = $1",
      [created.tenantId],
    );
    assert.equal(tombstone.rows[0].state, "DELETED");
  });

  await t.test("PG-05 Outbox claims are exclusive and stale leases are fenced", async () => {
    await resetDatabase();
    const { registry, store } = registryFor();
    await registry.execute(operator, createCommand(fixtures[0]));

    const claims = await Promise.all([
      store.claimOutbox({
        workerId: "worker-a",
        limit: 1,
        leaseSeconds: 30,
      }),
      store.claimOutbox({
        workerId: "worker-b",
        limit: 1,
        leaseSeconds: 30,
      }),
    ]);
    assert.equal(claims[0].length + claims[1].length, 1);
    const originalClaim = claims.find(({ length }) => length === 1)[0];
    assert.equal(originalClaim.leaseVersion, 1);
    assert.deepEqual(
      await store.claimOutbox({
        workerId: "worker-waiting",
        limit: 1,
        leaseSeconds: 30,
      }),
      [],
    );

    await pool.query(
      `UPDATE aios_core.tenant_outbox
          SET lease_until = now() - interval '1 second'
        WHERE event_id = $1`,
      [originalClaim.eventId],
    );
    const reclaimed = await store.claimOutbox({
      workerId: "worker-recovery",
      limit: 1,
      leaseSeconds: 30,
    });
    assert.equal(reclaimed.length, 1);
    assert.equal(reclaimed[0].eventId, originalClaim.eventId);
    assert.equal(reclaimed[0].leaseVersion, 2);

    await assert.rejects(
      store.completeOutbox(originalClaim),
      (error) => error.code === "STALE_OUTBOX_LEASE",
    );
    await assert.rejects(
      store.failOutbox({
        ...originalClaim,
        errorCode: "STALE_WORKER",
        retryDelaySeconds: 1,
      }),
      (error) => error.code === "STALE_OUTBOX_LEASE",
    );
    await store.completeOutbox(reclaimed[0]);

    const metadata = await pool.query(
      `SELECT status, attempt_count, lease_version, leased_by, lease_until,
              published_at
         FROM aios_core.tenant_outbox
        WHERE event_id = $1`,
      [originalClaim.eventId],
    );
    assert.equal(metadata.rows[0].status, "PUBLISHED");
    assert.equal(metadata.rows[0].attempt_count, 2);
    assert.equal(Number(metadata.rows[0].lease_version), 2);
    assert.equal(metadata.rows[0].leased_by, null);
    assert.equal(metadata.rows[0].lease_until, null);
    assert.notEqual(metadata.rows[0].published_at, null);
    assert.deepEqual(
      await store.claimOutbox({
        workerId: "worker-after-publish",
        limit: 1,
        leaseSeconds: 30,
      }),
      [],
    );
  });
});
