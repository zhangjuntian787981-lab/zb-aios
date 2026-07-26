import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import pg from "pg";
import { createPostgresTenantDataAdapter } from "../../lib/postgres-tenant-data-adapter.mjs";
import { createPostgresTenantStore } from "../../lib/postgres-tenant-store.mjs";
import { createC03TenantLifecycleVerifier } from "../../lib/tenant-data-boundary.mjs";
import { createC07OperationCatalog } from "../../lib/c07-operation-catalog.mjs";

const { Pool } = pg;
const migrationUrls = [
  "../../implementation/p1/c03/postgresql/0001_tenant_registry.sql",
  "../../implementation/p1/c07/postgresql/0011_tenant_data_isolation.sql",
  "../../implementation/p1/c07/postgresql/0012_tenant_data_runtime_roles.sql",
].map((path) => new URL(path, import.meta.url));
const migrations = await Promise.all(
  migrationUrls.map((url) => readFile(url, "utf8")),
);
const catalog = createC07OperationCatalog(
  JSON.parse(
    await readFile(
      new URL(
        "../../implementation/p1/c07/operation-catalog.v1.json",
        import.meta.url,
      ),
      "utf8",
    ),
  ),
);

const TENANTS = [
  {
    tenantId: "stn_01984910-1000-7000-8000-000000000001",
    namespaceId: "sns_01984910-1000-7000-8000-000000000011",
    operationId: "op_01984910-1000-7000-8000-000000000021",
    fixtureId: "synthetic-tenant-blue-harbor-tools",
  },
  {
    tenantId: "stn_01984910-1000-7000-8000-000000000002",
    namespaceId: "sns_01984910-1000-7000-8000-000000000012",
    operationId: "op_01984910-1000-7000-8000-000000000022",
    fixtureId: "synthetic-tenant-cedar-field-components",
  },
  {
    tenantId: "stn_01984910-1000-7000-8000-000000000003",
    namespaceId: "sns_01984910-1000-7000-8000-000000000013",
    operationId: "op_01984910-1000-7000-8000-000000000023",
    fixtureId: "synthetic-tenant-northstar-fasteners",
  },
];
const DATA_LOGIN = "c07_test_data_login";
const SCOPE_LOGIN = "c07_test_scope_login";
const LIFECYCLE_LOGIN = "c07_test_lifecycle_login";
const COMBINED_LOGIN = "c07_test_combined_login";
const PROJECTIONS = [
  "AUTHORIZATION",
  "IDENTITY",
  "KNOWLEDGE",
  "SECRET_REFS",
  "STORAGE",
];

function config(user = process.env.C07_TEST_PGUSER, max = 4) {
  if (process.env.C07_TEST_EPHEMERAL !== "1") {
    throw new Error("C07_TEST_EPHEMERAL=1 is required.");
  }
  for (const name of [
    "C07_TEST_PGHOST",
    "C07_TEST_PGPORT",
    "C07_TEST_PGDATABASE",
    "C07_TEST_PGUSER",
  ]) {
    if (!process.env[name]) throw new Error(`${name} is required.`);
  }
  return {
    host: process.env.C07_TEST_PGHOST,
    port: Number(process.env.C07_TEST_PGPORT),
    database: process.env.C07_TEST_PGDATABASE,
    user,
    max,
  };
}

function lifecycleEvent({
  tenant,
  suffix,
  type,
  version,
  generation,
  state,
  operationId = tenant.operationId,
}) {
  return {
    specversion: "1.0",
    id: `evt-${tenant.fixtureId}-${suffix}`,
    source: "/aios-core/tenant-registry",
    type,
    subject: tenant.tenantId,
    time: `2026-07-26T10:0${Math.min(version, 9)}:00.000Z`,
    datacontenttype: "application/json",
    tenantkind: "SYNTHETIC",
    correlationid: `c07-${tenant.fixtureId}-${suffix}`,
    synthetic: true,
    data: {
      tenant_id: tenant.tenantId,
      lifecycle_version: version,
      generation,
      operation_id: operationId,
      state,
      actor_id: "prn_01984910-1000-7000-8000-000000000099",
    },
  };
}

function scope(tenant, lifecycleVersion = 2) {
  return {
    trustSource: "C07_VERIFIED_TENANT_SCOPE",
    tenantId: tenant.tenantId,
    tenantKind: "SYNTHETIC",
    lifecycleVersion,
    correlationId: `c07-runtime-${tenant.fixtureId}`,
    decisionId: `azd-c07-${tenant.fixtureId}`,
    evidenceRef: `evidence://c07/${tenant.fixtureId}`,
    policyVersion: "c07-synthetic-policy-v1",
  };
}

function operation(id, resourceId, input) {
  return {
    ...catalog.resolve(id),
    resourceId,
    input,
  };
}

async function waitForSleepingWrite(adminPool) {
  for (let attempt = 0; attempt < 100; attempt += 1) {
    const result = await adminPool.query(
      `SELECT count(*)::integer AS count
         FROM pg_stat_activity
        WHERE datname = current_database()
          AND usename = $1
          AND wait_event = 'PgSleep'`,
      [DATA_LOGIN],
    );
    if (result.rows[0].count === 1) return;
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  throw new Error("C07 delayed write did not reach the fenced section.");
}

async function seedTenant(adminPool, tenant, index) {
  const time = `2026-07-26T09:0${index}:00.000Z`;
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
       $1, 'SYNTHETIC', 'PROVISIONING', 1, 1, $2, $3, $4,
       '[]'::jsonb, $5, $6, $7, $7
     )`,
    [
      tenant.tenantId,
      `creation-${tenant.fixtureId}`,
      `fixture://${tenant.fixtureId}`,
      `sha256:${String(index + 1).repeat(64)}`,
      tenant.namespaceId,
      tenant.operationId,
      time,
    ],
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
         source_event_id,
         updated_at
       ) VALUES ($1, 1, $2, 'PROVISION', 'READY', 1, $3, $4)`,
      [
        tenant.tenantId,
        projection,
        `seed-${index}-${projection.toLowerCase()}`,
        time,
      ],
    );
  }
}

async function setRegistryActive(adminPool, tenant) {
  await adminPool.query(
    `UPDATE aios_core.tenant_registry
        SET state = 'ACTIVE',
            lifecycle_version = 2,
            updated_at = '2026-07-26T10:02:00.000Z'
      WHERE tenant_id = $1`,
    [tenant.tenantId],
  );
}

async function recordC03Event(adminPool, event) {
  await adminPool.query(
    `WITH lifecycle AS (
       INSERT INTO aios_core.tenant_lifecycle_event (
         event_id, tenant_id, tenant_kind, event, created_at
       ) VALUES ($1, $2, 'SYNTHETIC', $3::jsonb, $4)
       RETURNING event_id, tenant_id, tenant_kind, event, created_at
     )
     INSERT INTO aios_core.tenant_outbox (
       event_id, tenant_id, tenant_kind, event, created_at
     )
     SELECT event_id, tenant_id, tenant_kind, event, created_at
       FROM lifecycle`,
    [event.id, event.subject, JSON.stringify(event), event.time],
  );
}

async function initialize() {
  const adminPool = new Pool(config());
  for (const migration of migrations) await adminPool.query(migration);
  await adminPool.query(`CREATE ROLE ${DATA_LOGIN} LOGIN`);
  await adminPool.query(`CREATE ROLE ${SCOPE_LOGIN} LOGIN`);
  await adminPool.query(`CREATE ROLE ${LIFECYCLE_LOGIN} LOGIN`);
  await adminPool.query(`CREATE ROLE ${COMBINED_LOGIN} LOGIN`);
  await adminPool.query(
    `GRANT aios_c07_data_runtime TO ${DATA_LOGIN};
     GRANT aios_c07_scope_runtime TO ${SCOPE_LOGIN};
     GRANT aios_c07_lifecycle_runtime TO ${LIFECYCLE_LOGIN};
     GRANT aios_c07_data_runtime, aios_c07_scope_runtime
       TO ${COMBINED_LOGIN};`,
  );
  for (const [index, tenant] of TENANTS.entries()) {
    await seedTenant(adminPool, tenant, index);
  }
  const runtimePool = new Pool(config(DATA_LOGIN, 1));
  const scopePool = new Pool(config(SCOPE_LOGIN, 2));
  const lifecyclePool = new Pool(config(LIFECYCLE_LOGIN, 2));
  const combinedPool = new Pool(config(COMBINED_LOGIN, 1));
  const adapter = createPostgresTenantDataAdapter({
    runtimePool,
    scopePool,
    lifecyclePool,
    controlPool: lifecyclePool,
  });
  const lifecycleVerifier = createC03TenantLifecycleVerifier({
    tenantStore: createPostgresTenantStore({ pool: adminPool }),
  });
  for (const tenant of TENANTS) {
    const provisioning = lifecycleEvent({
      tenant,
      suffix: "provision",
      type: "product.tenant.provisioning-requested.v1",
      version: 1,
      generation: 1,
      state: "PROVISIONING",
    });
    await recordC03Event(adminPool, provisioning);
    await lifecycleVerifier.verify(provisioning);
    await adapter.project(provisioning);
    await setRegistryActive(adminPool, tenant);
    const active = lifecycleEvent({
      tenant,
      suffix: "active",
      type: "product.tenant.activated.v1",
      version: 2,
      generation: 1,
      state: "ACTIVE",
    });
    await recordC03Event(adminPool, active);
    await lifecycleVerifier.verify(active);
    await adapter.project(active);
  }
  return {
    adapter,
    adminPool,
    combinedPool,
    lifecyclePool,
    runtimePool,
    scopePool,
  };
}

test("C07 PostgreSQL 17.10 isolation matrix", async (t) => {
  const {
    adapter,
    adminPool,
    combinedPool,
    lifecyclePool,
    runtimePool,
    scopePool,
  } =
    await initialize();
  t.after(async () => {
    await Promise.all([
      runtimePool.end(),
      scopePool.end(),
      combinedPool.end(),
      lifecyclePool.end(),
      adminPool.end(),
    ]);
  });
  const [tenantA, tenantB, tenantC] = TENANTS;

  await adapter.execute(
    scope(tenantA),
    operation("SQL_PUT", "record_a", {
      resourceId: "record_a",
      value: { owner: "A", synthetic: true },
    }),
  );
  await adapter.execute(
    scope(tenantB),
    operation("SQL_PUT", "record_b", {
      resourceId: "record_b",
      value: { owner: "B", synthetic: true },
    }),
  );
  await adapter.execute(
    scope(tenantC),
    operation("SQL_PUT", "record_c", {
      resourceId: "record_c",
      value: { owner: "C", synthetic: true },
    }),
  );
  assert.equal(
    (
      await adapter.execute(
        scope(tenantA),
        operation("SQL_GET", "record_a", { resourceId: "record_a" }),
      )
    ).value.owner,
    "A",
  );
  assert.equal(
    await adapter.execute(
      scope(tenantA),
      operation("SQL_GET", "record_b", { resourceId: "record_b" }),
    ),
    null,
  );
  const unsafeAdapter = createPostgresTenantDataAdapter({
    runtimePool: adminPool,
    scopePool,
    lifecyclePool,
  });
  await assert.rejects(
    unsafeAdapter.execute(
      scope(tenantA),
      operation("SQL_GET", "record_a", { resourceId: "record_a" }),
    ),
    { code: "INVALID_CONFIGURATION" },
  );
  const combinedAdapter = createPostgresTenantDataAdapter({
    runtimePool: combinedPool,
    scopePool,
    lifecyclePool,
  });
  await assert.rejects(
    combinedAdapter.execute(
      scope(tenantA),
      operation("SQL_GET", "record_a", { resourceId: "record_a" }),
    ),
    { code: "INVALID_CONFIGURATION" },
  );
  assert.throws(
    () =>
      createPostgresTenantDataAdapter({
        runtimePool,
        scopePool,
        lifecyclePool: scopePool,
      }),
    { code: "INVALID_CONFIGURATION" },
  );
  const falseRestoreAdapter = createPostgresTenantDataAdapter({
    runtimePool,
    scopePool,
    lifecyclePool,
    readOnly: true,
  });
  await assert.rejects(
    falseRestoreAdapter.execute(
      scope(tenantA),
      operation("SQL_GET", "record_a", { resourceId: "record_a" }),
    ),
    { code: "INVALID_CONFIGURATION" },
  );

  await adapter.execute(
    scope(tenantA),
    operation("VECTOR_UPSERT", "vector_a", {
      resourceId: "vector_a",
      embedding: [1, 0, 0],
      metadata: { owner: "A" },
    }),
  );
  await adapter.execute(
    scope(tenantB),
    operation("VECTOR_UPSERT", "vector_b", {
      resourceId: "vector_b",
      embedding: [0, 1, 0],
      metadata: { owner: "B" },
    }),
  );
  const vectors = await adapter.execute(
    scope(tenantA),
    operation("VECTOR_SEARCH", "vector_collection", {
      embedding: [0, 1, 0],
      limit: 10,
    }),
  );
  assert.deepEqual(
    vectors.map(({ resourceId }) => resourceId),
    ["vector_a"],
  );

  await adapter.execute(
    scope(tenantA),
    operation("SEARCH_INDEX", "search_a", {
      resourceId: "search_a",
      text: "needle synthetic",
      metadata: { owner: "A" },
    }),
  );
  await adapter.execute(
    scope(tenantB),
    operation("SEARCH_INDEX", "search_b", {
      resourceId: "search_b",
      text: "needle needle needle synthetic",
      metadata: { owner: "B" },
    }),
  );
  const search = await adapter.execute(
    scope(tenantA),
    operation("SEARCH_QUERY", "search_collection", {
      query: "needle",
      limit: 10,
    }),
  );
  assert.deepEqual(
    search.map(({ resourceId }) => resourceId),
    ["search_a"],
  );

  for (const [tenant, owner] of [
    [tenantA, "A"],
    [tenantB, "B"],
  ]) {
    await adapter.execute(
      scope(tenant),
      operation("CACHE_PUT", "cache_collection", {
        cacheKey: "same-logical-key",
        value: { owner },
        ttlSeconds: 3600,
      }),
    );
  }
  assert.equal(
    (
      await adapter.execute(
        scope(tenantA),
        operation("CACHE_GET", "cache_collection", {
          cacheKey: "same-logical-key",
        }),
      )
    ).value.owner,
    "A",
  );

  const direct = await runtimePool.connect();
  try {
    await direct.query("BEGIN");
    await direct.query(
      `SELECT set_config('aios.tenant_id', $1, true),
              set_config('aios.tenant_kind', 'SYNTHETIC', true),
              set_config('aios.lifecycle_version', '2', true),
              set_config('aios.correlation_id', 'c07-direct', true)`,
      [tenantA.tenantId],
    );
    const rows = await direct.query(
      `SELECT tenant_id, resource_id
         FROM aios_data.tenant_sql_record
        ORDER BY resource_id`,
    );
    assert.deepEqual(rows.rows, []);
    await assert.rejects(
      direct.query(
        `INSERT INTO aios_data.tenant_sql_record (
           tenant_id, tenant_kind, resource_id, value
         ) VALUES ($1, 'SYNTHETIC', 'cross_write', '{}'::jsonb)`,
        [tenantB.tenantId],
      ),
      (error) => error?.code === "42501",
    );
    await direct.query("ROLLBACK");

    const cleared = await direct.query(
      `SELECT current_setting('aios.tenant_id', true) AS tenant_id`,
    );
    assert.equal(["", null].includes(cleared.rows[0].tenant_id), true);
    const withoutScope = await direct.query(
      `SELECT count(*)::integer AS count
         FROM aios_data.tenant_sql_record`,
    );
    assert.equal(withoutScope.rows[0].count, 0);
  } finally {
    direct.release();
  }

  await assert.rejects(
    adapter.execute(
      scope(tenantA),
      operation("VECTOR_UPSERT", "invalid_vector", {
        resourceId: "invalid_vector",
        embedding: [Number.NaN],
        metadata: {},
      }),
    ),
    { code: "INVALID_INPUT" },
  );
  assert.equal(
    (
      await adapter.execute(
        scope(tenantB),
        operation("SQL_GET", "record_b", { resourceId: "record_b" }),
      )
    ).value.owner,
    "B",
  );

  await adminPool.query(
    `UPDATE aios_core.tenant_registry
        SET state = 'SUSPENDED',
            lifecycle_version = 3,
            updated_at = '2026-07-26T10:03:00.000Z'
      WHERE tenant_id = $1`,
    [tenantA.tenantId],
  );
  const suspended = lifecycleEvent({
    tenant: tenantA,
    suffix: "suspend",
    type: "product.tenant.suspended.v1",
    version: 3,
    generation: 1,
    state: "SUSPENDED",
  });
  await recordC03Event(adminPool, suspended);
  const firstSuspension = await adapter.project(suspended);
  const repeatedSuspension = await adapter.project(suspended);
  assert.equal(firstSuspension.duplicate, false);
  assert.equal(repeatedSuspension.duplicate, true);
  const suspendedSnapshot = await adapter.snapshot({
    tenantId: tenantA.tenantId,
  });
  assert.equal(suspendedSnapshot.state, "SUSPENDED");
  assert.equal(suspendedSnapshot.cacheCount, 0);

  const deleteOperation =
    "op_01984910-1000-7000-8000-000000000032";
  await adminPool.query(
    `UPDATE aios_core.tenant_registry
        SET state = 'DELETING',
            lifecycle_version = 3,
            generation = 2,
            operation_id = $2,
            updated_at = '2026-07-26T10:03:30.000Z'
      WHERE tenant_id = $1`,
    [tenantB.tenantId, deleteOperation],
  );
  const deletion = lifecycleEvent({
    tenant: tenantB,
    suffix: "delete",
    type: "product.tenant.deletion-requested.v1",
    version: 3,
    generation: 2,
    state: "DELETING",
    operationId: deleteOperation,
  });
  await recordC03Event(adminPool, deletion);
  await adapter.project(deletion);
  const deletedSnapshot = await adapter.snapshot({
    tenantId: tenantB.tenantId,
  });
  assert.deepEqual(
    {
      state: deletedSnapshot.state,
      recordCount: deletedSnapshot.recordCount,
      vectorCount: deletedSnapshot.vectorCount,
      searchCount: deletedSnapshot.searchCount,
      cacheCount: deletedSnapshot.cacheCount,
    },
    {
      state: "DELETING",
      recordCount: 0,
      vectorCount: 0,
      searchCount: 0,
      cacheCount: 0,
    },
  );

  await assert.rejects(
    adapter.project(
      lifecycleEvent({
        tenant: tenantC,
        suffix: "gap",
        type: "product.tenant.suspended.v1",
        version: 4,
        generation: 1,
        state: "SUSPENDED",
      }),
    ),
    { code: "STALE_LIFECYCLE_EVENT" },
  );

  await adminPool.query(
    `CREATE FUNCTION aios_data.c07_test_delay_write()
     RETURNS trigger
     LANGUAGE plpgsql
     SECURITY DEFINER
     SET search_path = pg_catalog
     AS $$
     BEGIN
       PERFORM pg_sleep(0.25);
       RETURN NEW;
     END
     $$;
     CREATE TRIGGER c07_test_delay_write
       BEFORE INSERT ON aios_data.tenant_sql_record
       FOR EACH ROW
       WHEN (NEW.resource_id = 'race_record')
       EXECUTE FUNCTION aios_data.c07_test_delay_write();`,
  );
  const racedWrite = adapter.execute(
    scope(tenantC),
    operation("SQL_PUT", "race_record", {
      resourceId: "race_record",
      value: { mustBePurged: true },
    }),
  );
  await waitForSleepingWrite(adminPool);

  const racedDeleteOperation =
    "op_01984910-1000-7000-8000-000000000033";
  await adminPool.query(
    `UPDATE aios_core.tenant_registry
        SET state = 'DELETING',
            lifecycle_version = 3,
            generation = 2,
            operation_id = $2,
            updated_at = '2026-07-26T10:04:00.000Z'
      WHERE tenant_id = $1`,
    [tenantC.tenantId, racedDeleteOperation],
  );
  const racedDeletionEvent = lifecycleEvent({
    tenant: tenantC,
    suffix: "race-delete",
    type: "product.tenant.deletion-requested.v1",
    version: 3,
    generation: 2,
    state: "DELETING",
    operationId: racedDeleteOperation,
  });
  await recordC03Event(adminPool, racedDeletionEvent);
  const racedDeletion = adapter.project(racedDeletionEvent);
  await Promise.all([racedWrite, racedDeletion]);
  const racedSnapshot = await adapter.snapshot({
    tenantId: tenantC.tenantId,
  });
  assert.deepEqual(
    {
      state: racedSnapshot.state,
      recordCount: racedSnapshot.recordCount,
      vectorCount: racedSnapshot.vectorCount,
      searchCount: racedSnapshot.searchCount,
      cacheCount: racedSnapshot.cacheCount,
    },
    {
      state: "DELETING",
      recordCount: 0,
      vectorCount: 0,
      searchCount: 0,
      cacheCount: 0,
    },
  );
});
