import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import pg from "pg";
import { createC07OperationCatalog } from "../../lib/c07-operation-catalog.mjs";
import { createFileTenantObjectAdapter } from "../../lib/file-tenant-object-adapter.mjs";
import { createPostgresTenantDataAdapter } from "../../lib/postgres-tenant-data-adapter.mjs";
import { createTenantDataBoundary } from "../../lib/tenant-data-boundary.mjs";

const { Pool } = pg;
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
const RESTORE_LOGIN = "c07_restore_read_login";
const SCOPE_LOGIN = "c07_restore_scope_login";
const TENANT_A = "stn_01984910-3000-7000-8000-000000000001";
const TENANT_B = "stn_01984910-3000-7000-8000-000000000002";
const TENANT_C = "stn_01984910-3000-7000-8000-000000000003";
const TENANTS = [
  { tenantId: TENANT_A, suffix: "a", embedding: [1, 0] },
  { tenantId: TENANT_B, suffix: "b", embedding: [0, 1] },
  { tenantId: TENANT_C, suffix: "c", embedding: [1, 1] },
];
const PRINCIPAL = "prn_01984910-3000-7000-8000-000000000098";
const DELEGATION = "dlg_01984910-3000-7000-8000-000000000097";

function config(user = process.env.C07_RESTORE_TEST_PGUSER, max = 2) {
  if (process.env.C07_RESTORE_TEST_EPHEMERAL !== "1") {
    throw new Error("C07_RESTORE_TEST_EPHEMERAL=1 is required.");
  }
  for (const name of [
    "C07_RESTORE_TEST_PGHOST",
    "C07_RESTORE_TEST_PGPORT",
    "C07_RESTORE_TARGET_DATABASE",
    "C07_RESTORE_TEST_PGUSER",
    "C07_RESTORE_OBJECT_TARGET",
  ]) {
    if (!process.env[name]) throw new Error(`${name} is required.`);
  }
  return {
    host: process.env.C07_RESTORE_TEST_PGHOST,
    port: Number(process.env.C07_RESTORE_TEST_PGPORT),
    database: process.env.C07_RESTORE_TARGET_DATABASE,
    user,
    max,
  };
}

function tracked(adapter, calls) {
  return Object.freeze({
    id: adapter.id,
    paths: adapter.paths,
    async execute(scope, operation) {
      calls.push([adapter.id, operation.operationId, scope.tenantId]);
      return adapter.execute(scope, operation);
    },
    project(event) {
      return adapter.project(event);
    },
    snapshot(query) {
      return adapter.snapshot(query);
    },
  });
}

function context(tenantId, operationId) {
  return {
    synthetic: true,
    routeTrustSource: "VERIFIED_ROUTE_DESCRIPTOR",
    tenantId,
    operationId,
    workloadTrustSource: "VERIFIED_WORKLOAD_CONTEXT",
    workloadActorPrincipalId: PRINCIPAL,
  };
}

function request(resourceId, input) {
  return {
    sessionToken: "c07-restored-session",
    delegationId: DELEGATION,
    resourceId,
    correlationId: `c07-restored-${resourceId}`,
    input,
  };
}

test("C07 backup restores to a read-only isolated endpoint", async (t) => {
  const adminPool = new Pool(config());
  const runtimePool = new Pool(config(RESTORE_LOGIN, 1));
  const scopePool = new Pool(config(SCOPE_LOGIN));
  t.after(async () => {
    await Promise.all([
      runtimePool.end(),
      scopePool.end(),
      adminPool.end(),
    ]);
  });

  const restoredState = await adminPool.query(
    `SELECT
       current_database() AS database,
       current_setting('default_transaction_read_only') AS read_only,
       (
         SELECT extversion
           FROM pg_extension
          WHERE extname = 'vector'
       ) AS vector_version,
       (
         SELECT count(*)::integer
           FROM aios_data.tenant_cache_record
       ) AS cache_count`,
  );
  assert.match(
    restoredState.rows[0].database,
    /^c07_restore_target_[0-9]+$/,
  );
  assert.deepEqual(restoredState.rows[0], {
    database: restoredState.rows[0].database,
    read_only: "on",
    vector_version: "0.8.5",
    cache_count: 0,
  });

  const rls = await adminPool.query(
    `SELECT count(*)::integer AS count
       FROM pg_class AS relation
       JOIN pg_namespace AS namespace
         ON namespace.oid = relation.relnamespace
      WHERE namespace.nspname = 'aios_data'
        AND relation.relname = ANY($1::text[])
        AND relation.relrowsecurity
        AND relation.relforcerowsecurity
        AND pg_get_userbyid(relation.relowner) = 'aios_c07_owner'`,
    [[
      "tenant_sql_record",
      "tenant_vector_record",
      "tenant_search_record",
      "tenant_cache_record",
    ]],
  );
  assert.equal(rls.rows[0].count, 4);

  const postgres = createPostgresTenantDataAdapter({
    runtimePool,
    scopePool,
    readOnly: true,
  });
  await assert.rejects(postgres.project({}), {
    code: "STORE_UNAVAILABLE",
  });
  await assert.rejects(
    postgres.snapshot({ tenantId: TENANT_A }),
    { code: "STORE_UNAVAILABLE" },
  );
  const objects = createFileTenantObjectAdapter({
    rootDir: process.env.C07_RESTORE_OBJECT_TARGET,
    readOnly: true,
  });
  const calls = [];
  const tombstones = new Set();
  const boundary = createTenantDataBoundary({
    tenantRegistry: {
      async admitNewRequest({ tenantId }) {
        if (tombstones.has(tenantId)) {
          const error = new Error("deleted");
          error.code = "TENANT_DELETED";
          throw error;
        }
        return {
          tenantId,
          tenantKind: "SYNTHETIC",
          lifecycleVersion: 2,
          trustSource: "VERIFIED_SERVER_CONTEXT",
        };
      },
    },
    authorizer: {
      async enforce() {
        return {
          decisionId: "azd_c07_restored",
          evidenceRef: "evidence://c07/restored",
          policyVersion: "c07-restored-policy-v1",
        };
      },
    },
    lifecycleSource: {
      async verify() {
        throw new Error("restore endpoint does not project lifecycle events");
      },
    },
    operationCatalog: catalog,
    adapters: {
      "c07.postgres": tracked(postgres, calls),
      "c07.object-storage": tracked(objects, calls),
    },
  });

  for (const target of TENANTS) {
    for (const source of TENANTS) {
      const sql = await boundary.execute(
        context(target.tenantId, "SQL_GET"),
        request(`record_${source.suffix}`, {
          resourceId: `record_${source.suffix}`,
        }),
      );
      assert.equal(
        sql.value?.value?.owner ?? null,
        target.tenantId === source.tenantId ? target.suffix : null,
      );

      const vectors = await boundary.execute(
        context(target.tenantId, "VECTOR_SEARCH"),
        request("vector_collection", {
          embedding: source.embedding,
          limit: 10,
        }),
      );
      assert.deepEqual(
        vectors.value.map(({ resourceId }) => resourceId),
        [`vector_${target.suffix}`],
      );

      const object = await boundary.execute(
        context(target.tenantId, "OBJECT_GET"),
        request(`object_${source.suffix}`, {
          objectKey: `reports/${source.suffix}.txt`,
        }),
      );
      assert.equal(
        object.value?.body ?? null,
        target.tenantId === source.tenantId
          ? `restore tenant ${target.suffix}`
          : null,
      );
    }

    const search = await boundary.execute(
      context(target.tenantId, "SEARCH_QUERY"),
      request("search_collection", { query: "needle", limit: 10 }),
    );
    assert.deepEqual(
      search.value.map(({ resourceId }) => resourceId),
      [`search_${target.suffix}`],
    );

    const cache = await boundary.execute(
      context(target.tenantId, "CACHE_GET"),
      request("cache_collection", { cacheKey: "same_cache_key" }),
    );
    assert.equal(cache.value, null);
  }

  const foreignCursor = await boundary.execute(
    context(TENANT_B, "OBJECT_LIST"),
    request("object_collection", { cursor: "reports/a.txt", limit: 10 }),
  );
  assert.equal(
    foreignCursor.value.items.every(
      ({ tenantId }) => tenantId === TENANT_B,
    ),
    true,
  );
  assert.equal(
    foreignCursor.value.items.some(({ resourceId }) => resourceId === "object_a"),
    false,
  );

  await assert.rejects(
    boundary.execute(
      context(TENANT_A, "SQL_PUT"),
      request("read_only_write", {
        resourceId: "read_only_write",
        value: { forbidden: true },
      }),
    ),
    { code: "STORE_UNAVAILABLE" },
  );
  await assert.rejects(
    boundary.execute(
      context(TENANT_A, "OBJECT_PUT"),
      request("read_only_object_write", {
        objectKey: "reports/read-only-write.txt",
        body: "forbidden",
        contentType: "text/plain",
      }),
    ),
    { code: "STORE_UNAVAILABLE" },
  );
  await assert.rejects(
    objects.project({
      specversion: "1.0",
      id: "evt-c07-restore-suspend",
      source: "/aios-core/tenant-registry",
      type: "product.tenant.suspended.v1",
      subject: TENANT_A,
      time: "2026-07-26T12:00:00.000Z",
      datacontenttype: "application/json",
      tenantkind: "SYNTHETIC",
      correlationid: "c07-restore-suspend",
      synthetic: true,
      data: {
        tenant_id: TENANT_A,
        lifecycle_version: 3,
        generation: 1,
        operation_id: "op_01984910-3000-7000-8000-000000000099",
        state: "SUSPENDED",
        actor_id: PRINCIPAL,
      },
    }),
    { code: "STORE_UNAVAILABLE" },
  );
  assert.equal(
    (await objects.snapshot({ tenantId: TENANT_A })).state,
    "ACTIVE",
  );

  const restoreClient = await runtimePool.connect();
  try {
    await restoreClient.query("SET default_transaction_read_only = off");
    await assert.rejects(
      restoreClient.query(
        `INSERT INTO aios_data.tenant_sql_record (
           tenant_id, tenant_kind, resource_id, value
         ) VALUES ($1, 'SYNTHETIC', 'restore_write', '{}'::jsonb)`,
        [TENANT_A],
      ),
      (error) => error?.code === "42501",
    );
    await restoreClient.query("SET default_transaction_read_only = on");
  } finally {
    restoreClient.release();
  }

  tombstones.add(TENANT_A);
  const callsBeforeTombstone = calls.length;
  for (const [operationId, resourceId, input] of [
    ["SQL_GET", "record_a", { resourceId: "record_a" }],
    ["OBJECT_GET", "object_a", { objectKey: "reports/a.txt" }],
  ]) {
    await assert.rejects(
      boundary.execute(
        context(TENANT_A, operationId),
        request(resourceId, input),
      ),
      { code: "TENANT_NOT_ACTIVE" },
    );
  }
  assert.equal(calls.length, callsBeforeTombstone);
});
