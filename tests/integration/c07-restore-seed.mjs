import { readFile } from "node:fs/promises";
import pg from "pg";
import { createC07OperationCatalog } from "../../lib/c07-operation-catalog.mjs";
import { createFileTenantObjectAdapter } from "../../lib/file-tenant-object-adapter.mjs";
import { createPostgresTenantDataAdapter } from "../../lib/postgres-tenant-data-adapter.mjs";

const { Pool } = pg;
const migrations = await Promise.all(
  [
    "../../implementation/p1/c03/postgresql/0001_tenant_registry.sql",
    "../../implementation/p1/c07/postgresql/0011_tenant_data_isolation.sql",
    "../../implementation/p1/c07/postgresql/0012_tenant_data_runtime_roles.sql",
  ].map((path) => readFile(new URL(path, import.meta.url), "utf8")),
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

const DATA_LOGIN = "c07_restore_data_login";
const RESTORE_LOGIN = "c07_restore_read_login";
const SCOPE_LOGIN = "c07_restore_scope_login";
const LIFECYCLE_LOGIN = "c07_restore_lifecycle_login";
const TENANTS = [
  {
    tenantId: "stn_01984910-3000-7000-8000-000000000001",
    namespaceId: "sns_01984910-3000-7000-8000-000000000011",
    operationId: "op_01984910-3000-7000-8000-000000000021",
    suffix: "a",
  },
  {
    tenantId: "stn_01984910-3000-7000-8000-000000000002",
    namespaceId: "sns_01984910-3000-7000-8000-000000000012",
    operationId: "op_01984910-3000-7000-8000-000000000022",
    suffix: "b",
  },
  {
    tenantId: "stn_01984910-3000-7000-8000-000000000003",
    namespaceId: "sns_01984910-3000-7000-8000-000000000013",
    operationId: "op_01984910-3000-7000-8000-000000000023",
    suffix: "c",
  },
];
const PROJECTIONS = [
  "AUTHORIZATION",
  "IDENTITY",
  "KNOWLEDGE",
  "SECRET_REFS",
  "STORAGE",
];

function config(user = process.env.C07_RESTORE_TEST_PGUSER) {
  if (process.env.C07_RESTORE_TEST_EPHEMERAL !== "1") {
    throw new Error("C07_RESTORE_TEST_EPHEMERAL=1 is required.");
  }
  for (const name of [
    "C07_RESTORE_TEST_PGHOST",
    "C07_RESTORE_TEST_PGPORT",
    "C07_RESTORE_SOURCE_DATABASE",
    "C07_RESTORE_TEST_PGUSER",
    "C07_RESTORE_OBJECT_SOURCE",
  ]) {
    if (!process.env[name]) throw new Error(`${name} is required.`);
  }
  return {
    host: process.env.C07_RESTORE_TEST_PGHOST,
    port: Number(process.env.C07_RESTORE_TEST_PGPORT),
    database: process.env.C07_RESTORE_SOURCE_DATABASE,
    user,
    max: 2,
  };
}

function lifecycleEvent(tenant, suffix, type, version, state) {
  return {
    specversion: "1.0",
    id: `evt-c07-restore-${tenant.suffix}-${suffix}`,
    source: "/aios-core/tenant-registry",
    type,
    subject: tenant.tenantId,
    time: `2026-07-26T12:0${version}:00.000Z`,
    datacontenttype: "application/json",
    tenantkind: "SYNTHETIC",
    correlationid: `c07-restore-${tenant.suffix}-${suffix}`,
    synthetic: true,
    data: {
      tenant_id: tenant.tenantId,
      lifecycle_version: version,
      generation: 1,
      operation_id: tenant.operationId,
      state,
      actor_id: "prn_01984910-3000-7000-8000-000000000099",
    },
  };
}

function scope(tenant) {
  return {
    trustSource: "C07_VERIFIED_TENANT_SCOPE",
    tenantId: tenant.tenantId,
    tenantKind: "SYNTHETIC",
    lifecycleVersion: 2,
    correlationId: `c07-restore-seed-${tenant.suffix}`,
    decisionId: `azd-c07-restore-${tenant.suffix}`,
    evidenceRef: `evidence://c07/restore/${tenant.suffix}`,
    policyVersion: "c07-restore-policy-v1",
  };
}

function operation(id, resourceId, input) {
  return { ...catalog.resolve(id), resourceId, input };
}

async function seedTenant(adminPool, tenant, index) {
  const time = `2026-07-26T12:0${index}:00.000Z`;
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
      `c07-restore-${tenant.suffix}`,
      `fixture://c07/restore/${tenant.suffix}`,
      `sha256:${String(index + 4).repeat(64)}`,
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
        `seed-${tenant.suffix}-${projection.toLowerCase()}`,
        time,
      ],
    );
  }
}

async function main() {
  const adminPool = new Pool(config());
  let runtimePool;
  let scopePool;
  let lifecyclePool;
  try {
    for (const migration of migrations) await adminPool.query(migration);
    await adminPool.query(
      `CREATE ROLE ${DATA_LOGIN} LOGIN;
       CREATE ROLE ${RESTORE_LOGIN} LOGIN;
       CREATE ROLE ${SCOPE_LOGIN} LOGIN;
       CREATE ROLE ${LIFECYCLE_LOGIN} LOGIN;
       GRANT aios_c07_data_runtime TO ${DATA_LOGIN};
       GRANT aios_c07_restore_runtime TO ${RESTORE_LOGIN};
       GRANT aios_c07_scope_runtime TO ${SCOPE_LOGIN};
       GRANT aios_c07_lifecycle_runtime TO ${LIFECYCLE_LOGIN};`,
    );
    for (const [index, tenant] of TENANTS.entries()) {
      await seedTenant(adminPool, tenant, index);
    }

    runtimePool = new Pool(config(DATA_LOGIN));
    scopePool = new Pool(config(SCOPE_LOGIN));
    lifecyclePool = new Pool(config(LIFECYCLE_LOGIN));
    const postgresAdapter = createPostgresTenantDataAdapter({
      runtimePool,
      scopePool,
      lifecyclePool,
      controlPool: lifecyclePool,
    });
    const objectAdapter = createFileTenantObjectAdapter({
      rootDir: process.env.C07_RESTORE_OBJECT_SOURCE,
    });

    for (const tenant of TENANTS) {
      const provisioning = lifecycleEvent(
        tenant,
        "provision",
        "product.tenant.provisioning-requested.v1",
        1,
        "PROVISIONING",
      );
      await postgresAdapter.project(provisioning);
      await objectAdapter.project(provisioning);
      await adminPool.query(
        `UPDATE aios_core.tenant_registry
            SET state = 'ACTIVE',
                lifecycle_version = 2,
                updated_at = '2026-07-26T12:02:00.000Z'
          WHERE tenant_id = $1`,
        [tenant.tenantId],
      );
      const active = lifecycleEvent(
        tenant,
        "active",
        "product.tenant.activated.v1",
        2,
        "ACTIVE",
      );
      await postgresAdapter.project(active);
      await objectAdapter.project(active);

      await postgresAdapter.execute(
        scope(tenant),
        operation("SQL_PUT", `record_${tenant.suffix}`, {
          resourceId: `record_${tenant.suffix}`,
          value: { owner: tenant.suffix },
        }),
      );
      await postgresAdapter.execute(
        scope(tenant),
        operation("VECTOR_UPSERT", `vector_${tenant.suffix}`, {
          resourceId: `vector_${tenant.suffix}`,
          embedding: {
            a: [1, 0],
            b: [0, 1],
            c: [1, 1],
          }[tenant.suffix],
          metadata: { owner: tenant.suffix },
        }),
      );
      await postgresAdapter.execute(
        scope(tenant),
        operation("SEARCH_INDEX", `search_${tenant.suffix}`, {
          resourceId: `search_${tenant.suffix}`,
          text:
            tenant.suffix === "a"
              ? "restore needle"
              : "restore needle needle needle",
          metadata: { owner: tenant.suffix },
        }),
      );
      await postgresAdapter.execute(
        scope(tenant),
        operation("CACHE_PUT", "same_cache_key", {
          cacheKey: "same_cache_key",
          value: { owner: tenant.suffix },
          ttlSeconds: 3600,
        }),
      );
      await objectAdapter.execute(scope(tenant), {
        kind: "OBJECT_PUT",
        resourceId: `object_${tenant.suffix}`,
        input: {
          objectKey: `reports/${tenant.suffix}.txt`,
          body: `restore tenant ${tenant.suffix}`,
          contentType: "text/plain",
        },
      });
    }
  } finally {
    await Promise.all([
      runtimePool?.end(),
      scopePool?.end(),
      lifecyclePool?.end(),
      adminPool.end(),
    ]);
  }
}

await main();
