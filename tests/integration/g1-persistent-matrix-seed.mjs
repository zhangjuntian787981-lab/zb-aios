import pg from "pg";
import { readFile } from "node:fs/promises";
import { createC07OperationCatalog } from "../../lib/c07-operation-catalog.mjs";
import { createPostgresTenantDataAdapter } from "../../lib/postgres-tenant-data-adapter.mjs";
import {
  G1_MATRIX_NOW,
  G1_MATRIX_PROJECTIONS,
  createG1MatrixDeployment,
  g1C07Scope,
  g1DeploymentSha256,
  g1MatrixSha256,
  g1RestoreResourceId,
  g1RestoreValue,
  loadG1MatrixJson,
} from "./g1-persistent-matrix-helpers.mjs";

const { Pool } = pg;
const MIGRATION_PATHS = Object.freeze([
  "implementation/p1/c03/postgresql/0001_tenant_registry.sql",
  "implementation/p1/c07/postgresql/0011_tenant_data_isolation.sql",
  "implementation/p1/c07/postgresql/0012_tenant_data_runtime_roles.sql",
  "implementation/p1/c16/postgresql/0029_tool_gateway.sql",
  "implementation/p1/c16/postgresql/0030_tool_gateway_runtime_roles.sql",
]);
const DATA_LOGIN = "g1_matrix_c07_data";
const SCOPE_LOGIN = "g1_matrix_c07_scope";
const LIFECYCLE_LOGIN = "g1_matrix_c07_lifecycle";
const RESTORE_LOGIN = "g1_matrix_c07_restore";
const C16_RUNTIME_LOGIN = "g1_matrix_c16_runtime";
const C16_WORKER_LOGIN = "g1_matrix_c16_worker";
const C16_AUDIT_LOGIN = "g1_matrix_c16_audit";
const C16_RECOVERY_LOGIN = "g1_matrix_c16_recovery";

function required(name) {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is required.`);
  return value;
}

function config(user = required("G1_MATRIX_PGUSER")) {
  if (process.env.G1_MATRIX_EPHEMERAL !== "1") {
    throw new Error("G1_MATRIX_EPHEMERAL=1 is required.");
  }
  return {
    host: required("G1_MATRIX_PGHOST"),
    port: Number(required("G1_MATRIX_PGPORT")),
    database: required("G1_MATRIX_SOURCE_DATABASE"),
    user,
    max: 4,
  };
}

async function seedTenant(adminPool, tenant, index) {
  const namespaceId =
    `sns_018f1000-0000-7000-8000-${String(index + 1).padStart(12, "0")}`;
  const operationId =
    `op_018f1000-0000-7000-8000-${String(index + 1).padStart(12, "0")}`;
  const createdAt = `2026-07-27T00:0${index}:00.000Z`;
  await adminPool.query(
    `INSERT INTO aios_core.tenant_registry (
       tenant_id,tenant_kind,state,lifecycle_version,generation,
       creation_key,origin_ref,origin_hash,config_refs,
       resource_namespace_id,operation_id,created_at,updated_at
     ) VALUES (
       $1,'SYNTHETIC','PROVISIONING',1,1,$2,$3,$4,'[]'::jsonb,
       $5,$6,$7,$7
     )`,
    [
      tenant.tenantId,
      `g1-matrix-${index + 1}`,
      `fixture://g1/matrix/${tenant.tenantId}`,
      g1MatrixSha256(`g1-matrix-${tenant.tenantId}`),
      namespaceId,
      operationId,
      createdAt,
    ],
  );
  await adminPool.query(
    `INSERT INTO aios_core.tenant_projection (
       tenant_id,generation,projection,desired_action,status,
       attempt_count,source_event_id,updated_at
     )
     SELECT $1,1,projection,'PROVISION','READY',1,
            'g1-matrix-' || $2 || '-' || lower(projection),$3::timestamptz
       FROM unnest($4::text[]) AS projection`,
    [tenant.tenantId, String(index + 1), createdAt, G1_MATRIX_PROJECTIONS],
  );
  await adminPool.query(
    `UPDATE aios_core.tenant_registry
        SET state='ACTIVE',lifecycle_version=2,updated_at=$2
      WHERE tenant_id=$1`,
    [tenant.tenantId, G1_MATRIX_NOW],
  );
  await adminPool.query(
    `INSERT INTO aios_data.tenant_data_lifecycle (
       tenant_id,tenant_kind,lifecycle_version,generation,
       operation_id,state,last_event_id,updated_at
     ) VALUES ($1,'SYNTHETIC',2,1,$2,'ACTIVE',$3,$4)`,
    [
      tenant.tenantId,
      operationId,
      `evt-g1-matrix-active-${index + 1}`,
      G1_MATRIX_NOW,
    ],
  );
}

async function main() {
  const migrations = await Promise.all(
    MIGRATION_PATHS.map((path) =>
      readFile(new URL(`../../${path}`, import.meta.url), "utf8"),
    ),
  );
  const catalog = createC07OperationCatalog(
    await loadG1MatrixJson(
      "implementation/p1/c07/operation-catalog.v1.json",
    ),
  );
  const deployment = await createG1MatrixDeployment();
  const adminPool = new Pool(config());
  let runtimePool;
  let scopePool;
  let lifecyclePool;
  try {
    for (const migration of migrations) await adminPool.query(migration);
    await adminPool.query(
      `REVOKE ALL PRIVILEGES ON SCHEMA aios_core FROM PUBLIC;
       REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA aios_core FROM PUBLIC;
       REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA aios_core FROM PUBLIC;
       REVOKE ALL PRIVILEGES ON ALL FUNCTIONS IN SCHEMA aios_core FROM PUBLIC;
       CREATE ROLE ${DATA_LOGIN} LOGIN;
       CREATE ROLE ${SCOPE_LOGIN} LOGIN;
       CREATE ROLE ${LIFECYCLE_LOGIN} LOGIN;
       CREATE ROLE ${RESTORE_LOGIN} LOGIN;
       CREATE ROLE ${C16_RUNTIME_LOGIN} LOGIN;
       CREATE ROLE ${C16_WORKER_LOGIN} LOGIN;
       CREATE ROLE ${C16_AUDIT_LOGIN} LOGIN;
       CREATE ROLE ${C16_RECOVERY_LOGIN} LOGIN;
       GRANT aios_c07_data_runtime TO ${DATA_LOGIN};
       GRANT aios_c07_scope_runtime TO ${SCOPE_LOGIN};
       GRANT aios_c07_lifecycle_runtime TO ${LIFECYCLE_LOGIN};
       GRANT aios_c07_restore_runtime TO ${RESTORE_LOGIN};
       GRANT aios_c16_runtime TO ${C16_RUNTIME_LOGIN};
       GRANT aios_c16_worker TO ${C16_WORKER_LOGIN};
       GRANT aios_c16_audit_worker TO ${C16_AUDIT_LOGIN};
       GRANT aios_c16_recovery_reader TO ${C16_RECOVERY_LOGIN};`,
    );
    for (const [index, tenant] of deployment.tenants.entries()) {
      await seedTenant(adminPool, tenant, index);
    }

    runtimePool = new Pool(config(DATA_LOGIN));
    scopePool = new Pool(config(SCOPE_LOGIN));
    lifecyclePool = new Pool(config(LIFECYCLE_LOGIN));
    const adapter = createPostgresTenantDataAdapter({
      runtimePool,
      scopePool,
      lifecyclePool,
    });
    for (const [tenantIndex, tenant] of deployment.tenants.entries()) {
      for (const [userIndex, user] of tenant.users.entries()) {
        const resourceId = g1RestoreResourceId(user);
        await adapter.execute(
          g1C07Scope(
            tenant.tenantId,
            `restore-seed-${tenantIndex + 1}-${userIndex + 1}`,
          ),
          {
            ...catalog.resolve("SQL_PUT"),
            resourceId,
            input: {
              resourceId,
              value: g1RestoreValue(
                tenant,
                user,
                tenantIndex,
                userIndex,
              ),
            },
          },
        );
      }
    }
    process.stdout.write(
      `${JSON.stringify({
        schemaVersion: "g1-persistent-matrix-seed.v1",
        deploymentSha256: g1DeploymentSha256(deployment),
        tenantCount: deployment.tenants.length,
        restoredResourceCount: 9,
      })}\n`,
    );
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
