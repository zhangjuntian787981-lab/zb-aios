import assert from "node:assert/strict";
import test from "node:test";
import pg from "pg";
import { createC07OperationCatalog } from "../../lib/c07-operation-catalog.mjs";
import { createFileC10QuarantineStore } from "../../lib/file-c10-quarantine-store.mjs";
import { createFileTenantObjectAdapter } from "../../lib/file-tenant-object-adapter.mjs";
import { runG1PersistentIsolationMatrix } from "../../lib/g1-persistent-isolation-matrix.mjs";
import { createG1RoleAuthorization } from "../../lib/g1-role-authorization.mjs";
import { createOpenFgaPdp } from "../../lib/openfga-pdp.mjs";
import { createPostgresTenantDataAdapter } from "../../lib/postgres-tenant-data-adapter.mjs";
import { createPostgresToolGatewayStore } from "../../lib/postgres-tool-gateway-store.mjs";
import { createG1C16BoundFacade } from "./g1-c16-bound-facade.mjs";
import { createG1PersistentSurfaceAdapters } from "./g1-persistent-surface-adapters.mjs";
import {
  G1_MATRIX_NOW,
  createG1MatrixDeployment,
  g1C07Scope,
  g1DeploymentSha256,
  g1LifecycleEvent,
  g1MatrixSha256,
  loadG1MatrixJson,
} from "./g1-persistent-matrix-helpers.mjs";

const { Pool } = pg;
const OPENFGA_VERSION = "v1.18.1";
const OPENFGA_SHA256 =
  "d667620fcf54d5343fae374c60e1ac0af98defd5e44d93ca9af52866a2881f94";
const EXPECTED_DEPLOYMENT_SHA256 =
  "sha256:0ad6c07cea92ea050232b34af2bf1362e7599ae5f694a5c6d23968e18c066162";
const DATA_LOGIN = "g1_matrix_c07_data";
const SCOPE_LOGIN = "g1_matrix_c07_scope";
const LIFECYCLE_LOGIN = "g1_matrix_c07_lifecycle";
const RESTORE_LOGIN = "g1_matrix_c07_restore";
const C16_RUNTIME_LOGIN = "g1_matrix_c16_runtime";
const C16_WORKER_LOGIN = "g1_matrix_c16_worker";
const C16_AUDIT_LOGIN = "g1_matrix_c16_audit";
const C16_RECOVERY_LOGIN = "g1_matrix_c16_recovery";
const EXPECTED_BACKEND_KINDS = Object.freeze({
  SQL: "POSTGRESQL_C07_SOURCE",
  VECTOR: "POSTGRESQL_C07_SOURCE",
  FILE: "C10_FILE_QUARANTINE",
  OBJECT: "C07_FILE_OBJECT_ROOT",
  SEARCH: "POSTGRESQL_C07_SOURCE",
  CACHE: "POSTGRESQL_C07_SOURCE",
  TOOL: "C16_POSTGRESQL_GATEWAY_C0",
  RESTORE_REPLICA: "POSTGRESQL_C07_RESTORE_REPLICA",
});

function required(name) {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is required.`);
  return value;
}

function config(database, user = required("G1_MATRIX_PGUSER"), max = 8) {
  if (process.env.G1_MATRIX_EPHEMERAL !== "1") {
    throw new Error("G1_MATRIX_EPHEMERAL=1 is required.");
  }
  return {
    host: required("G1_MATRIX_PGHOST"),
    port: Number(required("G1_MATRIX_PGPORT")),
    database,
    user,
    max,
  };
}

function deterministicIds() {
  let value = 900;
  return () => {
    value += 1;
    return `018f2000-0000-7000-8000-${String(value).padStart(12, "0")}`;
  };
}

function observeC07(adapter, backendKind, backendInstanceId, readOnly) {
  let executeCount = 0;
  return Object.freeze({
    async execute(scope, operation) {
      executeCount += 1;
      return adapter.execute(scope, operation);
    },
    observations() {
      return Object.freeze({
        backendKind,
        backendInstanceId,
        persistent: true,
        readOnly,
        executeCount,
        negativeStorageTouchCount: 0,
      });
    },
  });
}

function observeFile(store, backendInstanceId) {
  let putCount = 0;
  let readCount = 0;
  return Object.freeze({
    async put(input) {
      putCount += 1;
      return store.put(input);
    },
    async read(input) {
      readCount += 1;
      return store.read(input);
    },
    observations() {
      return Object.freeze({
        backendKind: "C10_FILE_QUARANTINE",
        backendInstanceId,
        persistent: true,
        putCount,
        readCount,
        negativeStorageTouchCount: 0,
      });
    },
  });
}

function observeObject(adapter, backendInstanceId) {
  let executeCount = 0;
  return Object.freeze({
    async execute(scope, operation) {
      executeCount += 1;
      return adapter.execute(scope, operation);
    },
    project(event) {
      return adapter.project(event);
    },
    observations() {
      return Object.freeze({
        backendKind: "C07_FILE_OBJECT_ROOT",
        backendInstanceId,
        persistent: true,
        executeCount,
        negativeStorageTouchCount: 0,
      });
    },
  });
}

function observeC16Store(store, backendInstanceId) {
  return Object.freeze({
    ...store,
    observations() {
      return Object.freeze({
        backendKind: "C16_POSTGRESQL_STORE",
        backendInstanceId,
        persistent: true,
        negativeStorageTouchCount: 0,
      });
    },
  });
}

function createRealOpenFgaAdapter(baseUrl) {
  const tenants = new Map();
  let actualCheckCount = 0;
  let publishedModelCount = 0;
  return {
    adapter: {
      async prepareTenant({ tenantId, model }) {
        const pdp = createOpenFgaPdp({ baseUrl });
        const provisioned = await pdp.provisionStore({
          name: `g1-persistent-matrix-${tenants.size + 1}`,
        });
        const published = await pdp.publishModel(model);
        const readback = await pdp.readAuthorizationModel({
          authorizationModelId: published.authorizationModelId,
        });
        assert.deepEqual(readback.model, model);
        tenants.set(tenantId, {
          pdp,
          storeId: provisioned.storeId,
          authorizationModelId: published.authorizationModelId,
        });
        publishedModelCount += 1;
        return {
          storeId: provisioned.storeId,
          authorizationModelId: published.authorizationModelId,
        };
      },
      async writeTuples(input) {
        const tenant = tenants.get(input.tenantId);
        assert.equal(tenant.storeId, input.storeId);
        assert.equal(
          tenant.authorizationModelId,
          input.authorizationModelId,
        );
        return tenant.pdp.writeTuples({
          authorizationModelId: input.authorizationModelId,
          tupleKeys: input.tupleKeys,
        });
      },
      async check(input) {
        const tenant = tenants.get(input.tenantId);
        assert.equal(tenant.storeId, input.storeId);
        assert.equal(
          tenant.authorizationModelId,
          input.authorizationModelId,
        );
        actualCheckCount += 1;
        return tenant.pdp.check({
          authorizationModelId: input.authorizationModelId,
          tupleKey: input.tupleKey,
        });
      },
    },
    observations() {
      return {
        actualCheckCount,
        publishedModelCount,
      };
    },
  };
}

test("real OpenFGA and eight persistent surfaces isolate 288 cases with a verified read-only restore", async (t) => {
  assert.equal(process.env.G1_MATRIX_OPENFGA_VERSION, OPENFGA_VERSION);
  assert.equal(process.env.G1_MATRIX_OPENFGA_SHA256, OPENFGA_SHA256);
  const sourceDatabase = required("G1_MATRIX_SOURCE_DATABASE");
  const restoreDatabase = required("G1_MATRIX_RESTORE_DATABASE");
  const deployment = {
    tenants: (await createG1MatrixDeployment()).tenants.map((tenant) => ({
      ...tenant,
      lifecycleVersion: 2,
    })),
  };
  const repeatedDeployment = {
    tenants: (await createG1MatrixDeployment()).tenants.map((tenant) => ({
      ...tenant,
      lifecycleVersion: 2,
    })),
  };
  const deploymentSha256 = g1DeploymentSha256(deployment);
  assert.equal(deploymentSha256, EXPECTED_DEPLOYMENT_SHA256);
  assert.equal(
    g1DeploymentSha256(repeatedDeployment),
    deploymentSha256,
  );

  const sourceAdmin = new Pool(config(sourceDatabase));
  const restoreAdmin = new Pool(config(restoreDatabase));
  const sourceRuntimePool = new Pool(config(sourceDatabase, DATA_LOGIN));
  const sourceScopePool = new Pool(config(sourceDatabase, SCOPE_LOGIN));
  const sourceLifecyclePool = new Pool(
    config(sourceDatabase, LIFECYCLE_LOGIN),
  );
  const restoreRuntimePool = new Pool(
    config(restoreDatabase, RESTORE_LOGIN),
  );
  const restoreScopePool = new Pool(
    config(restoreDatabase, SCOPE_LOGIN),
  );
  const c16Pools = {
    runtime: new Pool(config(sourceDatabase, C16_RUNTIME_LOGIN)),
    worker: new Pool(config(sourceDatabase, C16_WORKER_LOGIN)),
    audit: new Pool(config(sourceDatabase, C16_AUDIT_LOGIN)),
    recovery: new Pool(config(sourceDatabase, C16_RECOVERY_LOGIN)),
    scope: new Pool(config(sourceDatabase, SCOPE_LOGIN)),
  };
  t.after(async () => {
    await Promise.all([
      sourceAdmin.end(),
      restoreAdmin.end(),
      sourceRuntimePool.end(),
      sourceScopePool.end(),
      sourceLifecyclePool.end(),
      restoreRuntimePool.end(),
      restoreScopePool.end(),
      ...Object.values(c16Pools).map((pool) => pool.end()),
    ]);
  });

  const catalog = createC07OperationCatalog(
    await loadG1MatrixJson(
      "implementation/p1/c07/operation-catalog.v1.json",
    ),
  );
  const sourceNative = createPostgresTenantDataAdapter({
    runtimePool: sourceRuntimePool,
    scopePool: sourceScopePool,
    lifecyclePool: sourceLifecyclePool,
  });
  const restoreNative = createPostgresTenantDataAdapter({
    runtimePool: restoreRuntimePool,
    scopePool: restoreScopePool,
    readOnly: true,
  });
  const source = observeC07(
    sourceNative,
    "POSTGRESQL_C07_SOURCE",
    `postgresql://${sourceDatabase}/aios_data`,
    false,
  );
  const restore = observeC07(
    restoreNative,
    "POSTGRESQL_C07_RESTORE_REPLICA",
    `postgresql://${restoreDatabase}/aios_data`,
    true,
  );
  const file = observeFile(
    createFileC10QuarantineStore({
      rootDir: required("G1_MATRIX_FILE_ROOT"),
    }),
    required("G1_MATRIX_FILE_ROOT"),
  );
  const object = observeObject(
    createFileTenantObjectAdapter({
      rootDir: required("G1_MATRIX_OBJECT_ROOT"),
    }),
    required("G1_MATRIX_OBJECT_ROOT"),
  );
  for (const tenant of deployment.tenants) {
    await object.project(
      g1LifecycleEvent(
        tenant,
        "provision",
        "product.tenant.provisioning-requested.v1",
        1,
        "PROVISIONING",
      ),
    );
    await object.project(
      g1LifecycleEvent(
        tenant,
        "active",
        "product.tenant.activated.v1",
        2,
        "ACTIVE",
      ),
    );
  }
  const c16Store = observeC16Store(
    createPostgresToolGatewayStore({
      runtimePool: c16Pools.runtime,
      toolWorkerPool: c16Pools.worker,
      auditWorkerPool: c16Pools.audit,
      recoveryPool: c16Pools.recovery,
      scopePool: c16Pools.scope,
    }),
    `postgresql://${sourceDatabase}/aios_tool`,
  );
  const c16 = createG1C16BoundFacade({
    deployment,
    store: c16Store,
    catalogDocument: await loadG1MatrixJson(
      "implementation/p1/c16/operation-catalog.v1.json",
    ),
    fixtureDocument: await loadG1MatrixJson(
      "implementation/p1/c16/synthetic-tool-fixtures.v1.json",
    ),
    clock: () => G1_MATRIX_NOW,
    idFactory: deterministicIds(),
  });
  const openFga = createRealOpenFgaAdapter(
    required("G1_MATRIX_OPENFGA_BASE_URL"),
  );
  const authorization = await createG1RoleAuthorization({
    deployment,
    c06: openFga.adapter,
  });
  const verifiedRestores = new Map();
  const lifecycleVersionByTenant = Object.fromEntries(
    deployment.tenants.map((tenant) => [tenant.tenantId, 2]),
  );
  const restoreVerifier = {
    async verify({ tenantId, resourceId }) {
      const scope = g1C07Scope(
        tenantId,
        `restore-verify-${g1MatrixSha256(resourceId).slice(7, 19)}`,
      );
      const operation = {
        ...catalog.resolve("SQL_GET"),
        resourceId,
        input: { resourceId },
      };
      const [sourceValue, replicaValue] = await Promise.all([
        source.execute(scope, operation),
        restore.execute(scope, operation),
      ]);
      const sourceSha256 = g1MatrixSha256(sourceValue?.value ?? null);
      const replicaSha256 = g1MatrixSha256(replicaValue?.value ?? null);
      verifiedRestores.set(`${tenantId}|${resourceId}`, {
        sourceSha256,
        replicaSha256,
      });
      return {
        verified: sourceSha256 === replicaSha256,
        restoreId: `pg-restore-${restoreDatabase}`,
        sourceBackendInstanceId:
          source.observations().backendInstanceId,
        replicaBackendInstanceId:
          restore.observations().backendInstanceId,
        sourceSha256,
        replicaSha256,
      };
    },
  };
  const surfaces = createG1PersistentSurfaceAdapters({
    c07Source: source,
    c07Restore: restore,
    fileStore: file,
    objectStore: object,
    c16Gateway: c16,
    deployment,
    lifecycleVersionByTenant,
    restoreVerifier,
  });
  const matrix = await runG1PersistentIsolationMatrix({
    deployment,
    authorization,
    surfaces,
  });

  assert.equal(
    matrix.gateConditionStatus,
    "SATISFIED",
    JSON.stringify({
      counts: matrix.counts,
      authorizationDelta: matrix.authorizationDelta,
      remainingGaps: matrix.remainingGaps,
      failures: matrix.surfaces.flatMap((surface) =>
        surface.cases
          .filter(({ casePassed }) => !casePassed)
          .map((currentCase) => ({
            surface: surface.surface,
            caseId: currentCase.caseId,
            errorCode: currentCase.errorCode,
            adapterTouchDelta: currentCase.adapterTouchDelta,
          })),
      ),
    }),
  );
  assert.deepEqual(matrix.counts, {
    total: 288,
    positive: 72,
    negative: 216,
    wrongTenant: 72,
    wrongUser: 72,
    wrongRole: 72,
    c06BoundaryEntered: 288,
    positiveAdapterTouches: 144,
    negativeAdapterTouches: 0,
    observedLeaks: 0,
    wrongAttributions: 0,
  });
  assert.deepEqual(matrix.authorizationDelta, {
    checks: 288,
    allows: 72,
    denies: 216,
  });
  assert.deepEqual(openFga.observations(), {
    actualCheckCount: 288,
    publishedModelCount: 3,
  });
  for (const surface of matrix.surfaces) {
    assert.equal(
      surface.observations.backendKind,
      EXPECTED_BACKEND_KINDS[surface.surface],
    );
    assert.notEqual(
      surface.observations.backendKind,
      "NON_GATE_TEST_DOUBLE",
    );
    assert.equal(surface.observations.persistent, true);
    assert.equal(surface.negativeAdapterTouches, 0);
    assert.equal(
      surface.observations.negativeStorageTouchCount,
      0,
    );
  }
  assert.equal(source.observations().executeCount, 81);
  assert.equal(restore.observations().executeCount, 18);
  assert.equal(file.observations().putCount, 9);
  assert.equal(file.observations().readCount, 9);
  assert.equal(object.observations().executeCount, 18);
  assert.deepEqual(c16.observations(), {
    backendKind: "C16_POSTGRESQL_GATEWAY_C0",
    backendInstanceId: `postgresql://${sourceDatabase}/aios_tool`,
    persistent: true,
    confirmCount: 9,
    executeCount: 9,
    newExecutionCount: 9,
    networkRequestCount: 0,
    enterpriseEndpointCount: 0,
    enterpriseCredentialCount: 0,
    externalEffectCount: 0,
    negativeStorageTouchCount: 0,
  });
  const sourceRows = await sourceAdmin.query(
    `SELECT
       (SELECT count(*)::integer
          FROM aios_data.tenant_sql_record) AS sql_count,
       (SELECT count(*)::integer
          FROM aios_data.tenant_vector_record) AS vector_count,
       (SELECT count(*)::integer
          FROM aios_data.tenant_search_record) AS search_count,
       (SELECT count(*)::integer
          FROM aios_data.tenant_cache_record) AS cache_count,
       (SELECT count(*)::integer
          FROM aios_tool.tool_confirmation) AS confirmation_count,
       (SELECT count(*)::integer
          FROM aios_tool.tool_call) AS tool_call_count`,
  );
  assert.deepEqual(sourceRows.rows[0], {
    sql_count: 18,
    vector_count: 9,
    search_count: 9,
    cache_count: 9,
    confirmation_count: 9,
    tool_call_count: 9,
  });
  assert.equal(verifiedRestores.size, 9);
  assert.equal(
    [...verifiedRestores.values()].every(
      (value) => value.sourceSha256 === value.replicaSha256,
    ),
    true,
  );

  const restoredState = await restoreAdmin.query(
    `SELECT current_database() AS database,
            current_setting('default_transaction_read_only') AS read_only,
            (
              SELECT extversion
                FROM pg_extension
               WHERE extname='vector'
            ) AS vector_version`,
  );
  assert.deepEqual(restoredState.rows[0], {
    database: restoreDatabase,
    read_only: "on",
    vector_version: "0.8.5",
  });
  await assert.rejects(
    restore.execute(
      g1C07Scope(deployment.tenants[0].tenantId, "read-only-proof"),
      {
        ...catalog.resolve("SQL_PUT"),
        resourceId: "read-only-proof",
        input: {
          resourceId: "read-only-proof",
          value: { forbidden: true },
        },
      },
    ),
    { code: "STORE_UNAVAILABLE" },
  );
  const restoreClient = await restoreRuntimePool.connect();
  try {
    await restoreClient.query("SET default_transaction_read_only=off");
    await assert.rejects(
      restoreClient.query(
        `INSERT INTO aios_data.tenant_sql_record (
           tenant_id,tenant_kind,resource_id,value
         ) VALUES ($1,'SYNTHETIC','direct-write-proof','{}'::jsonb)`,
        [deployment.tenants[0].tenantId],
      ),
      (error) => error?.code === "42501",
    );
  } finally {
    restoreClient.release();
  }

  t.diagnostic(
    JSON.stringify({
      schemaVersion: "g1-real-eight-surface-isolation-evidence.v1",
      evidenceScope: "REAL_C06_AND_EIGHT_SURFACE_ISOLATION",
      persistentTenantDeploymentProven: false,
      deploymentSha256,
      deploymentBindingRequired:
        "MUST_EQUAL_CROSS_PROCESS_PERSISTENT_RUNTIME_DEPLOYMENT_SHA256",
      postgresSourceDatabase: sourceDatabase,
      postgresRestoreDatabase: restoreDatabase,
      actualPgDumpRestore: true,
      restoreReadOnly: true,
      restoreHashMatchCount: verifiedRestores.size,
      openFgaVersion: OPENFGA_VERSION,
      openFgaActualCheckCount: 288,
      caseCount: matrix.counts.total,
      allowCount: matrix.authorizationDelta.allows,
      denyCount: matrix.authorizationDelta.denies,
      negativeBackendTouchCount:
        matrix.counts.negativeAdapterTouches,
      backendKinds: Object.values(EXPECTED_BACKEND_KINDS),
    }),
  );
});
