import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import test from "node:test";
import pg from "pg";
import {
  ModelGatewayError,
  createModelGateway,
  createSyntheticModelCatalog,
  modelGatewaySha256,
} from "../../lib/model-gateway.mjs";
import { createC14SyntheticDataPolicyResolver } from "../../lib/c14-synthetic-data-policy.mjs";
import { createC14SyntheticModelProvider } from "../../lib/c14-synthetic-model-provider.mjs";
import { createPostgresModelGatewayStore } from "../../lib/postgres-model-gateway-store.mjs";

const { Pool } = pg;
const migrationPaths = [
  "../../implementation/p1/c03/postgresql/0001_tenant_registry.sql",
  "../../implementation/p1/c07/postgresql/0011_tenant_data_isolation.sql",
  "../../implementation/p1/c07/postgresql/0012_tenant_data_runtime_roles.sql",
  "../../implementation/p1/c14/postgresql/0021_model_gateway.sql",
  "../../implementation/p1/c14/postgresql/0022_model_gateway_runtime_roles.sql",
];
const migrations = await Promise.all(
  migrationPaths.map((path) =>
    readFile(new URL(path, import.meta.url), "utf8"),
  ),
);
const catalogDocument = JSON.parse(
  await readFile(
    new URL(
      "../../implementation/p1/c14/synthetic-model-catalog.v1.json",
      import.meta.url,
    ),
    "utf8",
  ),
);
for (const policy of catalogDocument.tenantPolicies) {
  policy.canaryPercent = 0;
}
const dataPolicyDocument = JSON.parse(
  await readFile(
    new URL(
      "../../implementation/p1/c14/synthetic-data-policy-fixtures.v1.json",
      import.meta.url,
    ),
    "utf8",
  ),
);
const TENANTS = [
  {
    tenantId: "stn_018f0000-0000-7000-8000-000000000010",
    namespaceId: "sns_01984910-3000-7000-8000-000000000011",
    operationId: "op_01984910-3000-7000-8000-000000000021",
    fixtureId: "northstar",
    expectedPlane: "LOCAL",
  },
  {
    tenantId: "stn_018f0000-0000-7000-8000-000000000011",
    namespaceId: "sns_01984910-3000-7000-8000-000000000012",
    operationId: "op_01984910-3000-7000-8000-000000000022",
    fixtureId: "blue-harbor",
    expectedPlane: "CLOUD",
  },
  {
    tenantId: "stn_018f0000-0000-7000-8000-000000000012",
    namespaceId: "sns_01984910-3000-7000-8000-000000000013",
    operationId: "op_01984910-3000-7000-8000-000000000023",
    fixtureId: "cedar",
    expectedPlane: "CLOUD",
  },
];
const RUNTIME_LOGIN = "c14_test_runtime_login";
const SCOPE_LOGIN = "c14_test_scope_login";
const ACTOR = "prn_018f0000-0000-7000-8000-000000000002";
const HUMAN = "prn_018f0000-0000-7000-8000-000000000001";
const DELEGATION =
  "dlg_018f0000-0000-7000-8000-000000000020";
const PROJECTIONS = [
  "AUTHORIZATION",
  "IDENTITY",
  "KNOWLEDGE",
  "SECRET_REFS",
  "STORAGE",
];

function config(user = process.env.C14_TEST_PGUSER, max = 30) {
  if (process.env.C14_TEST_EPHEMERAL !== "1") {
    throw new Error("C14_TEST_EPHEMERAL=1 is required.");
  }
  for (const name of [
    "C14_TEST_PGHOST",
    "C14_TEST_PGPORT",
    "C14_TEST_PGDATABASE",
    "C14_TEST_PGUSER",
  ]) {
    if (!process.env[name]) throw new Error(`${name} is required.`);
  }
  return {
    host: process.env.C14_TEST_PGHOST,
    port: Number(process.env.C14_TEST_PGPORT),
    database: process.env.C14_TEST_PGDATABASE,
    user,
    max,
  };
}

function digest(value) {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

function deterministicIds() {
  let counter = 500;
  return () => {
    counter += 1;
    return `018f0000-0000-7000-8000-${String(counter).padStart(12, "0")}`;
  };
}

function identity(tenantId) {
  return {
    tenantId,
    tenantKind: "SYNTHETIC",
    identityAccountId: "sia_018f0000-0000-7000-8000-000000000030",
    identityLinkId: "lnk_018f0000-0000-7000-8000-000000000031",
    sessionId: "ses_018f0000-0000-7000-8000-000000000032",
    humanSubject: {
      principalId: HUMAN,
      principalType: "HUMAN",
      lifecycleVersion: 1,
      securityEpoch: 1,
    },
    workloadActor: {
      principalId: ACTOR,
      principalType: "AGENT",
      lifecycleVersion: 1,
      securityEpoch: 1,
    },
    purposeRef: "synthetic://c06/purpose/manage",
    delegationChain: [
      {
        delegationId: DELEGATION,
        delegatorPrincipalId: HUMAN,
        delegatePrincipalId: ACTOR,
        purposeRef: "synthetic://c06/purpose/manage",
        lifecycleVersion: 1,
        expiresAt: "2026-07-27T00:00:00.000Z",
      },
    ],
    trustSource:
      "VERIFIED_SESSION_IDENTITY_LINK_AND_WORKLOAD_CONTEXT",
    authorizationStatus: "NOT_EVALUATED",
  };
}

function context(tenantId) {
  return {
    synthetic: true,
    routeTrustSource: "VERIFIED_ROUTE_DESCRIPTOR",
    tenantId,
    workloadTrustSource: "VERIFIED_WORKLOAD_CONTEXT",
    workloadActorPrincipalId: ACTOR,
  };
}

function routeRequest(tenant, suffix = tenant.fixtureId) {
  return {
    sessionToken: "synthetic-session-token",
    delegationId: DELEGATION,
    idempotencyKey: `c14-${suffix}`,
    correlationId: `c14-correlation-${suffix}`,
    taskRef: "synthetic://c14/tasks/chat",
    inputRef: "synthetic://c14/inputs/public-summary",
    inputSha256:
      "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  };
}

function scope(tenantId, suffix = "read") {
  return {
    trustSource: "C07_VERIFIED_TENANT_SCOPE",
    tenantId,
    tenantKind: "SYNTHETIC",
    lifecycleVersion: 2,
    operationId: "C14_ROUTE_MODEL",
    storagePath: "model-gateway",
    correlationId: `c14-${suffix}`,
    decisionId: `decision-${suffix}`,
    evidenceRef: `evidence://c14/${suffix}`,
    policyVersion: "c06-model-1",
  };
}

async function seedTenant(adminPool, tenant, index) {
  const createdAt = `2026-07-26T10:0${index}:00.000Z`;
  await adminPool.query(
    `INSERT INTO aios_core.tenant_registry (
       tenant_id, tenant_kind, state, lifecycle_version, generation,
       creation_key, origin_ref, origin_hash, config_refs,
       resource_namespace_id, operation_id, created_at, updated_at
     ) VALUES (
       $1,'SYNTHETIC','PROVISIONING',1,1,$2,$3,$4,'[]'::jsonb,
       $5,$6,$7,$7
     )`,
    [
      tenant.tenantId,
      `c14-creation-${tenant.fixtureId}`,
      `fixture://c14/${tenant.fixtureId}`,
      digest(`origin-${tenant.fixtureId}`),
      tenant.namespaceId,
      tenant.operationId,
      createdAt,
    ],
  );
  for (const projection of PROJECTIONS) {
    await adminPool.query(
      `INSERT INTO aios_core.tenant_projection (
         tenant_id,generation,projection,desired_action,status,
         attempt_count,source_event_id,updated_at
       ) VALUES ($1,1,$2,'PROVISION','READY',1,$3,$4)`,
      [
        tenant.tenantId,
        projection,
        `c14-${tenant.fixtureId}-${projection.toLowerCase()}`,
        createdAt,
      ],
    );
  }
  await adminPool.query(
    `UPDATE aios_core.tenant_registry
        SET state='ACTIVE',lifecycle_version=2,updated_at=$2
      WHERE tenant_id=$1`,
    [tenant.tenantId, `2026-07-26T10:1${index}:00.000Z`],
  );
  await adminPool.query(
    `INSERT INTO aios_data.tenant_data_lifecycle (
       tenant_id,tenant_kind,lifecycle_version,generation,
       operation_id,state,last_event_id,updated_at
     ) VALUES ($1,'SYNTHETIC',2,1,$2,'ACTIVE',$3,$4)`,
    [
      tenant.tenantId,
      tenant.operationId,
      `c14-active-${tenant.fixtureId}`,
      `2026-07-26T10:1${index}:00.000Z`,
    ],
  );
}

function createGateway(store, provider, tenant, idFactory) {
  const catalog = createSyntheticModelCatalog(catalogDocument);
  const stablePrincipalRegistry = {
    async resolveActionIdentity() {
      return identity(tenant.tenantId);
    },
  };
  const authorizer = {
    async enforce(_context, value) {
      const current = identity(tenant.tenantId);
      return {
        trustSource: "C06_BOUND_DECISION_EVIDENCE",
        decisionId: `decision-${tenant.fixtureId}`,
        evidenceRef: `evidence://c14/${tenant.fixtureId}`,
        policyVersion: "c06-model-1",
        tenantId: tenant.tenantId,
        surface: "MANAGE",
        resourceId: value.resourceId,
        humanPrincipalId: HUMAN,
        humanSecurityEpoch: 1,
        workloadActorPrincipalId: ACTOR,
        workloadActorSecurityEpoch: 1,
        leafDelegationId: DELEGATION,
        delegationChainSha256: modelGatewaySha256(
          current.delegationChain,
        ),
        purposeRef: current.purposeRef,
      };
    },
  };
  return createModelGateway({
    tenantRegistry: {
      async admitNewRequest() {
        return {
          tenantId: tenant.tenantId,
          tenantKind: "SYNTHETIC",
          lifecycleVersion: 2,
          trustSource: "VERIFIED_SERVER_CONTEXT",
        };
      },
    },
    stablePrincipalRegistry,
    authorizer,
    catalog,
    dataPolicyResolver:
      createC14SyntheticDataPolicyResolver(dataPolicyDocument),
    providerInvoker: provider,
    store,
    idFactory,
    clock: () => "2026-07-26T12:00:00.000Z",
  });
}

test("C14 PostgreSQL route ledger is isolated, durable, and least privilege", async (t) => {
  const adminPool = new Pool(config());
  const runtimePool = new Pool(config(RUNTIME_LOGIN));
  const scopePool = new Pool(config(SCOPE_LOGIN));
  t.after(async () => {
    await Promise.all([runtimePool.end(), scopePool.end()]);
    await adminPool.end();
  });

  const safety = await adminPool.query(
    `SELECT current_database() AS database,
            to_regnamespace('aios_model') AS model_schema`,
  );
  assert.match(safety.rows[0].database, /^c14_test_[0-9]+$/);
  assert.equal(safety.rows[0].model_schema, null);

  for (const migration of migrations) await adminPool.query(migration);
  await adminPool.query(`CREATE ROLE ${RUNTIME_LOGIN} LOGIN`);
  await adminPool.query(`CREATE ROLE ${SCOPE_LOGIN} LOGIN`);
  await adminPool.query(
    `GRANT aios_c14_runtime TO ${RUNTIME_LOGIN};
     GRANT aios_c07_scope_runtime TO ${SCOPE_LOGIN};`,
  );
  for (const [index, tenant] of TENANTS.entries()) {
    await seedTenant(adminPool, tenant, index);
  }

  const store = createPostgresModelGatewayStore({
    runtimePool,
    scopePool,
  });
  const provider = createC14SyntheticModelProvider();
  const idFactory = deterministicIds();

  await t.test("three Synthetic Tenants route independently", async () => {
    const results = [];
    for (const tenant of TENANTS) {
      const gateway = createGateway(
        store,
        provider,
        tenant,
        idFactory,
      );
      results.push(
        await gateway.route(
          context(tenant.tenantId),
          routeRequest(tenant),
        ),
      );
    }
    assert.deepEqual(
      results.map((result) => result.route.selectedModel.plane),
      TENANTS.map((tenant) => tenant.expectedPlane),
    );
    assert.equal(new Set(results.map((result) => result.route.routeId)).size, 3);
    for (const [index, tenant] of TENANTS.entries()) {
      const own = await store.readRoute(
        scope(tenant.tenantId, `own-${index}`),
        results[index].route.routeId,
      );
      assert.equal(own.tenantId, tenant.tenantId);
      const other = TENANTS[(index + 1) % TENANTS.length];
      const cross = await store.readRoute(
        scope(other.tenantId, `cross-${index}`),
        results[index].route.routeId,
      );
      assert.equal(cross, null);
    }
  });

  await t.test("retry does not duplicate route or provider billing", async () => {
    const tenant = TENANTS[0];
    const localProvider = createC14SyntheticModelProvider();
    const gateway = createGateway(
      store,
      localProvider,
      tenant,
      idFactory,
    );
    const first = await gateway.route(
      context(tenant.tenantId),
      routeRequest(tenant, "retry"),
    );
    const second = await gateway.route(
      context(tenant.tenantId),
      routeRequest(tenant, "retry"),
    );
    assert.equal(second.duplicate, true);
    assert.equal(second.route.routeId, first.route.routeId);
    assert.equal(localProvider.calls.length, 1);
    const count = await adminPool.query(
      `SELECT count(*)::int AS count
         FROM aios_model.model_route
        WHERE tenant_id=$1 AND idempotency_key=$2`,
      [tenant.tenantId, "c14-retry"],
    );
    assert.equal(count.rows[0].count, 1);
  });

  await t.test("provider acknowledgement loss resumes one prepared route", async () => {
    const tenant = TENANTS[1];
    const underlying = createC14SyntheticModelProvider();
    let lost = false;
    const uncertain = {
      async invoke(value) {
        const receipt = await underlying.invoke(value);
        if (!lost) {
          lost = true;
          throw new Error("synthetic provider acknowledgement loss");
        }
        return receipt;
      },
    };
    const gateway = createGateway(
      store,
      uncertain,
      tenant,
      idFactory,
    );
    const value = routeRequest(tenant, "ack-loss");
    await assert.rejects(
      gateway.route(context(tenant.tenantId), value),
      (error) =>
        error instanceof ModelGatewayError &&
        error.code === "PROVIDER_UNAVAILABLE",
    );
    const prepared = await adminPool.query(
      `SELECT status,count(*)::int AS count
         FROM aios_model.model_route
        WHERE tenant_id=$1 AND idempotency_key=$2
        GROUP BY status`,
      [tenant.tenantId, "c14-ack-loss"],
    );
    assert.deepEqual(prepared.rows, [{ status: "PREPARED", count: 1 }]);
    const recovered = await gateway.route(
      context(tenant.tenantId),
      value,
    );
    assert.equal(recovered.route.status, "SUCCEEDED");
    assert.equal(underlying.calls.length, 1);
  });

  await t.test("runtime role cannot bypass scope, delete, or mutate history", async () => {
    const privileges = await adminPool.query(
      `SELECT
         has_table_privilege($1,'aios_model.model_route','SELECT') AS can_select,
         has_table_privilege($1,'aios_model.model_route','INSERT') AS can_insert,
         has_table_privilege($1,'aios_model.model_route','UPDATE') AS can_update,
         has_table_privilege($1,'aios_model.model_route','DELETE') AS can_delete,
         r.rolsuper,
         r.rolbypassrls
       FROM pg_roles r WHERE r.rolname=$1`,
      [RUNTIME_LOGIN],
    );
    assert.deepEqual(privileges.rows[0], {
      can_select: true,
      can_insert: true,
      can_update: true,
      can_delete: false,
      rolsuper: false,
      rolbypassrls: false,
    });
    await assert.rejects(
      runtimePool.query(
        `INSERT INTO aios_model.model_route (
           tenant_id,tenant_kind,route_id,status,version,idempotency_key,
           request_hash,correlation_id,task_ref,input_ref,input_sha256,
           data_classification,required_plane,tenant_region,catalog_version,
           catalog_sha256,tenant_policy_version,authorization_evidence,
           identity_binding,evaluated_candidates,candidate_bindings,
           reserved_input_tokens,reserved_output_tokens,
           reserved_cost_microusd,created_at,updated_at
         ) VALUES (
           $1,'SYNTHETIC',
           'mrt_018f0000-0000-7000-8000-000000009999',
           'PREPARED',1,'direct',
           'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
           'direct','synthetic://c14/tasks/chat',
           'synthetic://c14/inputs/public-summary',
           'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
           'PUBLIC','ANY','CN','catalog',
           'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
           'policy','{}'::jsonb,'{}'::jsonb,'[]'::jsonb,
           '[{"modelRef":"x"}]'::jsonb,1,1,0,now(),now()
         )`,
        [TENANTS[0].tenantId],
      ),
      (error) => error?.code === "42501",
    );
    const existing = await adminPool.query(
      `SELECT tenant_id,route_id FROM aios_model.model_route
       ORDER BY created_at LIMIT 1`,
    );
    await assert.rejects(
      adminPool.query(
        `UPDATE aios_model.model_route
            SET task_ref='synthetic://c14/tasks/changed'
          WHERE tenant_id=$1 AND route_id=$2`,
        [existing.rows[0].tenant_id, existing.rows[0].route_id],
      ),
      (error) =>
        error?.constraint === "model_route_transition_guard",
    );
    await assert.rejects(
      adminPool.query(
        `DELETE FROM aios_model.model_route
          WHERE tenant_id=$1 AND route_id=$2`,
        [existing.rows[0].tenant_id, existing.rows[0].route_id],
      ),
      (error) => error?.constraint === "model_route_delete_guard",
    );
  });

  await t.test("persisted ledger contains no prompt, input body, URL, or credential", async () => {
    const rows = await adminPool.query(
      `SELECT row_to_json(r)::text AS serialized
         FROM aios_model.model_route r`,
    );
    for (const row of rows.rows) {
      assert.doesNotMatch(
        row.serialized,
        /"prompt"|"inputBody"|https?:\/\/|api[_-]?key|password/i,
      );
    }
  });
});
