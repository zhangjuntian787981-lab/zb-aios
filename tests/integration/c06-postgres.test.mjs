import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import pg from "pg";
import {
  AuthorizationError,
  buildSyntheticPolicyTuples,
  createAuthorizationFacade,
  createSyntheticAuthorizationCatalog,
  hashSyntheticPolicyTuples,
} from "../../lib/authorization-facade.mjs";
import { createPostgresAuthorizationStore } from "../../lib/postgres-authorization-store.mjs";

const { Pool } = pg;
const migrationUrls = [
  "../../implementation/p1/c03/postgresql/0001_tenant_registry.sql",
  "../../implementation/p1/c06/postgresql/0009_authorization.sql",
].map((path) => new URL(path, import.meta.url));
const migrations = await Promise.all(
  migrationUrls.map((url) => readFile(url, "utf8")),
);
const catalogUrls = {
  policyCatalog:
    "../../implementation/p1/c06/synthetic-policy-catalog.v1.json",
  protectedOperations:
    "../../implementation/p1/c06/protected-operations.v1.json",
  fixtures:
    "../../implementation/p1/c06/synthetic-authorization-fixtures.v1.json",
  model:
    "../../implementation/p1/c06/openfga/authorization-model.v1.json",
};
const catalogParts = Object.fromEntries(
  await Promise.all(
    Object.entries(catalogUrls).map(async ([name, path]) => [
      name,
      JSON.parse(await readFile(new URL(path, import.meta.url), "utf8")),
    ]),
  ),
);
const authorizationCatalog =
  createSyntheticAuthorizationCatalog(catalogParts);

const TENANT_ID = "stn_01984900-0000-7000-8000-000000000001";
const FIXTURE_ID = "synthetic-tenant-northstar-fasteners";
const TEMPLATE_ONE = "fixture://c06/policy-release/baseline-v1";
const FACADE_HUMAN_ID =
  "prn_01984900-0000-7000-8000-0000000003b6";
const FACADE_ACTOR_ID =
  "prn_01984900-0000-7000-8000-0000000003b7";
const FACADE_NOAH_ID =
  "prn_01984900-0000-7000-8000-0000000003b8";
const FACADE_DELEGATION_ID =
  "dlg_01984900-0000-7000-8000-0000000003b9";
const NOW = "2026-07-26T08:00:00.000Z";
const LATER = "2026-07-26T08:01:00.000Z";
const STORE_ONE = "01ARZ3NDEKTSV4RRFFQ69G5FAV";
const MODEL_ONE = "01ARZ3NDEKTSV4RRFFQ69G5FAW";
const STORE_TWO = "01ARZ3NDEKTSV4RRFFQ69G5FAX";
const MODEL_TWO = "01ARZ3NDEKTSV4RRFFQ69G5FAY";
const PROJECTIONS = [
  "AUTHORIZATION",
  "IDENTITY",
  "KNOWLEDGE",
  "SECRET_REFS",
  "STORAGE",
];

function hash(character) {
  return `sha256:${character.repeat(64)}`;
}

function uuid(counter) {
  return `01984900-0000-7000-8000-${counter
    .toString(16)
    .padStart(12, "0")}`;
}

function postgresConfig() {
  if (process.env.C06_TEST_EPHEMERAL !== "1") {
    throw new Error("C06_TEST_EPHEMERAL=1 is required.");
  }
  for (const name of [
    "C06_TEST_PGHOST",
    "C06_TEST_PGPORT",
    "C06_TEST_PGDATABASE",
    "C06_TEST_PGUSER",
  ]) {
    if (!process.env[name]) throw new Error(`${name} is required.`);
  }
  return {
    host: process.env.C06_TEST_PGHOST,
    port: Number(process.env.C06_TEST_PGPORT),
    database: process.env.C06_TEST_PGDATABASE,
    user: process.env.C06_TEST_PGUSER,
    max: 48,
  };
}

const pool = new Pool(postgresConfig());
const store = createPostgresAuthorizationStore({ pool });

async function resetDatabase() {
  await pool.query("TRUNCATE TABLE aios_core.tenant_registry CASCADE");
}

async function seedActiveTenant() {
  await pool.query(
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
       $1, 'SYNTHETIC', 'PROVISIONING', 1, 1,
       'c06:postgres:tenant',
       'fixture://c06/postgres/tenant',
       $2,
       '[]'::jsonb,
       $3,
       $4,
       $5,
       $5
     )`,
    [
      TENANT_ID,
      hash("1"),
      `sns_${uuid(2)}`,
      `op_${uuid(3)}`,
      NOW,
    ],
  );
  for (const projection of PROJECTIONS) {
    await pool.query(
      `INSERT INTO aios_core.tenant_projection (
         tenant_id,
         generation,
         projection,
         desired_action,
         status,
         attempt_count,
         updated_at
       ) VALUES ($1, 1, $2, 'PROVISION', 'READY', 1, $3)`,
      [TENANT_ID, projection, NOW],
    );
  }
  await pool.query(
    `UPDATE aios_core.tenant_registry
        SET state = 'ACTIVE',
            lifecycle_version = 2,
            updated_at = $2
      WHERE tenant_id = $1`,
    [TENANT_ID, LATER],
  );
}

function release(sequence) {
  return {
    policyReleaseId: `azr_${uuid(10 + sequence)}`,
    tenantId: TENANT_ID,
    tenantKind: "SYNTHETIC",
    tenantLifecycleVersion: 2,
    fixtureId: "synthetic-tenant-c06-postgres",
    templateRef: `fixture://c06/policy/release-${sequence}`,
    templateSequence: sequence,
    bundleSha256: sequence === 1 ? hash("2") : hash("3"),
    modelSha256: hash("4"),
    operationCatalogVersion: "c06-protected-operations-v1",
    fixtureVersion: "c06-fixtures-v1",
    state: "STAGED",
    createdAt: NOW,
    updatedAt: NOW,
  };
}

function readyRelease(value) {
  return {
    ...value,
    state: "READY",
    projectionOperationId: `c06-project-${value.templateSequence}`,
    openFgaStoreId:
      value.templateSequence === 1 ? STORE_ONE : STORE_TWO,
    authorizationModelId:
      value.templateSequence === 1 ? MODEL_ONE : MODEL_TWO,
    tupleBundleSha256:
      value.templateSequence === 1 ? hash("9") : hash("a"),
    fixtureReportRef:
      `evidence://c06/projection/${value.templateSequence}`,
    fixtureReportSha256: hash("5"),
    fixturePassCount: 30,
    fixtureFailCount: 0,
    updatedAt: LATER,
  };
}

function event({
  counter,
  type,
  subject,
  correlationId,
  data = {},
}) {
  return {
    specversion: "1.0",
    id: `evt_${uuid(counter)}`,
    source: "/product-core/authorization",
    type,
    subject,
    time: LATER,
    datacontenttype: "application/json",
    tenantkind: "SYNTHETIC",
    correlationid: correlationId,
    synthetic: true,
    data: {
      tenant_id: TENANT_ID,
      ...data,
    },
  };
}

async function runCommand(selectedStore, key, reducer) {
  return selectedStore.runCommand(
    {
      tenantId: TENANT_ID,
      idempotencyKey: key,
      commandHash: hash(
        (Number.parseInt(key.replace(/\D/g, ""), 10) % 10)
          .toString(16),
      ),
    },
    reducer,
  );
}

async function stage(selectedStore, value, key, counter) {
  const stagedEvent = event({
    counter,
    type: "product.authorization.policy-release-staged.v1",
    subject: value.policyReleaseId,
    correlationId: key,
    data: {
      policy_release_id: value.policyReleaseId,
      template_ref: value.templateRef,
      bundle_sha256: value.bundleSha256,
    },
  });
  return runCommand(selectedStore, key, async (transaction) => {
    const existing = await transaction.findReleaseByTemplate(
      TENANT_ID,
      value.templateRef,
    );
    if (existing) return { ...existing, duplicate: true };
    await transaction.insertRelease(value);
    await transaction.appendEvent(stagedEvent);
    return value;
  });
}

async function project(selectedStore, staged, key, counter) {
  const ready = readyRelease(staged);
  const projectionEvent = event({
    counter,
    type: "product.authorization.policy-projection-recorded.v1",
    subject: staged.policyReleaseId,
    correlationId: key,
    data: {
      policy_release_id: staged.policyReleaseId,
      projection_outcome: "READY",
      bundle_sha256: staged.bundleSha256,
    },
  });
  await runCommand(selectedStore, key, async (transaction) => {
    const current = await transaction.findRelease(staged.policyReleaseId);
    assert.equal(current.state, "STAGED");
    await transaction.putRelease(ready);
    await transaction.appendEvent(projectionEvent);
    return ready;
  });
  return ready;
}

async function activate(
  selectedStore,
  target,
  {
    key,
    counter,
    activationCounter,
    expectedVersion,
    kind = "ACTIVATE",
  },
) {
  return runCommand(selectedStore, key, async (transaction) => {
    const current = await transaction.activePolicy(TENANT_ID);
    if ((current?.activationVersion ?? 0) !== expectedVersion) {
      throw new AuthorizationError(
        "ACTIVATION_CONFLICT",
        "Policy activation changed.",
      );
    }
    const activation = {
      activationId: `aza_${uuid(activationCounter)}`,
      tenantId: TENANT_ID,
      tenantKind: "SYNTHETIC",
      policyReleaseId: target.policyReleaseId,
      previousPolicyReleaseId: current?.policyReleaseId ?? null,
      templateSequence: target.templateSequence,
      activationVersion: expectedVersion + 1,
      activationKind: kind,
      reasonRef: `fixture://c06/activation/${key}`,
      activatedAt: LATER,
    };
    await transaction.activate(activation);
    await transaction.appendEvent(
      event({
        counter,
        type:
          kind === "ROLLBACK"
            ? "product.authorization.policy-rolled-back.v1"
            : "product.authorization.policy-activated.v1",
        subject: activation.activationId,
        correlationId: key,
        data: {
          policy_release_id: target.policyReleaseId,
          previous_policy_release_id:
            activation.previousPolicyReleaseId,
          activation_version: activation.activationVersion,
        },
      }),
    );
    return activation;
  });
}

async function prepareActiveReleaseOne() {
  const first = release(1);
  await stage(store, first, "stage-1", 101);
  const ready = await project(store, first, "project-1", 102);
  await activate(store, ready, {
    key: "activate-1",
    counter: 103,
    activationCounter: 104,
    expectedVersion: 0,
  });
  return ready;
}

function decision(releaseValue, counter = 201) {
  return {
    decisionId: `azd_${uuid(counter)}`,
    tenantId: TENANT_ID,
    tenantKind: "SYNTHETIC",
    correlationId: `c06-decision-${counter}`,
    surface: "READ",
    resourceType: "protected_resource",
    resourceId: "synthetic-tenant-c06-postgres--read",
    resourceAuthorizationVersion: 1,
    humanPrincipalId: `prn_${uuid(202)}`,
    humanSecurityEpoch: 1,
    workloadActorPrincipalId: `prn_${uuid(203)}`,
    workloadActorSecurityEpoch: 1,
    leafDelegationId: `dlg_${uuid(204)}`,
    delegationChainSha256: hash("6"),
    purposeRef: "fixture://c06/purpose/read",
    policyReleaseId: releaseValue.policyReleaseId,
    bundleSha256: releaseValue.bundleSha256,
    tupleBundleSha256: releaseValue.tupleBundleSha256,
    openFgaStoreId: releaseValue.openFgaStoreId,
    authorizationModelId: releaseValue.authorizationModelId,
    activationVersion: 1,
    consistency: "HIGHER_CONSISTENCY",
    effect: "ALLOW",
    authorizationStatus: "ALLOWED",
    reasonCode: "ALL_FACTORS_ALLOWED",
    inputSha256: hash("7"),
    checkTuples: {
      human: {
        user: `human:prn_${uuid(202)}`,
        relation: "can_read",
        object: "protected_resource:fixture-read",
      },
    },
    checkResults: { human: true, actor: true, purpose: true },
    checkResultSha256: hash("8"),
    evaluatedAt: LATER,
    evidenceRef: `evidence://c06/decisions/azd_${uuid(counter)}`,
  };
}

function decisionEvent(value, counter = 205) {
  return event({
    counter,
    type: "product.authorization.decision-recorded.v1",
    subject: value.decisionId,
    correlationId: value.correlationId,
    data: {
      decision_id: value.decisionId,
      policy_release_id: value.policyReleaseId,
      tuple_bundle_sha256: value.tupleBundleSha256,
      authorization_model_id: value.authorizationModelId,
      activation_version: value.activationVersion,
      effect: value.effect,
      reason_code: value.reasonCode,
      input_sha256: value.inputSha256,
    },
  });
}

function crashAfterSqlPool(fragment) {
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
            sql.includes(fragment)
          ) {
            terminated = true;
            const ended = new Promise((resolve) => {
              client.once("error", resolve);
            });
            const killed = await pool.query(
              "SELECT pg_terminate_backend($1) AS killed",
              [backendPid],
            );
            assert.equal(killed.rows[0].killed, true);
            await ended;
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

function decisionBarrierPool() {
  let signalReached;
  let releaseBarrier;
  const reached = new Promise((resolve) => {
    signalReached = resolve;
  });
  const barrier = new Promise((resolve) => {
    releaseBarrier = resolve;
  });
  let paused = false;
  return {
    reached,
    release: releaseBarrier,
    pool: {
      async connect() {
        const client = await pool.connect();
        return {
          async query(sql, parameters = []) {
            const result = await client.query(sql, parameters);
            if (
              !paused &&
              typeof sql === "string" &&
              sql.includes(
                "SELECT policy_release_id, activation_version",
              ) &&
              sql.includes("FOR SHARE")
            ) {
              paused = true;
              signalReached();
              await barrier;
            }
            return result;
          },
          release() {
            client.release();
          },
        };
      },
    },
  };
}

function tupleKey(value) {
  return `${value.user}|${value.relation}|${value.object}`;
}

function deterministicFacadeIds() {
  let counter = 1000;
  return () => {
    counter += 1;
    return uuid(counter);
  };
}

function createPostgresFacadeHarness() {
  const principalIdsByFixtureRef = {
    [`fixture://${FIXTURE_ID}/principals/ava`]: FACADE_HUMAN_ID,
    [`fixture://${FIXTURE_ID}/principals/assistant-agent`]:
      FACADE_ACTOR_ID,
    [`fixture://${FIXTURE_ID}/principals/noah`]: FACADE_NOAH_ID,
  };
  const tupleBundle = buildSyntheticPolicyTuples({
    catalog: authorizationCatalog,
    templateRef: TEMPLATE_ONE,
    fixtureId: FIXTURE_ID,
    principalIdsByFixtureRef,
  });
  const tupleBundleSha256 = hashSyntheticPolicyTuples(tupleBundle);
  const tupleSet = new Set(tupleBundle.map(tupleKey));
  const tenantRegistry = {
    async admitNewRequest({ tenantId, expectedTenantKind }) {
      const result = await pool.query(
        `SELECT tenant_kind, state, lifecycle_version
           FROM aios_core.tenant_registry
          WHERE tenant_id = $1`,
        [tenantId],
      );
      const tenant = result.rows[0];
      if (
        tenant?.tenant_kind !== expectedTenantKind ||
        tenant.state !== "ACTIVE"
      ) {
        throw new AuthorizationError(
          "TENANT_NOT_ACTIVE",
          "The Synthetic Tenant is not active.",
        );
      }
      return {
        tenantId,
        tenantKind: tenant.tenant_kind,
        lifecycleVersion: Number(tenant.lifecycle_version),
        trustSource: "VERIFIED_SERVER_CONTEXT",
      };
    },
  };
  const stablePrincipalRegistry = {
    async resolveActionIdentity() {
      return {
        tenantId: TENANT_ID,
        tenantKind: "SYNTHETIC",
        identityAccountId:
          "sia_01984900-0000-7000-8000-0000000003ba",
        identityLinkId:
          "lnk_01984900-0000-7000-8000-0000000003bb",
        sessionId: "ses_01984900-0000-7000-8000-0000000003bc",
        humanSubject: {
          principalId: FACADE_HUMAN_ID,
          principalType: "HUMAN",
          lifecycleVersion: 1,
          securityEpoch: 1,
        },
        workloadActor: {
          principalId: FACADE_ACTOR_ID,
          principalType: "AGENT",
          lifecycleVersion: 1,
          securityEpoch: 1,
        },
        purposeRef: "synthetic://c06/purpose/read",
        delegationChain: [
          {
            delegationId: FACADE_DELEGATION_ID,
            delegatorPrincipalId: FACADE_HUMAN_ID,
            delegatePrincipalId: FACADE_ACTOR_ID,
            purposeRef: "synthetic://c06/purpose/read",
            lifecycleVersion: 1,
            expiresAt: "2026-07-27T00:00:00.000Z",
          },
        ],
        trustSource:
          "VERIFIED_SESSION_IDENTITY_LINK_AND_WORKLOAD_CONTEXT",
        authorizationStatus: "NOT_EVALUATED",
      };
    },
  };
  const facade = createAuthorizationFacade({
    store,
    tenantRegistry,
    stablePrincipalRegistry,
    policyCatalog: authorizationCatalog,
    async resolveTenantFixture(tenantId) {
      return {
        tenantId,
        tenantKind: "SYNTHETIC",
        fixtureId: FIXTURE_ID,
      };
    },
    async resolveResource({
      tenantId,
      tenantKind,
      surface,
      resourceId,
    }) {
      return {
        tenantId,
        tenantKind,
        resourceType:
          authorizationCatalog.operation(surface).resource_type,
        resourceId,
        state: "ACTIVE",
        authorizationVersion: 1,
        trustSource: "VERIFIED_RESOURCE_CONTEXT",
      };
    },
    pdpFactory: ({ storeId, authorizationModelId }) => ({
      async check({ authorizationModelId: requestedModelId, tupleKey: key }) {
        return {
          allowed: tupleSet.has(tupleKey(key)),
          storeId,
          authorizationModelId:
            requestedModelId === authorizationModelId
              ? authorizationModelId
              : "mismatch",
          consistency: "HIGHER_CONSISTENCY",
        };
      },
    }),
    async verifyPolicyRelease(value) {
      return {
        passed: true,
        fixturePassCount: value.fixturePassCount,
        fixtureFailCount: value.fixtureFailCount,
        policyBundleSha256: value.bundleSha256,
        tupleBundleSha256: value.tupleBundleSha256,
        fixtureReportSha256: value.fixtureReportSha256,
        modelSha256: value.modelSha256,
        openFgaStoreId: value.openFgaStoreId,
        authorizationModelId: value.authorizationModelId,
      };
    },
    authorizeControl: (context, capability) =>
      context?.capabilities?.includes(capability) === true,
    clock: () => LATER,
    idFactory: deterministicFacadeIds(),
  });
  return {
    facade,
    tupleBundleSha256,
    control: {
      actorId: "synthetic-authorization-admin",
      projectionTrustSource: "VERIFIED_PROJECTION_WORKER",
      capabilities: [
        "AUTHORIZATION_POLICY_STAGE",
        "AUTHORIZATION_POLICY_PROJECT",
        "AUTHORIZATION_POLICY_ACTIVATE",
        "AUTHORIZATION_GOVERNANCE_READ",
      ],
    },
    serverContext: {
      synthetic: true,
      routeTrustSource: "VERIFIED_ROUTE_DESCRIPTOR",
      tenantId: TENANT_ID,
      surface: "READ",
      workloadTrustSource: "VERIFIED_WORKLOAD_CONTEXT",
      workloadActorPrincipalId: FACADE_ACTOR_ID,
    },
    request: {
      sessionToken: "synthetic-postgres-session",
      delegationId: FACADE_DELEGATION_ID,
      resourceId: `${FIXTURE_ID}--read`,
      correlationId: "c06-postgres-facade-decision",
    },
  };
}

test("C06 PostgreSQL 17.10 authorization invariants", async (t) => {
  t.after(async () => {
    await pool.end();
  });

  const safety = await pool.query(
    "SELECT current_database() AS database, to_regnamespace('aios_core') AS schema",
  );
  assert.match(safety.rows[0].database, /^c06_test_[0-9]+$/);
  assert.equal(safety.rows[0].schema, null);
  for (const migration of migrations) {
    await pool.query(migration);
  }
  const version = await pool.query("SHOW server_version_num");
  assert.equal(Number(version.rows[0].server_version_num), 170010);

  await t.test("PG-01 creates exactly seven C06 tables", async () => {
    const result = await pool.query(`
      SELECT table_name
        FROM information_schema.tables
       WHERE table_schema = 'aios_core'
         AND table_name LIKE 'authorization_%'
       ORDER BY table_name
    `);
    assert.deepEqual(
      result.rows.map(({ table_name }) => table_name),
      [
        "authorization_activation",
        "authorization_active_policy",
        "authorization_command_receipt",
        "authorization_decision",
        "authorization_event",
        "authorization_outbox",
        "authorization_policy_release",
      ],
    );
  });

  await t.test("PG-02 serializes concurrent exact command replay", async () => {
    await resetDatabase();
    await seedActiveTenant();
    const first = release(1);
    const results = await Promise.all(
      Array.from({ length: 16 }, () =>
        stage(store, first, "stage-16", 301),
      ),
    );
    assert.equal(
      results.filter(({ duplicate }) => duplicate === false).length,
      1,
    );
    assert.equal(
      results.filter(({ duplicate }) => duplicate === true).length,
      15,
    );
    const counts = await pool.query(`
      SELECT
        (SELECT count(*) FROM aios_core.authorization_policy_release) AS releases,
        (SELECT count(*) FROM aios_core.authorization_command_receipt) AS receipts,
        (SELECT count(*) FROM aios_core.authorization_event) AS events,
        (SELECT count(*) FROM aios_core.authorization_outbox) AS outbox
    `);
    assert.deepEqual(
      Object.values(counts.rows[0]).map(Number),
      [1, 1, 1, 1],
    );
  });

  await t.test("PG-03 backend termination rolls back the whole command", async () => {
    await resetDatabase();
    await seedActiveTenant();
    const crashStore = createPostgresAuthorizationStore({
      pool: crashAfterSqlPool(
        'INSERT INTO "aios_core"."authorization_command_receipt"',
      ),
      maxSerializableRetries: 0,
    });
    await assert.rejects(
      stage(crashStore, release(1), "stage-crash-3", 302),
      (error) => error.code === "STORE_UNAVAILABLE",
    );
    const counts = await pool.query(`
      SELECT
        (SELECT count(*) FROM aios_core.authorization_policy_release) AS releases,
        (SELECT count(*) FROM aios_core.authorization_command_receipt) AS receipts,
        (SELECT count(*) FROM aios_core.authorization_event) AS events,
        (SELECT count(*) FROM aios_core.authorization_outbox) AS outbox
    `);
    assert.deepEqual(
      Object.values(counts.rows[0]).map(Number),
      [0, 0, 0, 0],
    );
  });

  await t.test("PG-04 rejects an Event without its exact Outbox pair", async () => {
    await resetDatabase();
    await seedActiveTenant();
    const orphan = event({
      counter: 303,
      type: "product.authorization.policy-release-staged.v1",
      subject: `azr_${uuid(11)}`,
      correlationId: "orphan-event",
    });
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      await client.query(
        `INSERT INTO aios_core.authorization_event (
           event_id, tenant_id, tenant_kind, event, created_at
         ) VALUES ($1, $2, 'SYNTHETIC', $3::jsonb, $4)`,
        [orphan.id, TENANT_ID, JSON.stringify(orphan), LATER],
      );
      await assert.rejects(
        client.query("COMMIT"),
        (error) =>
          error.constraint ===
          "authorization_event_outbox_pair_guard",
      );
    } finally {
      await client.query("ROLLBACK").catch(() => {});
      client.release();
    }
    const count = await pool.query(
      "SELECT count(*) FROM aios_core.authorization_event",
    );
    assert.equal(Number(count.rows[0].count), 0);
  });

  await t.test("PG-05 one activation wins and verified rollback advances version", async () => {
    await resetDatabase();
    await seedActiveTenant();
    const first = release(1);
    const second = release(2);
    await stage(store, first, "stage-51", 304);
    const readyOne = await project(store, first, "project-51", 305);
    await stage(store, second, "stage-52", 306);
    const readyTwo = await project(store, second, "project-52", 307);
    await activate(store, readyOne, {
      key: "activate-51",
      counter: 308,
      activationCounter: 309,
      expectedVersion: 0,
    });
    const results = await Promise.allSettled([
      activate(store, readyTwo, {
        key: "activate-52",
        counter: 310,
        activationCounter: 311,
        expectedVersion: 1,
      }),
      activate(store, readyTwo, {
        key: "activate-53",
        counter: 312,
        activationCounter: 313,
        expectedVersion: 1,
      }),
    ]);
    assert.equal(
      results.filter(({ status }) => status === "fulfilled").length,
      1,
    );
    const rejected = results.find(({ status }) => status === "rejected");
    assert.equal(rejected.reason.code, "ACTIVATION_CONFLICT");
    const activeTwo = await store.readActiveRelease(TENANT_ID);
    assert.equal(activeTwo.active.activationVersion, 2);
    assert.equal(activeTwo.release.policyReleaseId, readyTwo.policyReleaseId);

    await activate(store, readyOne, {
      key: "rollback-54",
      counter: 314,
      activationCounter: 315,
      expectedVersion: 2,
      kind: "ROLLBACK",
    });
    const rolledBack = await store.readActiveRelease(TENANT_ID);
    assert.equal(rolledBack.active.activationVersion, 3);
    assert.equal(rolledBack.active.activationKind, "ROLLBACK");
    assert.equal(
      rolledBack.release.policyReleaseId,
      readyOne.policyReleaseId,
    );
  });

  await t.test("PG-06 records Decision, Event and Outbox atomically", async () => {
    await resetDatabase();
    await seedActiveTenant();
    const ready = await prepareActiveReleaseOne();
    assert.notEqual(ready.tupleBundleSha256, ready.bundleSha256);
    const value = decision(ready);
    const recorded = await store.recordDecision({
      tenantId: TENANT_ID,
      expectedPolicyReleaseId: ready.policyReleaseId,
      expectedActivationVersion: 1,
      decision: value,
      event: decisionEvent(value),
    });
    assert.deepEqual(recorded, value);
    assert.deepEqual(await store.readDecision(value.decisionId), value);
    const evidence = await pool.query(
      `SELECT
         (SELECT count(*) FROM aios_core.authorization_decision
           WHERE decision_id = $1) AS decisions,
         (SELECT count(*) FROM aios_core.authorization_event
           WHERE event ->> 'subject' = $1) AS events,
         (SELECT count(*) FROM aios_core.authorization_outbox
           WHERE event ->> 'subject' = $1) AS outbox`,
      [value.decisionId],
    );
    assert.deepEqual(
      Object.values(evidence.rows[0]).map(Number),
      [1, 1, 1],
    );
  });

  await t.test("PG-07 rejects a stale active Policy version", async () => {
    await resetDatabase();
    await seedActiveTenant();
    const readyOne = await prepareActiveReleaseOne();
    const second = release(2);
    await stage(store, second, "stage-71", 401);
    const readyTwo = await project(store, second, "project-71", 402);
    await activate(store, readyTwo, {
      key: "activate-71",
      counter: 403,
      activationCounter: 404,
      expectedVersion: 1,
    });
    const stale = decision(readyOne, 405);
    await assert.rejects(
      store.recordDecision({
        tenantId: TENANT_ID,
        expectedPolicyReleaseId: readyOne.policyReleaseId,
        expectedActivationVersion: 1,
        decision: stale,
        event: decisionEvent(stale, 406),
      }),
      (error) => error.code === "AUTHORIZATION_CHANGED",
    );
    assert.equal(await store.readDecision(stale.decisionId), null);
  });

  await t.test("PG-08 Tenant suspension after preflight blocks Decision commit", async () => {
    await resetDatabase();
    await seedActiveTenant();
    const ready = await prepareActiveReleaseOne();
    const value = decision(ready, 501);
    const gate = decisionBarrierPool();
    const gatedStore = createPostgresAuthorizationStore({
      pool,
      decisionPool: gate.pool,
      maxSerializableRetries: 1,
    });
    const pending = gatedStore.recordDecision({
      tenantId: TENANT_ID,
      expectedPolicyReleaseId: ready.policyReleaseId,
      expectedActivationVersion: 1,
      decision: value,
      event: decisionEvent(value, 502),
    });
    await gate.reached;
    await pool.query(
      `UPDATE aios_core.tenant_registry
          SET state = 'SUSPENDED',
              lifecycle_version = lifecycle_version + 1,
              updated_at = $2
        WHERE tenant_id = $1`,
      [TENANT_ID, "2026-07-26T08:02:00.000Z"],
    );
    gate.release();
    await assert.rejects(
      pending,
      (error) => error.code === "TENANT_NOT_ACTIVE",
    );
    assert.equal(await store.readDecision(value.decisionId), null);
  });

  await t.test("PG-09 interrupted Decision evidence commit leaves no partial rows", async () => {
    await resetDatabase();
    await seedActiveTenant();
    const ready = await prepareActiveReleaseOne();
    const value = decision(ready, 601);
    const crashStore = createPostgresAuthorizationStore({
      pool,
      decisionPool: crashAfterSqlPool(
        'INSERT INTO "aios_core"."authorization_outbox"',
      ),
      maxSerializableRetries: 0,
    });
    await assert.rejects(
      crashStore.recordDecision({
        tenantId: TENANT_ID,
        expectedPolicyReleaseId: ready.policyReleaseId,
        expectedActivationVersion: 1,
        decision: value,
        event: decisionEvent(value, 602),
      }),
      (error) => error.code === "STORE_UNAVAILABLE",
    );
    const evidence = await pool.query(
      `SELECT
         (SELECT count(*) FROM aios_core.authorization_decision
           WHERE decision_id = $1) AS decisions,
         (SELECT count(*) FROM aios_core.authorization_event
           WHERE event ->> 'subject' = $1) AS events,
         (SELECT count(*) FROM aios_core.authorization_outbox
           WHERE event ->> 'subject' = $1) AS outbox`,
      [value.decisionId],
    );
    assert.deepEqual(
      Object.values(evidence.rows[0]).map(Number),
      [0, 0, 0],
    );
  });

  await t.test("PG-10 Outbox leases reject stale completion", async () => {
    await resetDatabase();
    await seedActiveTenant();
    await stage(store, release(1), "stage-101", 701);
    const claimed = await store.claimOutbox({
      workerId: "c06-postgres-worker",
      limit: 10,
      leaseSeconds: 30,
    });
    assert.equal(claimed.length, 1);
    await store.completeOutbox(claimed[0]);
    await assert.rejects(
      store.completeOutbox(claimed[0]),
      (error) => error.code === "STALE_OUTBOX_LEASE",
    );
    const state = await pool.query(
      `SELECT status, published_at
         FROM aios_core.authorization_outbox
        WHERE event_id = $1`,
      [claimed[0].eventId],
    );
    assert.equal(state.rows[0].status, "PUBLISHED");
    assert.ok(state.rows[0].published_at);
  });

  await t.test("PG-11 terminal and evidence records remain immutable", async () => {
    await resetDatabase();
    await seedActiveTenant();
    const ready = await prepareActiveReleaseOne();
    const value = decision(ready, 801);
    await store.recordDecision({
      tenantId: TENANT_ID,
      expectedPolicyReleaseId: ready.policyReleaseId,
      expectedActivationVersion: 1,
      decision: value,
      event: decisionEvent(value, 802),
    });

    await assert.rejects(
      pool.query(
        `UPDATE aios_core.authorization_policy_release
            SET updated_at = updated_at
          WHERE policy_release_id = $1`,
        [ready.policyReleaseId],
      ),
      (error) =>
        error.constraint === "authorization_release_transition_guard",
    );
    for (const operation of [
      () => pool.query(
        `UPDATE aios_core.authorization_activation
            SET reason_ref = reason_ref
          WHERE activation_version = 1`,
      ),
      () => pool.query(
        `UPDATE aios_core.authorization_decision
            SET reason_code = reason_code
          WHERE decision_id = $1`,
        [value.decisionId],
      ),
      () => pool.query(
        `UPDATE aios_core.authorization_command_receipt
            SET result = result
          WHERE tenant_id = $1`,
        [TENANT_ID],
      ),
      () => pool.query(
        `UPDATE aios_core.authorization_event
            SET created_at = created_at
          WHERE event ->> 'subject' = $1`,
        [value.decisionId],
      ),
    ]) {
      await assert.rejects(
        operation(),
        (error) =>
          error.constraint === "authorization_append_only_guard",
      );
    }
    await assert.rejects(
      pool.query(
        `DELETE FROM aios_core.authorization_active_policy
          WHERE tenant_id = $1`,
        [TENANT_ID],
      ),
      (error) =>
        error.constraint === "authorization_tombstone_no_delete",
    );
  });

  await t.test("PG-12 suspended Tenant cannot finalize a staged Release", async () => {
    await resetDatabase();
    await seedActiveTenant();
    const staged = release(1);
    await stage(store, staged, "stage-121", 901);
    await pool.query(
      `UPDATE aios_core.tenant_registry
          SET state = 'SUSPENDED',
              lifecycle_version = lifecycle_version + 1,
              updated_at = $2
        WHERE tenant_id = $1`,
      [TENANT_ID, "2026-07-26T08:03:00.000Z"],
    );
    await assert.rejects(
      project(store, staged, "project-121", 902),
      (error) => error.code === "TENANT_NOT_ACTIVE",
    );
    const unchanged = await store.readPolicyRelease(
      staged.policyReleaseId,
    );
    assert.equal(unchanged.state, "STAGED");
    const counts = await pool.query(`
      SELECT
        (SELECT count(*) FROM aios_core.authorization_command_receipt)
          AS receipts,
        (SELECT count(*) FROM aios_core.authorization_event) AS events,
        (SELECT count(*) FROM aios_core.authorization_outbox) AS outbox
    `);
    assert.deepEqual(
      Object.values(counts.rows[0]).map(Number),
      [1, 1, 1],
    );
  });

  await t.test("PG-13 runs the real async Facade and PostgreSQL Store chain", async () => {
    await resetDatabase();
    await seedActiveTenant();
    const value = createPostgresFacadeHarness();
    const staged = await value.facade.execute(value.control, {
      kind: "STAGE_SYNTHETIC_POLICY_RELEASE",
      tenantId: TENANT_ID,
      templateRef: TEMPLATE_ONE,
      idempotencyKey: "facade-pg-stage",
      correlationId: "facade-pg-stage-correlation",
    });
    const ready = await value.facade.execute(value.control, {
      kind: "RECORD_POLICY_PROJECTION",
      tenantId: TENANT_ID,
      policyReleaseId: staged.policyReleaseId,
      projectionOperationId: "facade-pg-projection-operation",
      outcome: "READY",
      openFgaStoreId: STORE_ONE,
      authorizationModelId: MODEL_ONE,
      tupleBundleSha256: value.tupleBundleSha256,
      fixtureReportRef: "evidence://c06/facade-pg/projection",
      fixtureReportSha256: hash("b"),
      fixturePassCount: 30,
      fixtureFailCount: 0,
      reasonRef: null,
      idempotencyKey: "facade-pg-project",
      correlationId: "facade-pg-project-correlation",
    });
    assert.notEqual(ready.tupleBundleSha256, ready.bundleSha256);
    const activation = await value.facade.execute(value.control, {
      kind: "ACTIVATE_POLICY_RELEASE",
      tenantId: TENANT_ID,
      policyReleaseId: ready.policyReleaseId,
      expectedActivationVersion: 0,
      reasonRef: "policy://c06/facade-pg/activate",
      idempotencyKey: "facade-pg-activate",
      correlationId: "facade-pg-activate-correlation",
    });
    assert.equal(activation.activationVersion, 1);

    const recorded = await value.facade.decide(
      value.serverContext,
      value.request,
    );
    assert.equal(recorded.effect, "ALLOW");
    assert.equal(recorded.tupleBundleSha256, value.tupleBundleSha256);
    assert.notEqual(recorded.tupleBundleSha256, recorded.bundleSha256);
    assert.deepEqual(
      await store.readDecision(recorded.decisionId),
      recorded,
    );

    const evidence = await pool.query(`
      SELECT
        (SELECT count(*) FROM aios_core.authorization_policy_release)
          AS releases,
        (SELECT count(*) FROM aios_core.authorization_activation)
          AS activations,
        (SELECT count(*) FROM aios_core.authorization_decision)
          AS decisions,
        (SELECT count(*) FROM aios_core.authorization_command_receipt)
          AS receipts,
        (SELECT count(*) FROM aios_core.authorization_event) AS events,
        (SELECT count(*) FROM aios_core.authorization_outbox) AS outbox,
        (
          SELECT bool_and(event.event = outbox.event)
            FROM aios_core.authorization_event AS event
            JOIN aios_core.authorization_outbox AS outbox
              USING (event_id)
        ) AS exact_pairs
    `);
    assert.deepEqual(
      evidence.rows[0],
      {
        releases: "1",
        activations: "1",
        decisions: "1",
        receipts: "3",
        events: "4",
        outbox: "4",
        exact_pairs: true,
      },
    );
  });

  await t.test("PG-14 replaces a failed baseline without deleting its tombstone", async () => {
    await resetDatabase();
    await seedActiveTenant();
    const value = createPostgresFacadeHarness();
    const failedAttempt = await value.facade.execute(value.control, {
      kind: "STAGE_SYNTHETIC_POLICY_RELEASE",
      tenantId: TENANT_ID,
      templateRef: TEMPLATE_ONE,
      idempotencyKey: "facade-pg-failed-stage",
      correlationId: "facade-pg-failed-stage-correlation",
    });
    const failed = await value.facade.execute(value.control, {
      kind: "RECORD_POLICY_PROJECTION",
      tenantId: TENANT_ID,
      policyReleaseId: failedAttempt.policyReleaseId,
      projectionOperationId: "facade-pg-failed-projection",
      outcome: "FAILED",
      openFgaStoreId: null,
      authorizationModelId: null,
      tupleBundleSha256: null,
      fixtureReportRef: null,
      fixtureReportSha256: null,
      fixturePassCount: null,
      fixtureFailCount: null,
      reasonRef: "evidence://c06/facade-pg/projection-failed",
      idempotencyKey: "facade-pg-failed-project",
      correlationId: "facade-pg-failed-project-correlation",
    });
    assert.equal(failed.state, "FAILED");

    const replacement = await value.facade.execute(value.control, {
      kind: "STAGE_SYNTHETIC_POLICY_RELEASE",
      tenantId: TENANT_ID,
      templateRef: TEMPLATE_ONE,
      idempotencyKey: "facade-pg-replacement-stage",
      correlationId: "facade-pg-replacement-stage-correlation",
    });
    assert.notEqual(replacement.policyReleaseId, failed.policyReleaseId);
    assert.equal(replacement.templateSequence, 1);
    assert.equal(replacement.state, "STAGED");

    const ready = await value.facade.execute(value.control, {
      kind: "RECORD_POLICY_PROJECTION",
      tenantId: TENANT_ID,
      policyReleaseId: replacement.policyReleaseId,
      projectionOperationId: "facade-pg-replacement-projection",
      outcome: "READY",
      openFgaStoreId: STORE_ONE,
      authorizationModelId: MODEL_ONE,
      tupleBundleSha256: value.tupleBundleSha256,
      fixtureReportRef: "evidence://c06/facade-pg/replacement",
      fixtureReportSha256: hash("b"),
      fixturePassCount: 30,
      fixtureFailCount: 0,
      reasonRef: null,
      idempotencyKey: "facade-pg-replacement-project",
      correlationId: "facade-pg-replacement-project-correlation",
    });
    const activation = await value.facade.execute(value.control, {
      kind: "ACTIVATE_POLICY_RELEASE",
      tenantId: TENANT_ID,
      policyReleaseId: ready.policyReleaseId,
      expectedActivationVersion: 0,
      reasonRef: "policy://c06/facade-pg/replacement-activate",
      idempotencyKey: "facade-pg-replacement-activate",
      correlationId: "facade-pg-replacement-activate-correlation",
    });
    assert.equal(activation.activationVersion, 1);

    const snapshot = await value.facade.snapshot(value.control, {
      tenantId: TENANT_ID,
    });
    assert.deepEqual(
      snapshot.releases.map(({ policyReleaseId, state, templateSequence }) => ({
        policyReleaseId,
        state,
        templateSequence,
      })),
      [
        {
          policyReleaseId: failed.policyReleaseId,
          state: "FAILED",
          templateSequence: 1,
        },
        {
          policyReleaseId: ready.policyReleaseId,
          state: "READY",
          templateSequence: 1,
        },
      ].sort((left, right) =>
        left.policyReleaseId.localeCompare(right.policyReleaseId),
      ),
    );
  });

  await t.test("PG-15 replays an exact Decision, Event and Outbox", async () => {
    await resetDatabase();
    await seedActiveTenant();
    const ready = await prepareActiveReleaseOne();
    const value = decision(ready, 1201);
    const evidence = decisionEvent(value, 1202);
    const input = {
      tenantId: TENANT_ID,
      expectedPolicyReleaseId: ready.policyReleaseId,
      expectedActivationVersion: 1,
      decision: value,
      event: evidence,
    };

    assert.deepEqual(await store.recordDecision(input), value);
    assert.deepEqual(await store.recordDecision(input), value);
    const counts = await pool.query(
      `SELECT
         (SELECT count(*) FROM aios_core.authorization_decision
           WHERE decision_id = $1) AS decisions,
         (SELECT count(*) FROM aios_core.authorization_event
           WHERE event ->> 'subject' = $1) AS events,
         (SELECT count(*) FROM aios_core.authorization_outbox
           WHERE event ->> 'subject' = $1) AS outbox`,
      [value.decisionId],
    );
    assert.deepEqual(
      Object.values(counts.rows[0]).map(Number),
      [1, 1, 1],
    );
  });

  await t.test("PG-16 rejects a changed Event for an existing Decision", async () => {
    await resetDatabase();
    await seedActiveTenant();
    const ready = await prepareActiveReleaseOne();
    const value = decision(ready, 1301);
    const evidence = decisionEvent(value, 1302);
    const input = {
      tenantId: TENANT_ID,
      expectedPolicyReleaseId: ready.policyReleaseId,
      expectedActivationVersion: 1,
      decision: value,
      event: evidence,
    };
    await store.recordDecision(input);

    await assert.rejects(
      store.recordDecision({
        ...input,
        event: decisionEvent(value, 1303),
      }),
      { code: "ID_COLLISION" },
    );
  });

  await t.test("PG-17 confirms an old exact Decision after Policy activation changes", async () => {
    await resetDatabase();
    await seedActiveTenant();
    const readyOne = await prepareActiveReleaseOne();
    const value = decision(readyOne, 1401);
    const evidence = decisionEvent(value, 1402);
    const input = {
      tenantId: TENANT_ID,
      expectedPolicyReleaseId: readyOne.policyReleaseId,
      expectedActivationVersion: 1,
      decision: value,
      event: evidence,
    };
    await store.recordDecision(input);

    const second = release(2);
    await stage(store, second, "stage-17", 1403);
    const readyTwo = await project(store, second, "project-17", 1404);
    await activate(store, readyTwo, {
      key: "activate-17",
      counter: 1405,
      activationCounter: 1406,
      expectedVersion: 1,
    });

    assert.deepEqual(await store.recordDecision(input), value);
  });

  await t.test("PG-18 serializes concurrent exact Decision replay", async () => {
    await resetDatabase();
    await seedActiveTenant();
    const ready = await prepareActiveReleaseOne();
    const value = decision(ready, 1501);
    const evidence = decisionEvent(value, 1502);
    const input = {
      tenantId: TENANT_ID,
      expectedPolicyReleaseId: ready.policyReleaseId,
      expectedActivationVersion: 1,
      decision: value,
      event: evidence,
    };

    const results = await Promise.all(
      Array.from({ length: 16 }, () => store.recordDecision(input)),
    );
    for (const result of results) assert.deepEqual(result, value);
    const counts = await pool.query(
      `SELECT
         (SELECT count(*) FROM aios_core.authorization_decision
           WHERE decision_id = $1) AS decisions,
         (SELECT count(*) FROM aios_core.authorization_event
           WHERE event ->> 'subject' = $1) AS events,
         (SELECT count(*) FROM aios_core.authorization_outbox
           WHERE event ->> 'subject' = $1) AS outbox`,
      [value.decisionId],
    );
    assert.deepEqual(
      Object.values(counts.rows[0]).map(Number),
      [1, 1, 1],
    );
  });
});
