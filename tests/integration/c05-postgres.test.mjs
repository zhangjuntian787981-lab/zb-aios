import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import pg from "pg";
import {
  createIdentityFederation,
  createSyntheticIdentityCatalog,
} from "../../lib/identity-federation.mjs";
import { createPostgresIdentityStore } from "../../lib/postgres-identity-store.mjs";
import { createPostgresPrincipalStore } from "../../lib/postgres-principal-store.mjs";
import { createPostgresTenantStore } from "../../lib/postgres-tenant-store.mjs";
import {
  createStablePrincipalRegistry,
  createSyntheticPrincipalCatalog,
} from "../../lib/stable-principal.mjs";
import {
  createSyntheticFixtureCatalog,
  createTenantRegistry,
} from "../../lib/tenant-registry.mjs";

const { Pool } = pg;
const migrationUrls = [
  "../../implementation/p1/c03/postgresql/0001_tenant_registry.sql",
  "../../implementation/p1/c04/postgresql/0002_identity_federation.sql",
  "../../implementation/p1/c04/postgresql/0003_identity_outbox_delivery.sql",
  "../../implementation/p1/c04/postgresql/0004_versioned_provider_configuration.sql",
  "../../implementation/p1/c04/postgresql/0005_scim_checkpoint.sql",
  "../../implementation/p1/c04/postgresql/0006_identity_runtime_roles.sql",
  "../../implementation/p1/c05/postgresql/0007_stable_principal.sql",
  "../../implementation/p1/c05/postgresql/0008_principal_runtime_roles.sql",
].map((path) => new URL(path, import.meta.url));
const migrations = await Promise.all(
  migrationUrls.map((url) => readFile(url, "utf8")),
);
const identityCatalogEntries = JSON.parse(
  await readFile(
    new URL(
      "../../implementation/p1/c04/synthetic-identity-catalog.v1.json",
      import.meta.url,
    ),
    "utf8",
  ),
);
const principalCatalogEntries = JSON.parse(
  await readFile(
    new URL(
      "../../implementation/p1/c05/synthetic-principal-catalog.v1.json",
      import.meta.url,
    ),
    "utf8",
  ),
);
const seedCatalog = JSON.parse(
  await readFile(
    new URL(
      "../../implementation/p0/f02/seed-catalog.v1.json",
      import.meta.url,
    ),
    "utf8",
  ),
);

const PROJECTIONS = [
  "AUTHORIZATION",
  "IDENTITY",
  "KNOWLEDGE",
  "SECRET_REFS",
  "STORAGE",
];
const NOW = "2026-07-26T08:00:00.000Z";
const ROOT_EXPIRY = "2026-07-26T09:00:00.000Z";
const CHILD_EXPIRY = "2026-07-26T08:45:00.000Z";
const northstar = identityCatalogEntries.find(
  ({ fixtureId }) => fixtureId === "synthetic-tenant-northstar-fasteners",
);
const blueHarbor = identityCatalogEntries.find(
  ({ fixtureId }) => fixtureId === "synthetic-tenant-blue-harbor-tools",
);

const tenantOperator = {
  actorId: "syn_prn_c05_pg_tenant_operator",
  capabilities: ["TENANT_LIFECYCLE_MANAGE", "TENANT_LIFECYCLE_READ"],
  synthetic: true,
};
const projectionWorker = {
  actorId: "syn_svc_c05_pg_projection_worker",
  capabilities: ["TENANT_PROJECTION_REPORT"],
  synthetic: true,
};
const tenantReconciler = {
  actorId: "syn_svc_c05_pg_tenant_reconciler",
  capabilities: ["TENANT_RECONCILE"],
  synthetic: true,
};
const tenantReader = {
  actorId: "syn_svc_c05_pg_tenant_reader",
  capabilities: ["TENANT_LIFECYCLE_READ"],
  synthetic: true,
};
const identityProjectionWorker = {
  actorId: "syn_svc_c05_pg_identity_projection",
  capabilities: ["IDENTITY_TENANT_PROJECT", "IDENTITY_READ"],
  synthetic: true,
};
const identityProvisioner = {
  actorId: "syn_svc_c05_pg_identity_provisioning",
  capabilities: ["IDENTITY_PROVISIONING_APPLY"],
  synthetic: true,
};
const identityReader = {
  actorId: "syn_svc_c05_pg_identity_reader",
  capabilities: ["IDENTITY_READ"],
  synthetic: true,
};
const portalContext = {
  actorId: "syn_svc_c05_pg_portal",
  synthetic: true,
};
const principalOperator = {
  actorId: "syn_svc_c05_pg_principal_operator",
  capabilities: [
    "PRINCIPAL_PROVISION",
    "PRINCIPAL_LINK_MANAGE",
    "PRINCIPAL_LIFECYCLE_APPLY",
    "DELEGATION_MANAGE",
    "PRINCIPAL_READ",
  ],
  synthetic: true,
};

function postgresConfig() {
  if (process.env.C05_TEST_EPHEMERAL !== "1") {
    throw new Error("C05_TEST_EPHEMERAL=1 is required.");
  }
  for (const name of [
    "C05_TEST_PGHOST",
    "C05_TEST_PGPORT",
    "C05_TEST_PGDATABASE",
    "C05_TEST_PGUSER",
  ]) {
    if (!process.env[name]) throw new Error(`${name} is required.`);
  }
  return {
    host: process.env.C05_TEST_PGHOST,
    port: Number(process.env.C05_TEST_PGPORT),
    database: process.env.C05_TEST_PGDATABASE,
    user: process.env.C05_TEST_PGUSER,
    max: 48,
  };
}

const pool = new Pool(postgresConfig());

function deterministicUuidFactory(start = 0) {
  let counter = start;
  return () => {
    counter += 1;
    return `01984700-0000-7000-8000-${counter
      .toString(16)
      .padStart(12, "0")}`;
  };
}

function deterministicSecretFactory() {
  let counter = 0;
  return () => {
    counter += 1;
    return counter.toString(16).padStart(64, "0");
  };
}

function fixtureSeed(entry) {
  const slug = entry.fixtureId.replace(/^synthetic-tenant-/, "");
  const seed = seedCatalog.seeds.find(({ tenant_slug }) => tenant_slug === slug);
  assert.ok(seed, `F02 seed missing for ${entry.fixtureId}`);
  return seed;
}

function fixtureRef(entry) {
  return { fixtureId: entry.fixtureId, sha256: entry.sha256 };
}

function createBroker() {
  const starts = [];
  return {
    starts,
    async startAuthorization(request) {
      starts.push(structuredClone(request));
      return {
        authorizationUrl:
          `${northstar.provider.issuer}/protocol/openid-connect/auth`,
      };
    },
    async exchangeAndVerify() {
      return {
        protocol: "OIDC",
        signatureVerified: true,
        synthetic: true,
        issuer: northstar.provider.issuer,
        audience: [northstar.provider.clientId],
        authorizedParty: northstar.provider.clientId,
        subject: northstar.users[0].loginSubject,
        nonce: starts.at(-1).nonce,
        issuedAt: NOW,
        notBefore: NOW,
        expiresAt: ROOT_EXPIRY,
        authenticationTime: NOW,
        authenticationMethods: ["pwd", "mfa"],
        algorithm: "RS256",
        keyId: "synthetic-k1",
        configurationVersion: 1,
      };
    },
  };
}

function createRuntime({ principalPool = pool } = {}) {
  const tenantRegistry = createTenantRegistry({
    store: createPostgresTenantStore({ pool }),
    fixtureCatalog: createSyntheticFixtureCatalog(
      identityCatalogEntries.map((entry) => ({
        ...fixtureRef(entry),
        allowedConfigRefs: [
          `fixture://${fixtureSeed(entry).seed_id}`,
        ],
      })),
    ),
    authorize: (context, capability) =>
      context?.synthetic === true &&
      context.capabilities?.includes(capability) === true,
    clock: () => NOW,
    idFactory: deterministicUuidFactory(),
  });
  const identity = createIdentityFederation({
    store: createPostgresIdentityStore({ pool }),
    tenantRegistry,
    tenantRegistryContext: tenantReader,
    identityCatalog: createSyntheticIdentityCatalog(identityCatalogEntries),
    authorize: (context, capability) =>
      context?.synthetic === true &&
      context.capabilities?.includes(capability) === true,
    federationBroker: createBroker(),
    clock: () => NOW,
    idFactory: deterministicUuidFactory(100),
    secretFactory: deterministicSecretFactory(),
  });
  const principals = createStablePrincipalRegistry({
    store: createPostgresPrincipalStore({ pool: principalPool }),
    tenantRegistry,
    tenantRegistryContext: tenantReader,
    identityFederation: identity,
    identityFederationReadContext: identityReader,
    identityFederationServerContext: portalContext,
    principalCatalog: createSyntheticPrincipalCatalog(
      principalCatalogEntries,
    ),
    authorize: (context, capability) =>
      context?.synthetic === true &&
      context.capabilities?.includes(capability) === true,
    clock: () => NOW,
    idFactory: deterministicUuidFactory(500),
  });
  return { tenantRegistry, identity, principals };
}

function identityCommandFromTenantEvent(event, idempotencyKey) {
  return {
    kind: "APPLY_TENANT_LIFECYCLE_EVENT",
    idempotencyKey,
    tenantId: event.data.tenant_id,
    sourceEventId: event.id,
    sourceLifecycleVersion: event.data.lifecycle_version,
    sourceGeneration: event.data.generation,
    sourceOperationId: event.data.operation_id,
    sourceState: event.data.state,
    correlationId: event.correlationid,
  };
}

async function bootstrapActive(runtime, catalogEntry) {
  const seed = fixtureSeed(catalogEntry);
  const suffix = seed.tenant_slug;
  const created = await runtime.tenantRegistry.execute(tenantOperator, {
    kind: "CREATE_SYNTHETIC_TENANT",
    idempotencyKey: `c05-pg-create-${suffix}`,
    creationKey: `p1:${seed.seed_id}:c05-pg-${suffix}`,
    fixtureRef: fixtureRef(catalogEntry),
    configRefs: [`fixture://${seed.seed_id}`],
    correlationId: `c05-pg-create-${suffix}`,
  });
  const provisioning = await runtime.tenantRegistry.snapshot(
    tenantReader,
    created.tenantId,
  );
  const provisioningEvent = provisioning.outbox.find(
    ({ type }) => type === "product.tenant.provisioning-requested.v1",
  );
  const projected = await runtime.identity.execute(
    identityProjectionWorker,
    identityCommandFromTenantEvent(
      provisioningEvent,
      `c05-pg-project-${suffix}`,
    ),
  );
  const identitySnapshot = await runtime.identity.snapshot(
    identityReader,
    { tenantId: created.tenantId },
  );
  const identityReadyEvent = identitySnapshot.outbox.find(
    ({ type }) => type === "product.identity.tenant-projection-ready.v1",
  );
  for (const [index, projection] of PROJECTIONS.entries()) {
    await runtime.tenantRegistry.execute(projectionWorker, {
      kind: "RECORD_PROJECTION_RESULT",
      idempotencyKey: `c05-pg-ready-${suffix}-${projection}`,
      tenantId: created.tenantId,
      generation: created.generation,
      operationId: created.operationId,
      projection,
      outcome: "SUCCEEDED",
      attempt: 1,
      sourceEventId:
        projection === "IDENTITY"
          ? identityReadyEvent.id
          : `c05-pg-ready-source-${suffix}-${index + 1}`,
      correlationId: `c05-pg-ready-${suffix}`,
    });
  }
  const active = await runtime.tenantRegistry.execute(tenantReconciler, {
    kind: "RECONCILE_TENANT",
    idempotencyKey: `c05-pg-reconcile-${suffix}`,
    tenantId: created.tenantId,
    correlationId: `c05-pg-reconcile-${suffix}`,
  });
  const account = await runtime.identity.execute(identityProvisioner, {
    kind: "APPLY_SYNTHETIC_ACCOUNT_SNAPSHOT",
    idempotencyKey: `c05-pg-account-${suffix}`,
    tenantId: created.tenantId,
    providerConnectionId: projected.providerConnectionId,
    fixtureUserId: catalogEntry.users[0].fixtureUserId,
    sourceEventId: `c05-pg-account-source-${suffix}`,
    sourceRevision: 1,
    desiredState: "ACTIVE",
    correlationId: `c05-pg-account-${suffix}`,
  });
  return { created, active, projected, account };
}

async function completeLogin(runtime, bootstrapped) {
  const started = await runtime.identity.startLogin(portalContext, {
    tenantId: bootstrapped.created.tenantId,
    providerConnectionId: bootstrapped.projected.providerConnectionId,
    returnRoute: "PORTAL_HOME",
  });
  return runtime.identity.completeLogin(portalContext, {
    transactionId: started.transactionId,
    state: started.state,
    authorizationCode: "synthetic-c05-pg-code",
    codeVerifier: started.codeVerifier,
  });
}

function principalRef(catalogEntry, name) {
  const catalog = principalCatalogEntries.find(
    ({ fixtureId }) => fixtureId === catalogEntry.fixtureId,
  );
  return catalog.principals.find(({ fixturePrincipalRef }) =>
    fixturePrincipalRef.endsWith(`/${name}`),
  ).fixturePrincipalRef;
}

function createPrincipal(runtime, tenantId, fixturePrincipalRef, suffix) {
  return runtime.principals.execute(principalOperator, {
    kind: "CREATE_SYNTHETIC_PRINCIPAL",
    idempotencyKey: `c05-pg-principal-${suffix}`,
    tenantId,
    fixturePrincipalRef,
    correlationId: `c05-pg-principal-${suffix}`,
  });
}

function createDelegation(
  runtime,
  tenantId,
  {
    humanSubjectPrincipalId,
    delegatorPrincipalId,
    delegatePrincipalId,
    parentDelegationId,
    expiresAt,
    suffix,
    purposeRef = `synthetic://c05-pg/delegation/${suffix}`,
  },
) {
  return runtime.principals.execute(principalOperator, {
    kind: "CREATE_DELEGATION",
    idempotencyKey: `c05-pg-delegation-${suffix}`,
    tenantId,
    humanSubjectPrincipalId,
    delegatorPrincipalId,
    delegatePrincipalId,
    ...(parentDelegationId ? { parentDelegationId } : {}),
    expiresAt,
    purposeRef,
    correlationId: `c05-pg-delegation-${suffix}`,
  });
}

async function clearData() {
  const tables = await pool.query(`
    SELECT format('%I.%I', table_schema, table_name) AS qualified_name
      FROM information_schema.tables
     WHERE table_schema = 'aios_core'
       AND table_type = 'BASE TABLE'
     ORDER BY table_name
  `);
  await pool.query(
    `TRUNCATE TABLE ${tables.rows
      .map(({ qualified_name }) => qualified_name)
      .join(", ")} CASCADE`,
  );
}

function crashBeforePrincipalCommitPool() {
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
            sql.includes(
              'INSERT INTO "aios_core"."principal_command_receipt"',
            )
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

function principalTransactionBarrierPool() {
  let beforeBegin = null;
  let triggered = false;
  return {
    arm(callback) {
      beforeBegin = callback;
    },
    pool: {
      async connect() {
        const client = await pool.connect();
        return {
          async query(sql, parameters = []) {
            if (
              !triggered &&
              beforeBegin &&
              sql === "BEGIN ISOLATION LEVEL SERIALIZABLE"
            ) {
              triggered = true;
              await beforeBegin();
            }
            return client.query(sql, parameters);
          },
          release() {
            client.release();
          },
        };
      },
    },
  };
}

test("C05 passes real PostgreSQL 17.10 runtime verification", async (t) => {
  t.after(async () => {
    await pool.end();
  });

  const safety = await pool.query(
    "SELECT current_database() AS database, to_regnamespace('aios_core') AS schema",
  );
  assert.match(safety.rows[0].database, /^c05_test_[0-9]+$/);
  assert.equal(safety.rows[0].schema, null);

  await t.test("PG-01 executes C03-C05 migrations on PostgreSQL 17.10", async () => {
    for (const migration of migrations) await pool.query(migration);
    const version = await pool.query("SHOW server_version_num");
    assert.equal(Number(version.rows[0].server_version_num), 170010);
    const tables = await pool.query(`
      SELECT table_name
        FROM information_schema.tables
       WHERE table_schema = 'aios_core'
         AND table_name LIKE 'principal_%'
       ORDER BY table_name
    `);
    assert.deepEqual(
      tables.rows.map(({ table_name }) => table_name),
      [
        "principal_command_receipt",
        "principal_delegation",
        "principal_event",
        "principal_identity_link",
        "principal_outbox",
        "principal_registry",
      ],
    );
  });

  await t.test("PG-02 resolves HUMAN to AGENT to SERVICE end to end", async () => {
    await clearData();
    const runtime = createRuntime();
    const bootstrapped = await bootstrapActive(runtime, northstar);
    const session = await completeLogin(runtime, bootstrapped);
    const tenantId = bootstrapped.created.tenantId;
    const human = await createPrincipal(
      runtime,
      tenantId,
      principalRef(northstar, "ava"),
      "northstar-ava",
    );
    const agent = await createPrincipal(
      runtime,
      tenantId,
      principalRef(northstar, "assistant-agent"),
      "northstar-agent",
    );
    const service = await createPrincipal(
      runtime,
      tenantId,
      principalRef(northstar, "runtime-service"),
      "northstar-service",
    );
    const replay = await createPrincipal(
      runtime,
      tenantId,
      principalRef(northstar, "ava"),
      "northstar-ava",
    );
    assert.equal(replay.duplicate, true);
    assert.equal(replay.principal.principalId, human.principal.principalId);

    await runtime.principals.execute(principalOperator, {
      kind: "LINK_IDENTITY_ACCOUNT",
      idempotencyKey: "c05-pg-link-northstar-ava",
      tenantId,
      principalId: human.principal.principalId,
      identityAccountId: bootstrapped.account.accountId,
      linkEvidenceRef: "synthetic://c05-pg/link/northstar-ava",
      correlationId: "c05-pg-link-northstar-ava",
    });
    const root = await createDelegation(runtime, tenantId, {
      humanSubjectPrincipalId: human.principal.principalId,
      delegatorPrincipalId: human.principal.principalId,
      delegatePrincipalId: agent.principal.principalId,
      expiresAt: ROOT_EXPIRY,
      suffix: "root",
    });
    await assert.rejects(
      createDelegation(runtime, tenantId, {
        humanSubjectPrincipalId: human.principal.principalId,
        delegatorPrincipalId: agent.principal.principalId,
        delegatePrincipalId: service.principal.principalId,
        parentDelegationId: root.delegation.delegationId,
        expiresAt: CHILD_EXPIRY,
        suffix: "purpose-mismatch",
      }),
      (error) => error.code === "DELEGATION_INVALID",
    );
    const child = await createDelegation(runtime, tenantId, {
      humanSubjectPrincipalId: human.principal.principalId,
      delegatorPrincipalId: agent.principal.principalId,
      delegatePrincipalId: service.principal.principalId,
      parentDelegationId: root.delegation.delegationId,
      expiresAt: CHILD_EXPIRY,
      suffix: "child",
      purposeRef: root.delegation.purposeRef,
    });
    const resolved = await runtime.principals.resolveActionIdentity(
      {
        synthetic: true,
        workloadActorPrincipalId: service.principal.principalId,
        workloadTrustSource: "VERIFIED_WORKLOAD_CONTEXT",
      },
      {
        sessionToken: session.sessionToken,
        expectedTenantId: tenantId,
        delegationId: child.delegation.delegationId,
      },
    );
    assert.equal(
      resolved.humanSubject.principalId,
      human.principal.principalId,
    );
    assert.equal(
      resolved.workloadActor.principalId,
      service.principal.principalId,
    );
    assert.deepEqual(
      resolved.delegationChain.map(({ delegationId }) => delegationId),
      [root.delegation.delegationId, child.delegation.delegationId],
    );
    assert.equal(resolved.purposeRef, root.delegation.purposeRef);
    assert.equal(resolved.authorizationStatus, "NOT_EVALUATED");

    const persisted = await pool.query(`
      SELECT
        (SELECT count(*) FROM aios_core.principal_registry) AS principals,
        (SELECT count(*) FROM aios_core.principal_identity_link) AS links,
        (SELECT count(*) FROM aios_core.principal_delegation) AS delegations,
        (SELECT count(*) FROM aios_core.principal_event) AS events,
        (SELECT count(*) FROM aios_core.principal_outbox) AS outbox,
        (SELECT count(*)
           FROM aios_core.principal_event AS event
           FULL JOIN aios_core.principal_outbox AS outbox
             USING (event_id)
          WHERE event.event IS DISTINCT FROM outbox.event) AS mismatches
    `);
    assert.deepEqual(
      Object.values(persisted.rows[0]).map(Number),
      [3, 1, 2, 6, 6, 0],
    );
  });

  await t.test("PG-03 converges 32 concurrent creates to one Principal", async () => {
    await clearData();
    const runtime = createRuntime();
    const bootstrapped = await bootstrapActive(runtime, northstar);
    const tenantId = bootstrapped.created.tenantId;
    const avaRef = principalRef(northstar, "ava");
    const settled = await Promise.allSettled(
      Array.from({ length: 32 }, (_, index) =>
        createPrincipal(
          runtime,
          tenantId,
          avaRef,
          `race-${index + 1}`,
        ),
      ),
    );
    assert.equal(
      settled.filter(({ status }) => status === "rejected").length,
      0,
    );
    const values = settled.map(({ value }) => value);
    assert.equal(values.filter(({ applied }) => applied).length, 1);
    assert.equal(
      new Set(values.map(({ principal }) => principal.principalId)).size,
      1,
    );
    const counts = await pool.query(`
      SELECT
        (SELECT count(*) FROM aios_core.principal_registry) AS principals,
        (SELECT count(*) FROM aios_core.principal_command_receipt) AS commands,
        (SELECT count(*) FROM aios_core.principal_event) AS events,
        (SELECT count(*) FROM aios_core.principal_outbox) AS outbox
    `);
    assert.deepEqual(
      Object.values(counts.rows[0]).map(Number),
      [1, 32, 1, 1],
    );
  });

  await t.test("PG-04 replays one concurrent idempotent command exactly", async () => {
    await clearData();
    const runtime = createRuntime();
    const bootstrapped = await bootstrapActive(runtime, northstar);
    const tenantId = bootstrapped.created.tenantId;
    const settled = await Promise.all(
      Array.from({ length: 16 }, () =>
        createPrincipal(
          runtime,
          tenantId,
          principalRef(northstar, "ava"),
          "same-command",
        ),
      ),
    );
    assert.equal(
      new Set(settled.map(({ principal }) => principal.principalId)).size,
      1,
    );
    assert.equal(settled.filter(({ applied }) => applied).length, 16);
    assert.equal(settled.filter(({ duplicate }) => duplicate).length, 15);
    const counts = await pool.query(`
      SELECT
        (SELECT count(*) FROM aios_core.principal_registry) AS principals,
        (SELECT count(*) FROM aios_core.principal_command_receipt) AS commands,
        (SELECT count(*) FROM aios_core.principal_event) AS events,
        (SELECT count(*) FROM aios_core.principal_outbox) AS outbox
    `);
    assert.deepEqual(
      Object.values(counts.rows[0]).map(Number),
      [1, 1, 1, 1],
    );
  });

  await t.test("PG-05 rejects a cross-Tenant delegation atomically", async () => {
    await clearData();
    const runtime = createRuntime();
    const first = await bootstrapActive(runtime, northstar);
    const second = await bootstrapActive(runtime, blueHarbor);
    const human = await createPrincipal(
      runtime,
      first.created.tenantId,
      principalRef(northstar, "ava"),
      "cross-human",
    );
    const foreignService = await createPrincipal(
      runtime,
      second.created.tenantId,
      principalRef(blueHarbor, "runtime-service"),
      "cross-foreign-service",
    );
    await assert.rejects(
      createDelegation(runtime, first.created.tenantId, {
        humanSubjectPrincipalId: human.principal.principalId,
        delegatorPrincipalId: human.principal.principalId,
        delegatePrincipalId: foreignService.principal.principalId,
        expiresAt: ROOT_EXPIRY,
        suffix: "cross-tenant",
      }),
      (error) => error.code === "PRINCIPAL_NOT_ACTIVE",
    );
    const count = await pool.query(
      "SELECT count(*) FROM aios_core.principal_delegation",
    );
    assert.equal(Number(count.rows[0].count), 0);
  });

  await t.test("PG-06 rolls back all C05 rows when commit is interrupted", async () => {
    await clearData();
    const normalRuntime = createRuntime();
    const bootstrapped = await bootstrapActive(normalRuntime, northstar);
    const crashRuntime = createRuntime({
      principalPool: crashBeforePrincipalCommitPool(),
    });
    await assert.rejects(
      createPrincipal(
        crashRuntime,
        bootstrapped.created.tenantId,
        principalRef(northstar, "ava"),
        "crash",
      ),
      (error) => error.code === "STORE_UNAVAILABLE",
    );
    const counts = await pool.query(`
      SELECT
        (SELECT count(*) FROM aios_core.principal_registry) AS principals,
        (SELECT count(*) FROM aios_core.principal_command_receipt) AS commands,
        (SELECT count(*) FROM aios_core.principal_event) AS events,
        (SELECT count(*) FROM aios_core.principal_outbox) AS outbox
    `);
    assert.deepEqual(
      Object.values(counts.rows[0]).map(Number),
      [0, 0, 0, 0],
    );
  });

  await t.test("PG-07 rejects an event without its exact Outbox pair", async () => {
    await clearData();
    const runtime = createRuntime();
    const bootstrapped = await bootstrapActive(runtime, northstar);
    await createPrincipal(
      runtime,
      bootstrapped.created.tenantId,
      principalRef(northstar, "ava"),
      "pair-source",
    );
    const source = await pool.query(
      "SELECT event FROM aios_core.principal_event LIMIT 1",
    );
    const orphan = structuredClone(source.rows[0].event);
    orphan.id = "evt_c05_pg_orphan";
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      await client.query(
        `INSERT INTO aios_core.principal_event (
           event_id, tenant_id, tenant_kind, event, created_at
         ) VALUES ($1, $2, 'SYNTHETIC', $3::jsonb, $4)`,
        [
          orphan.id,
          bootstrapped.created.tenantId,
          JSON.stringify(orphan),
          orphan.time,
        ],
      );
      await assert.rejects(
        client.query("COMMIT"),
        (error) =>
          error.code === "23000" &&
          error.constraint === "principal_event_outbox_pair_guard",
      );
    } finally {
      client.release();
    }
    const count = await pool.query(
      "SELECT count(*) FROM aios_core.principal_event WHERE event_id = $1",
      [orphan.id],
    );
    assert.equal(Number(count.rows[0].count), 0);
  });

  await t.test("PG-08 closes a Tenant suspension after C03 preflight", async () => {
    await clearData();
    const barrier = principalTransactionBarrierPool();
    const runtime = createRuntime({ principalPool: barrier.pool });
    const bootstrapped = await bootstrapActive(runtime, northstar);
    barrier.arm(() =>
      runtime.tenantRegistry.execute(tenantOperator, {
        kind: "SUSPEND_TENANT",
        idempotencyKey: "c05-pg-suspend-at-principal-commit",
        tenantId: bootstrapped.created.tenantId,
        expectedVersion: bootstrapped.active.lifecycleVersion,
        reasonRef: "test://c05/tenant-preflight-race",
        correlationId: "c05-pg-suspend-at-principal-commit",
      }),
    );

    await assert.rejects(
      createPrincipal(
        runtime,
        bootstrapped.created.tenantId,
        principalRef(northstar, "ava"),
        "tenant-preflight-race",
      ),
      (error) => error.code === "TENANT_NOT_ACTIVE",
    );
    const counts = await pool.query(`
      SELECT
        (SELECT count(*) FROM aios_core.principal_registry) AS principals,
        (SELECT count(*) FROM aios_core.principal_command_receipt) AS commands,
        (SELECT count(*) FROM aios_core.principal_event) AS events,
        (SELECT count(*) FROM aios_core.principal_outbox) AS outbox
    `);
    assert.deepEqual(
      Object.values(counts.rows[0]).map(Number),
      [0, 0, 0, 0],
    );
  });

  await t.test("PG-09 synchronizes a suspended Link for a suspended Principal", async () => {
    await clearData();
    const runtime = createRuntime();
    const bootstrapped = await bootstrapActive(runtime, northstar);
    const tenantId = bootstrapped.created.tenantId;
    const human = await createPrincipal(
      runtime,
      tenantId,
      principalRef(northstar, "ava"),
      "suspended-sync-human",
    );
    const linked = await runtime.principals.execute(principalOperator, {
      kind: "LINK_IDENTITY_ACCOUNT",
      idempotencyKey: "c05-pg-suspended-sync-link",
      tenantId,
      principalId: human.principal.principalId,
      identityAccountId: bootstrapped.account.accountId,
      linkEvidenceRef: "test://c05/suspended-sync/link",
      correlationId: "c05-pg-suspended-sync-link",
    });
    await runtime.principals.execute(principalOperator, {
      kind: "CHANGE_PRINCIPAL_STATE",
      idempotencyKey: "c05-pg-suspended-sync-principal",
      tenantId,
      principalId: human.principal.principalId,
      expectedVersion: 1,
      desiredState: "SUSPENDED",
      reasonRef: "test://c05/suspended-sync/principal",
      correlationId: "c05-pg-suspended-sync-principal",
    });
    await runtime.identity.execute(identityProvisioner, {
      kind: "APPLY_SYNTHETIC_ACCOUNT_SNAPSHOT",
      idempotencyKey: "c05-pg-suspended-sync-account",
      tenantId,
      providerConnectionId: bootstrapped.projected.providerConnectionId,
      fixtureUserId: northstar.users[0].fixtureUserId,
      sourceEventId: "c05-pg-suspended-sync-source",
      sourceRevision: 2,
      desiredState: "SUSPENDED",
      correlationId: "c05-pg-suspended-sync-account",
    });
    const synchronized = await runtime.principals.execute(
      principalOperator,
      {
        kind: "SYNC_IDENTITY_ACCOUNT",
        idempotencyKey: "c05-pg-suspended-sync",
        tenantId,
        identityAccountId: bootstrapped.account.accountId,
        correlationId: "c05-pg-suspended-sync",
      },
    );
    assert.equal(synchronized.identityLink.identityLinkId, linked.identityLink.identityLinkId);
    assert.equal(synchronized.identityLink.state, "SUSPENDED");
    assert.equal(synchronized.principal.state, "SUSPENDED");
  });

  await t.test("PG-10 preserves retired history during explicit reassignment", async () => {
    await clearData();
    const runtime = createRuntime();
    const bootstrapped = await bootstrapActive(runtime, northstar);
    const tenantId = bootstrapped.created.tenantId;
    const ava = await createPrincipal(
      runtime,
      tenantId,
      principalRef(northstar, "ava"),
      "reassign-ava",
    );
    const noah = await createPrincipal(
      runtime,
      tenantId,
      principalRef(northstar, "noah"),
      "reassign-noah",
    );
    const linked = await runtime.principals.execute(principalOperator, {
      kind: "LINK_IDENTITY_ACCOUNT",
      idempotencyKey: "c05-pg-reassign-link",
      tenantId,
      principalId: ava.principal.principalId,
      identityAccountId: bootstrapped.account.accountId,
      linkEvidenceRef: "test://c05/reassignment/link",
      correlationId: "c05-pg-reassign-link",
    });
    const correction = principalCatalogEntries
      .find(({ fixtureId }) => fixtureId === northstar.fixtureId)
      .identityCorrections[0];
    const reassigned = await runtime.principals.execute(principalOperator, {
      kind: "REASSIGN_IDENTITY_ACCOUNT",
      idempotencyKey: "c05-pg-reassign",
      tenantId,
      identityLinkId: linked.identityLink.identityLinkId,
      targetPrincipalId: noah.principal.principalId,
      expectedVersion: 1,
      reasonRef: correction.correctionRef,
      correlationId: "c05-pg-reassign",
    });
    assert.equal(reassigned.retiredIdentityLink.state, "RETIRED");
    assert.equal(
      reassigned.identityLink.principalId,
      noah.principal.principalId,
    );
    const links = await pool.query(
      `SELECT identity_link_id, principal_id, state
         FROM aios_core.principal_identity_link
        WHERE tenant_id = $1
        ORDER BY created_at, identity_link_id`,
      [tenantId],
    );
    assert.deepEqual(
      links.rows.map(({ principal_id, state }) => ({ principal_id, state })),
      [
        { principal_id: ava.principal.principalId, state: "RETIRED" },
        { principal_id: noah.principal.principalId, state: "ACTIVE" },
      ],
    );
  });

  await t.test("PG-11 arbitrates concurrent owners for one Identity Account", async () => {
    await clearData();
    const runtime = createRuntime();
    const bootstrapped = await bootstrapActive(runtime, northstar);
    const tenantId = bootstrapped.created.tenantId;
    const ava = await createPrincipal(
      runtime,
      tenantId,
      principalRef(northstar, "ava"),
      "contention-ava",
    );
    const noah = await createPrincipal(
      runtime,
      tenantId,
      principalRef(northstar, "noah"),
      "contention-noah",
    );
    async function contend(identityLinkId, principalId) {
      const client = await pool.connect();
      try {
        await client.query("BEGIN");
        await client.query(
          `INSERT INTO aios_core.principal_identity_link (
             identity_link_id,
             tenant_id,
             tenant_kind,
             identity_account_id,
             provider_connection_id,
             principal_id,
             principal_kind,
             link_evidence_ref,
             state,
             lifecycle_version,
             account_lifecycle_version,
             account_revocation_epoch,
             created_at,
             updated_at,
             retired_at
           ) VALUES (
             $1, $2, 'SYNTHETIC', $3, $4, $5, 'HUMAN',
             'test://c05/concurrent-owner', 'ACTIVE', 1, 1, 1,
             $6, $6, NULL
           )`,
          [
            identityLinkId,
            tenantId,
            bootstrapped.account.accountId,
            bootstrapped.projected.providerConnectionId,
            principalId,
            NOW,
          ],
        );
        await client.query("COMMIT");
        return { status: "COMMITTED" };
      } catch (error) {
        await client.query("ROLLBACK");
        return {
          status: "REJECTED",
          code: error.code,
          constraint: error.constraint,
        };
      } finally {
        client.release();
      }
    }
    const results = await Promise.all([
      contend(
        "lnk_01984700-0000-7000-8000-000000009001",
        ava.principal.principalId,
      ),
      contend(
        "lnk_01984700-0000-7000-8000-000000009002",
        noah.principal.principalId,
      ),
    ]);
    assert.equal(
      results.filter(({ status }) => status === "COMMITTED").length,
      1,
    );
    assert.deepEqual(
      results.find(({ status }) => status === "REJECTED"),
      {
        status: "REJECTED",
        code: "23505",
        constraint: "principal_identity_link_current_account_key",
      },
    );
    const count = await pool.query(
      `SELECT count(*)
         FROM aios_core.principal_identity_link
        WHERE tenant_id = $1
          AND identity_account_id = $2
          AND state IN ('ACTIVE', 'SUSPENDED')`,
      [tenantId, bootstrapped.account.accountId],
    );
    assert.equal(Number(count.rows[0].count), 1);
  });

  await t.test("PG-12 blocks action identity immediately after Tenant suspension", async () => {
    await clearData();
    const runtime = createRuntime();
    const bootstrapped = await bootstrapActive(runtime, northstar);
    const session = await completeLogin(runtime, bootstrapped);
    const tenantId = bootstrapped.created.tenantId;
    const human = await createPrincipal(
      runtime,
      tenantId,
      principalRef(northstar, "ava"),
      "tenant-suspend-human",
    );
    const agent = await createPrincipal(
      runtime,
      tenantId,
      principalRef(northstar, "assistant-agent"),
      "tenant-suspend-agent",
    );
    await runtime.principals.execute(principalOperator, {
      kind: "LINK_IDENTITY_ACCOUNT",
      idempotencyKey: "c05-pg-tenant-suspend-link",
      tenantId,
      principalId: human.principal.principalId,
      identityAccountId: bootstrapped.account.accountId,
      linkEvidenceRef: "test://c05/tenant-suspend/link",
      correlationId: "c05-pg-tenant-suspend-link",
    });
    const delegation = await createDelegation(runtime, tenantId, {
      humanSubjectPrincipalId: human.principal.principalId,
      delegatorPrincipalId: human.principal.principalId,
      delegatePrincipalId: agent.principal.principalId,
      expiresAt: ROOT_EXPIRY,
      suffix: "tenant-suspend",
    });
    await runtime.tenantRegistry.execute(tenantOperator, {
      kind: "SUSPEND_TENANT",
      idempotencyKey: "c05-pg-tenant-suspend",
      tenantId,
      expectedVersion: bootstrapped.active.lifecycleVersion,
      reasonRef: "test://c05/tenant-suspend",
      correlationId: "c05-pg-tenant-suspend",
    });

    await assert.rejects(
      runtime.principals.resolveActionIdentity(
        {
          synthetic: true,
          workloadActorPrincipalId: agent.principal.principalId,
          workloadTrustSource: "VERIFIED_WORKLOAD_CONTEXT",
        },
        {
          sessionToken: session.sessionToken,
          expectedTenantId: tenantId,
          delegationId: delegation.delegation.delegationId,
        },
      ),
      (error) => error.code === "ACTION_IDENTITY_INVALID",
    );
  });
});
