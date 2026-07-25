import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import test from "node:test";
import pg from "pg";
import {
  createIdentityFederation,
  createSyntheticIdentityCatalog,
} from "../../lib/identity-federation.mjs";
import { createPostgresIdentityOutbox } from "../../lib/postgres-identity-outbox.mjs";
import { createPostgresIdentityStore } from "../../lib/postgres-identity-store.mjs";
import { createPostgresTenantStore } from "../../lib/postgres-tenant-store.mjs";
import {
  createSyntheticFixtureCatalog,
  createTenantRegistry,
} from "../../lib/tenant-registry.mjs";

const { Pool } = pg;
const c03MigrationUrl = new URL(
  "../../implementation/p1/c03/postgresql/0001_tenant_registry.sql",
  import.meta.url,
);
const c04MigrationUrl = new URL(
  "../../implementation/p1/c04/postgresql/0002_identity_federation.sql",
  import.meta.url,
);
const outboxMigrationUrl = new URL(
  "../../implementation/p1/c04/postgresql/0003_identity_outbox_delivery.sql",
  import.meta.url,
);
const providerConfigurationMigrationUrl = new URL(
  "../../implementation/p1/c04/postgresql/0004_versioned_provider_configuration.sql",
  import.meta.url,
);
const c03MigrationSql = await readFile(c03MigrationUrl, "utf8");
const c04MigrationSql = await readFile(c04MigrationUrl, "utf8");
const outboxMigrationSql = await readFile(outboxMigrationUrl, "utf8");
const providerConfigurationMigrationSql = await readFile(
  providerConfigurationMigrationUrl,
  "utf8",
);
const outboxMigrationSha256 = `sha256:${createHash("sha256")
  .update(outboxMigrationSql)
  .digest("hex")}`;
const EXPECTED_OUTBOX_MIGRATION_SHA256 =
  "sha256:088760c3f8b80b20f525043ae643c7919b18260d70d9b1b21c5c39ab41e78c7c";

const FIXTURE_REF = Object.freeze({
  fixtureId: "synthetic-tenant-northstar-fasteners",
  sha256:
    "sha256:12693f1bed92c45128e0774ee1ea6c71b63a7edad0eff43cb988e79b6771db26",
});
const NOW = "2026-07-26T06:00:00.000Z";
const ISSUER =
  "https://idp.northstar-fasteners.example/realms/synthetic";
const CLIENT_ID = "synthetic-aios-portal";

const tenantOperator = {
  actorId: "syn_prn_c04_outbox_operator",
  capabilities: ["TENANT_LIFECYCLE_MANAGE", "TENANT_LIFECYCLE_READ"],
  synthetic: true,
};
const tenantRegistryContext = {
  actorId: "syn_svc_c04_outbox_tenant_reader",
  capabilities: ["TENANT_LIFECYCLE_READ"],
  synthetic: true,
};
const identityProjectionWorker = {
  actorId: "syn_svc_c04_outbox_projection",
  capabilities: ["IDENTITY_TENANT_PROJECT", "IDENTITY_READ"],
  synthetic: true,
};
const tenantProjectionWorker = {
  actorId: "syn_svc_c04_outbox_delivery",
  capabilities: ["TENANT_PROJECTION_REPORT"],
  synthetic: true,
};

function postgresConfig() {
  if (process.env.C04_OUTBOX_TEST_EPHEMERAL !== "1") {
    throw new Error("C04_OUTBOX_TEST_EPHEMERAL=1 is required.");
  }
  for (const name of [
    "C04_OUTBOX_TEST_PGHOST",
    "C04_OUTBOX_TEST_PGPORT",
    "C04_OUTBOX_TEST_PGDATABASE",
    "C04_OUTBOX_TEST_PGUSER",
  ]) {
    if (!process.env[name]) throw new Error(`${name} is required.`);
  }
  return {
    host: process.env.C04_OUTBOX_TEST_PGHOST,
    port: Number(process.env.C04_OUTBOX_TEST_PGPORT),
    database: process.env.C04_OUTBOX_TEST_PGDATABASE,
    user: process.env.C04_OUTBOX_TEST_PGUSER,
    max: 16,
  };
}

const pool = new Pool(postgresConfig());

function deterministicUuidFactory(start = 0) {
  let counter = start;
  return () => {
    counter += 1;
    return `01984710-0000-7000-8000-${counter
      .toString(16)
      .padStart(12, "0")}`;
  };
}

function createRuntime() {
  const tenantRegistry = createTenantRegistry({
    store: createPostgresTenantStore({ pool }),
    fixtureCatalog: createSyntheticFixtureCatalog([
      {
        ...FIXTURE_REF,
        allowedConfigRefs: ["fixture://SYNTHETIC-SEED-001"],
      },
    ]),
    authorize: (context, capability) =>
      context?.synthetic === true &&
      context.capabilities?.includes(capability) === true,
    clock: () => NOW,
    idFactory: deterministicUuidFactory(),
  });
  const identity = createIdentityFederation({
    store: createPostgresIdentityStore({ pool }),
    tenantRegistry,
    tenantRegistryContext,
    identityCatalog: createSyntheticIdentityCatalog([
      {
        ...FIXTURE_REF,
        provider: {
          issuer: ISSUER,
          clientId: CLIENT_ID,
          redirectRoutes: {
            PORTAL_HOME:
              "https://portal.northstar-fasteners.example/auth/callback",
          },
          configurationVersion: 1,
          allowedAlgorithms: ["RS256"],
          allowedKeyIds: ["synthetic-k1"],
          requiredAuthenticationMethods: ["mfa"],
          maxAuthenticationAgeSeconds: 3600,
          upstreamProtocols: ["OIDC"],
        },
        users: [
          {
            fixtureUserId: "northstar-fasteners-user-ava",
            directoryObjectId: "northstar-directory-ava",
            loginSubject: "northstar-fasteners-user-ava",
            profileRef:
              "fixture://synthetic-tenant-northstar-fasteners/users/ava",
          },
        ],
      },
    ]),
    authorize: (context, capability) =>
      context?.synthetic === true &&
      context.capabilities?.includes(capability) === true,
    federationBroker: {
      async startAuthorization() {
        throw new Error("login is outside this outbox test");
      },
      async exchangeAndVerify() {
        throw new Error("login is outside this outbox test");
      },
    },
    clock: () => NOW,
    idFactory: deterministicUuidFactory(100),
  });
  return {
    tenantRegistry,
    identity,
    outbox: createPostgresIdentityOutbox({ pool }),
  };
}

function wait(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

test("C04 worker-only outbox closes the PostgreSQL delivery loop", async (t) => {
  t.after(async () => {
    await pool.end();
  });

  const safety = await pool.query(
    "SELECT current_database() AS database, to_regnamespace('aios_core') AS schema",
  );
  assert.match(safety.rows[0].database, /^c04_outbox_test_[0-9]+$/);
  assert.equal(safety.rows[0].schema, null);

  await pool.query(c03MigrationSql);
  await pool.query(c04MigrationSql);
  assert.equal(
    outboxMigrationSha256,
    EXPECTED_OUTBOX_MIGRATION_SHA256,
  );
  await pool.query(outboxMigrationSql);
  await pool.query(providerConfigurationMigrationSql);
  const version = await pool.query("SHOW server_version_num");
  assert.equal(Number(version.rows[0].server_version_num), 170010);

  const runtime = createRuntime();
  const created = await runtime.tenantRegistry.execute(tenantOperator, {
    kind: "CREATE_SYNTHETIC_TENANT",
    idempotencyKey: "c04-outbox-create",
    creationKey: "p1:SYNTHETIC-SEED-001:c04-outbox",
    fixtureRef: FIXTURE_REF,
    configRefs: ["fixture://SYNTHETIC-SEED-001"],
    correlationId: "c04-outbox-create",
  });
  const provisioning = await runtime.tenantRegistry.snapshot(
    tenantRegistryContext,
    created.tenantId,
  );
  const sourceEvent = provisioning.outbox.find(
    ({ type }) => type === "product.tenant.provisioning-requested.v1",
  );
  await runtime.identity.execute(identityProjectionWorker, {
    kind: "APPLY_TENANT_LIFECYCLE_EVENT",
    idempotencyKey: "c04-outbox-project",
    tenantId: created.tenantId,
    sourceEventId: sourceEvent.id,
    sourceLifecycleVersion: sourceEvent.data.lifecycle_version,
    sourceGeneration: sourceEvent.data.generation,
    sourceOperationId: sourceEvent.data.operation_id,
    sourceState: sourceEvent.data.state,
    correlationId: sourceEvent.correlationid,
  });

  const concurrentClaims = await Promise.all([
    runtime.outbox.claimOutbox({
      workerId: "identity-worker-a",
      limit: 1,
      leaseSeconds: 1,
    }),
    runtime.outbox.claimOutbox({
      workerId: "identity-worker-b",
      limit: 1,
      leaseSeconds: 1,
    }),
  ]);
  assert.equal(
    concurrentClaims[0].length + concurrentClaims[1].length,
    1,
  );
  const originalClaim = concurrentClaims.find(({ length }) => length === 1)[0];
  assert.equal(originalClaim.leaseVersion, 1);
  assert.equal(
    originalClaim.event.type,
    "product.identity.tenant-projection-ready.v1",
  );
  assert.deepEqual(
    await runtime.outbox.claimOutbox({
      workerId: "identity-worker-waiting",
      limit: 1,
      leaseSeconds: 1,
    }),
    [],
  );

  await assert.rejects(
    pool.query(
      `UPDATE aios_core.identity_outbox
          SET attempt_count = attempt_count - 1,
              lease_version = lease_version - 1
        WHERE event_id = $1`,
      [originalClaim.eventId],
    ),
    (error) => error.code === "23000",
  );

  await wait(1_100);
  const reclaimed = await runtime.outbox.claimOutbox({
    workerId: "identity-worker-recovery",
    limit: 1,
    leaseSeconds: 30,
  });
  assert.equal(reclaimed.length, 1);
  assert.equal(reclaimed[0].eventId, originalClaim.eventId);
  assert.equal(reclaimed[0].leaseVersion, 2);
  await assert.rejects(
    runtime.outbox.completeOutbox({
      ...reclaimed[0],
      workerId: "identity-worker-wrong",
    }),
    (error) => error.code === "STALE_OUTBOX_LEASE",
  );
  await assert.rejects(
    runtime.outbox.completeOutbox(originalClaim),
    (error) => error.code === "STALE_OUTBOX_LEASE",
  );
  await assert.rejects(
    runtime.outbox.failOutbox({
      ...originalClaim,
      errorCode: "STALE_DELIVERY",
      retryDelaySeconds: 1,
    }),
    (error) => error.code === "STALE_OUTBOX_LEASE",
  );

  await runtime.outbox.failOutbox({
    ...reclaimed[0],
    errorCode: "SYNTHETIC_DELIVERY_FAILURE",
    retryDelaySeconds: 1,
  });
  const failed = await pool.query(
    `SELECT status, attempt_count, lease_version, last_error_code
       FROM aios_core.identity_outbox
      WHERE event_id = $1`,
    [originalClaim.eventId],
  );
  assert.deepEqual(
    {
      status: failed.rows[0].status,
      attemptCount: failed.rows[0].attempt_count,
      leaseVersion: Number(failed.rows[0].lease_version),
      lastErrorCode: failed.rows[0].last_error_code,
    },
    {
      status: "FAILED",
      attemptCount: 2,
      leaseVersion: 2,
      lastErrorCode: "SYNTHETIC_DELIVERY_FAILURE",
    },
  );
  assert.deepEqual(
    await runtime.outbox.claimOutbox({
      workerId: "identity-worker-too-early",
      limit: 1,
      leaseSeconds: 30,
    }),
    [],
  );

  await wait(1_100);
  const delivery = await runtime.outbox.claimOutbox({
    workerId: "identity-worker-delivery",
    limit: 1,
    leaseSeconds: 30,
  });
  assert.equal(delivery.length, 1);
  assert.equal(delivery[0].leaseVersion, 3);
  const readyEvent = delivery[0].event;
  await runtime.tenantRegistry.execute(tenantProjectionWorker, {
    kind: "RECORD_PROJECTION_RESULT",
    idempotencyKey: "c04-outbox-deliver-identity-ready",
    tenantId: readyEvent.data.tenant_id,
    generation: readyEvent.data.generation,
    operationId: readyEvent.data.operation_id,
    projection: "IDENTITY",
    outcome: "SUCCEEDED",
    attempt: 1,
    sourceEventId: readyEvent.id,
    correlationId: readyEvent.correlationid,
  });
  await runtime.outbox.completeOutbox(delivery[0]);

  const tenantAfterDelivery = await runtime.tenantRegistry.snapshot(
    tenantRegistryContext,
    created.tenantId,
  );
  const identityProjection = tenantAfterDelivery.projections.find(
    ({ projection }) => projection === "IDENTITY",
  );
  assert.equal(identityProjection.status, "READY");
  assert.equal(identityProjection.sourceEventId, readyEvent.id);

  const published = await pool.query(
    `SELECT status, attempt_count, lease_version, leased_by, lease_until,
            last_error_code, published_at
       FROM aios_core.identity_outbox
      WHERE event_id = $1`,
    [readyEvent.id],
  );
  assert.equal(published.rows[0].status, "PUBLISHED");
  assert.equal(published.rows[0].attempt_count, 3);
  assert.equal(Number(published.rows[0].lease_version), 3);
  assert.equal(published.rows[0].leased_by, null);
  assert.equal(published.rows[0].lease_until, null);
  assert.equal(published.rows[0].last_error_code, null);
  assert.notEqual(published.rows[0].published_at, null);
  assert.deepEqual(
    await runtime.outbox.claimOutbox({
      workerId: "identity-worker-after-publish",
      limit: 1,
      leaseSeconds: 30,
    }),
    [],
  );
  await assert.rejects(
    pool.query(
      `UPDATE aios_core.identity_outbox
          SET status = 'PROCESSING',
              attempt_count = attempt_count + 1,
              lease_version = lease_version + 1,
              leased_by = 'identity-worker-reopen',
              lease_until = statement_timestamp() + interval '30 seconds',
              published_at = NULL
        WHERE event_id = $1`,
      [readyEvent.id],
    ),
    (error) => error.code === "23000",
  );

  t.diagnostic(
    `PostgreSQL ${version.rows[0].server_version_num}; migration ${outboxMigrationSha256}`,
  );
});
