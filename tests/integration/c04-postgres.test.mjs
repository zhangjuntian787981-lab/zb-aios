import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import test from "node:test";
import pg from "pg";
import {
  createIdentityFederation,
  createSyntheticIdentityCatalog,
} from "../../lib/identity-federation.mjs";
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
const c04MigrationSha256 = `sha256:${createHash("sha256")
  .update(c04MigrationSql)
  .digest("hex")}`;
const EXPECTED_C04_MIGRATION_SHA256 =
  "sha256:d4866157ba766108af0017074b945dee6a8d89e91b1a6b8d57e3f4c984bbc81f";

const FIXTURE_REF = Object.freeze({
  fixtureId: "synthetic-tenant-northstar-fasteners",
  sha256:
    "sha256:12693f1bed92c45128e0774ee1ea6c71b63a7edad0eff43cb988e79b6771db26",
});
const PROJECTIONS = [
  "AUTHORIZATION",
  "IDENTITY",
  "KNOWLEDGE",
  "SECRET_REFS",
  "STORAGE",
];
const NOW = "2026-07-26T04:00:00.000Z";
const ISSUER =
  "https://idp.northstar-fasteners.example/realms/synthetic";
const CLIENT_ID = "synthetic-aios-portal";
const REDIRECT_URI =
  "https://portal.northstar-fasteners.example/auth/callback";

const tenantOperator = {
  actorId: "syn_prn_c04_pg_operator",
  capabilities: ["TENANT_LIFECYCLE_MANAGE", "TENANT_LIFECYCLE_READ"],
  synthetic: true,
};
const tenantProjectionWorker = {
  actorId: "syn_svc_c04_pg_tenant_projection",
  capabilities: ["TENANT_PROJECTION_REPORT"],
  synthetic: true,
};
const tenantReconciler = {
  actorId: "syn_svc_c04_pg_tenant_reconciler",
  capabilities: ["TENANT_RECONCILE"],
  synthetic: true,
};
const tenantRegistryContext = {
  actorId: "syn_svc_c04_pg_tenant_reader",
  capabilities: ["TENANT_LIFECYCLE_READ"],
  synthetic: true,
};
const identityProjectionWorker = {
  actorId: "syn_svc_c04_pg_identity_projection",
  capabilities: ["IDENTITY_TENANT_PROJECT", "IDENTITY_READ"],
  synthetic: true,
};
const identityProvisioningWorker = {
  actorId: "syn_svc_c04_pg_identity_provisioning",
  capabilities: ["IDENTITY_PROVISIONING_APPLY"],
  synthetic: true,
};
const identityProviderManager = {
  actorId: "syn_svc_c04_pg_provider_manager",
  capabilities: ["IDENTITY_PROVIDER_ROTATE", "IDENTITY_READ"],
  synthetic: true,
};
const portalContext = {
  actorId: "syn_svc_c04_pg_portal",
  synthetic: true,
};

function postgresConfig() {
  if (process.env.C04_TEST_EPHEMERAL !== "1") {
    throw new Error("C04_TEST_EPHEMERAL=1 is required.");
  }
  for (const name of [
    "C04_TEST_PGHOST",
    "C04_TEST_PGPORT",
    "C04_TEST_PGDATABASE",
    "C04_TEST_PGUSER",
  ]) {
    if (!process.env[name]) throw new Error(`${name} is required.`);
  }
  return {
    host: process.env.C04_TEST_PGHOST,
    port: Number(process.env.C04_TEST_PGPORT),
    database: process.env.C04_TEST_PGDATABASE,
    user: process.env.C04_TEST_PGUSER,
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

async function resetDatabase() {
  await pool.query("DROP SCHEMA IF EXISTS aios_core CASCADE");
  await pool.query(c03MigrationSql);
  await pool.query(c04MigrationSql);
  await pool.query(outboxMigrationSql);
  await pool.query(providerConfigurationMigrationSql);
}

function createRuntime({ identityPool = pool } = {}) {
  let currentTime = NOW;
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
    clock: () => currentTime,
    idFactory: deterministicUuidFactory(),
  });
  const broker = {
    starts: [],
    assertions: new Map(),
    exchangeCount: 0,
    beforeExchange: null,
    async startAuthorization(request) {
      this.starts.push(structuredClone(request));
      return {
        authorizationUrl:
          "https://idp.northstar-fasteners.example/realms/synthetic/protocol/openid-connect/auth",
      };
    },
    async exchangeAndVerify(request) {
      this.exchangeCount += 1;
      if (this.beforeExchange) await this.beforeExchange();
      const configured = this.assertions.get(request.authorizationCode);
      if (configured) return structuredClone(configured);
      return {
        protocol: "OIDC",
        signatureVerified: true,
        synthetic: true,
        issuer: ISSUER,
        audience: [CLIENT_ID],
        authorizedParty: CLIENT_ID,
        subject: "northstar-fasteners-user-ava",
        nonce: this.starts.at(-1).nonce,
        issuedAt: NOW,
        notBefore: NOW,
        expiresAt: "2026-07-26T05:00:00.000Z",
        authenticationTime: NOW,
        authenticationMethods: ["pwd", "mfa"],
        algorithm: "RS256",
        keyId: "synthetic-k1",
        configurationVersion: 1,
      };
    },
  };
  const baseIdentityStore = createPostgresIdentityStore({ pool: identityPool });
  const identityStoreControl = {
    beforeSessionRead: null,
    sessionReadCount: 0,
  };
  const identityStore = Object.freeze({
    ...baseIdentityStore,
    async readSessionSnapshot(tokenHash) {
      identityStoreControl.sessionReadCount += 1;
      if (identityStoreControl.beforeSessionRead) {
        await identityStoreControl.beforeSessionRead(
          identityStoreControl.sessionReadCount,
        );
      }
      return baseIdentityStore.readSessionSnapshot(tokenHash);
    },
  });
  const identity = createIdentityFederation({
    store: identityStore,
    tenantRegistry,
    tenantRegistryContext,
    identityCatalog: createSyntheticIdentityCatalog([
      {
        ...FIXTURE_REF,
        provider: {
          issuer: ISSUER,
          clientId: CLIENT_ID,
          redirectRoutes: { PORTAL_HOME: REDIRECT_URI },
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
    federationBroker: broker,
    clock: () => currentTime,
    idFactory: deterministicUuidFactory(100),
    secretFactory: deterministicSecretFactory(),
  });
  return {
    tenantRegistry,
    identity,
    identityStoreControl,
    broker,
    setTime(value) {
      currentTime = value;
    },
  };
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

async function bootstrapActive(runtime) {
  const created = await runtime.tenantRegistry.execute(tenantOperator, {
    kind: "CREATE_SYNTHETIC_TENANT",
    idempotencyKey: "c04-pg-create",
    creationKey: "p1:SYNTHETIC-SEED-001:c04-pg",
    fixtureRef: FIXTURE_REF,
    configRefs: ["fixture://SYNTHETIC-SEED-001"],
    correlationId: "c04-pg-create",
  });
  const provisioning = await runtime.tenantRegistry.snapshot(
    tenantRegistryContext,
    created.tenantId,
  );
  const sourceEvent = provisioning.outbox.find(
    ({ type }) => type === "product.tenant.provisioning-requested.v1",
  );
  const projected = await runtime.identity.execute(
    identityProjectionWorker,
    identityCommandFromTenantEvent(sourceEvent, "c04-pg-project"),
  );
  const identitySnapshot = await runtime.identity.snapshot(
    identityProjectionWorker,
    { tenantId: created.tenantId },
  );
  const identityReadyEvent = identitySnapshot.outbox.find(
    ({ type }) => type === "product.identity.tenant-projection-ready.v1",
  );
  for (const [index, projection] of PROJECTIONS.entries()) {
    await runtime.tenantRegistry.execute(tenantProjectionWorker, {
      kind: "RECORD_PROJECTION_RESULT",
      idempotencyKey: `c04-pg-ready-${projection}`,
      tenantId: created.tenantId,
      generation: created.generation,
      operationId: created.operationId,
      projection,
      outcome: "SUCCEEDED",
      attempt: 1,
      sourceEventId:
        projection === "IDENTITY"
          ? identityReadyEvent.id
          : `c04-pg-ready-source-${index + 1}`,
      correlationId: "c04-pg-ready",
    });
  }
  const active = await runtime.tenantRegistry.execute(tenantReconciler, {
    kind: "RECONCILE_TENANT",
    idempotencyKey: "c04-pg-reconcile",
    tenantId: created.tenantId,
    correlationId: "c04-pg-reconcile",
  });
  const account = await runtime.identity.execute(
    identityProvisioningWorker,
    {
      kind: "APPLY_SYNTHETIC_ACCOUNT_SNAPSHOT",
      idempotencyKey: "c04-pg-account-active",
      tenantId: created.tenantId,
      providerConnectionId: projected.providerConnectionId,
      fixtureUserId: "northstar-fasteners-user-ava",
      sourceEventId: "c04-pg-account-source-active",
      sourceRevision: 1,
      desiredState: "ACTIVE",
      correlationId: "c04-pg-account",
    },
  );
  return { created, active, projected, account, sourceEvent };
}

async function startAndCompleteLogin(runtime, tenantId, providerConnectionId) {
  const started = await runtime.identity.startLogin(portalContext, {
    tenantId,
    providerConnectionId,
    returnRoute: "PORTAL_HOME",
  });
  const completed = await runtime.identity.completeLogin(portalContext, {
    transactionId: started.transactionId,
    state: started.state,
    authorizationCode: "synthetic-pg-code",
    codeVerifier: started.codeVerifier,
  });
  return { started, completed };
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
            sql.includes('INSERT INTO "aios_core"."identity_command_receipt"')
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

test("C04 passes real PostgreSQL 17.10 runtime verification", async (t) => {
  t.after(async () => {
    await pool.end();
  });

  const safety = await pool.query(
    "SELECT current_database() AS database, to_regnamespace('aios_core') AS schema",
  );
  assert.match(safety.rows[0].database, /^c04_test_[0-9]+$/);
  assert.equal(safety.rows[0].schema, null);

  await t.test("PG-01 executes all C04 migrations on PostgreSQL 17.10", async () => {
    assert.equal(c04MigrationSha256, EXPECTED_C04_MIGRATION_SHA256);
    await pool.query(c03MigrationSql);
    await pool.query(c04MigrationSql);
    await pool.query(outboxMigrationSql);
    await pool.query(providerConfigurationMigrationSql);
    const version = await pool.query("SHOW server_version_num");
    assert.equal(Number(version.rows[0].server_version_num), 170010);
    const tables = await pool.query(`
      SELECT table_name
        FROM information_schema.tables
       WHERE table_schema = 'aios_core'
         AND table_name LIKE 'identity_%'
       ORDER BY table_name
    `);
    assert.equal(tables.rows.length, 10);
    t.diagnostic(
      `PostgreSQL ${version.rows[0].server_version_num}; migration ${c04MigrationSha256}`,
    );
  });

  await t.test("PG-01B upgrades a populated 0002 identity state", async () => {
    await pool.query("DROP SCHEMA IF EXISTS aios_core CASCADE");
    await pool.query(c03MigrationSql);
    await pool.query(c04MigrationSql);
    await pool.query(`
      INSERT INTO aios_core.tenant_registry (
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
        'stn_01984700-0000-7000-8000-000000000201',
        'SYNTHETIC',
        'PROVISIONING',
        1,
        1,
        'p1:SYNTHETIC-SEED-001:c04-pg-upgrade',
        'fixture://synthetic-c04-pg-upgrade',
        'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
        '["fixture://SYNTHETIC-SEED-001"]'::jsonb,
        'sns_01984700-0000-7000-8000-000000000202',
        'op_01984700-0000-7000-8000-000000000203',
        '2026-07-26T03:00:00.000Z',
        '2026-07-26T03:00:00.000Z'
      );

      INSERT INTO aios_core.identity_provider (
        provider_connection_id,
        tenant_id,
        tenant_kind,
        protocol,
        issuer,
        client_id,
        redirect_routes,
        configuration_version,
        allowed_algorithms,
        allowed_key_ids,
        required_authentication_methods,
        max_authentication_age_seconds,
        upstream_protocols,
        policy,
        status,
        created_at,
        updated_at
      ) VALUES (
        'idp_01984700-0000-7000-8000-000000000204',
        'stn_01984700-0000-7000-8000-000000000201',
        'SYNTHETIC',
        'OIDC',
        'https://idp.upgrade.example/realms/synthetic',
        'synthetic-upgrade-client',
        '{"PORTAL_HOME":"https://portal.upgrade.example/auth/callback"}'::jsonb,
        1,
        '["RS256"]'::jsonb,
        '["synthetic-upgrade-k1"]'::jsonb,
        '["mfa"]'::jsonb,
        3600,
        '["OIDC"]'::jsonb,
        'SCIM_REQUIRED',
        'ACTIVE',
        '2026-07-26T03:01:00.000Z',
        '2026-07-26T03:01:00.000Z'
      );

      INSERT INTO aios_core.identity_tenant_projection (
        tenant_id,
        tenant_kind,
        fixture_id,
        fixture_hash,
        provider_connection_id,
        state,
        generation,
        operation_id,
        revocation_epoch,
        updated_at
      ) VALUES (
        'stn_01984700-0000-7000-8000-000000000201',
        'SYNTHETIC',
        'synthetic-c04-pg-upgrade',
        'sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
        'idp_01984700-0000-7000-8000-000000000204',
        'READY',
        1,
        'op_01984700-0000-7000-8000-000000000203',
        1,
        '2026-07-26T03:02:00.000Z'
      );

      INSERT INTO aios_core.identity_account (
        account_id,
        tenant_id,
        tenant_kind,
        provider_connection_id,
        issuer,
        subject,
        directory_object_id,
        fixture_user_id,
        state,
        lifecycle_version,
        source_revision,
        source_payload_hash,
        revocation_epoch,
        incarnation,
        profile_ref,
        created_at,
        updated_at
      ) VALUES (
        'sia_01984700-0000-7000-8000-000000000205',
        'stn_01984700-0000-7000-8000-000000000201',
        'SYNTHETIC',
        'idp_01984700-0000-7000-8000-000000000204',
        'https://idp.upgrade.example/realms/synthetic',
        'synthetic-upgrade-user',
        'synthetic-upgrade-directory-user',
        'synthetic-upgrade-user',
        'ACTIVE',
        1,
        1,
        'sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc',
        1,
        1,
        'fixture://synthetic-c04-pg-upgrade/users/one',
        '2026-07-26T03:03:00.000Z',
        '2026-07-26T03:03:00.000Z'
      );

      INSERT INTO aios_core.identity_login_transaction (
        transaction_id,
        tenant_id,
        provider_connection_id,
        provider_configuration_version,
        state_hash,
        nonce_hash,
        pkce_verifier_hash,
        redirect_uri,
        return_route,
        issued_at,
        expires_at,
        claimed_at,
        claim_hash,
        consumed_at
      ) VALUES (
        'lgn_01984700-0000-7000-8000-000000000206',
        'stn_01984700-0000-7000-8000-000000000201',
        'idp_01984700-0000-7000-8000-000000000204',
        1,
        'sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd',
        'sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee',
        'sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
        'https://portal.upgrade.example/auth/callback',
        'PORTAL_HOME',
        '2026-07-26T03:04:00.000Z',
        '2026-07-26T03:09:00.000Z',
        '2026-07-26T03:05:00.000Z',
        'sha256:1111111111111111111111111111111111111111111111111111111111111111',
        '2026-07-26T03:06:00.000Z'
      );

      INSERT INTO aios_core.identity_session (
        session_id,
        tenant_id,
        tenant_kind,
        account_id,
        provider_connection_id,
        token_hash,
        account_revocation_epoch,
        tenant_revocation_epoch,
        status,
        authentication_time,
        authentication_methods,
        issued_at,
        expires_at,
        revoked_at
      ) VALUES (
        'ses_01984700-0000-7000-8000-000000000207',
        'stn_01984700-0000-7000-8000-000000000201',
        'SYNTHETIC',
        'sia_01984700-0000-7000-8000-000000000205',
        'idp_01984700-0000-7000-8000-000000000204',
        'sha256:2222222222222222222222222222222222222222222222222222222222222222',
        1,
        1,
        'ACTIVE',
        '2026-07-26T03:03:30.000Z',
        '["pwd","mfa"]'::jsonb,
        '2026-07-26T03:06:00.000Z',
        '2026-07-26T04:06:00.000Z',
        NULL
      );
    `);

    await pool.query(providerConfigurationMigrationSql);

    const upgraded = await pool.query(`
      SELECT
        configuration.configuration_version,
        configuration.state AS configuration_state,
        configuration.activated_at,
        login.transaction_id,
        login.provider_configuration_version AS login_configuration_version,
        session.session_id,
        session.provider_configuration_version AS session_configuration_version,
        (
          provider.configuration_version =
            configuration.configuration_version
          AND provider.redirect_routes =
            configuration.redirect_routes
          AND provider.allowed_algorithms =
            configuration.allowed_algorithms
          AND provider.allowed_key_ids =
            configuration.allowed_key_ids
          AND provider.required_authentication_methods =
            configuration.required_authentication_methods
          AND provider.max_authentication_age_seconds =
            configuration.max_authentication_age_seconds
          AND provider.upstream_protocols =
            configuration.upstream_protocols
        ) AS mirror_matches_current
      FROM aios_core.identity_provider AS provider
      JOIN aios_core.identity_provider_configuration AS configuration
        ON configuration.provider_connection_id =
             provider.provider_connection_id
       AND configuration.tenant_id = provider.tenant_id
       AND configuration.state = 'CURRENT'
      JOIN aios_core.identity_login_transaction AS login
        ON login.provider_connection_id =
             configuration.provider_connection_id
       AND login.tenant_id = configuration.tenant_id
       AND login.provider_configuration_version =
             configuration.configuration_version
      JOIN aios_core.identity_session AS session
        ON session.provider_connection_id =
             configuration.provider_connection_id
       AND session.tenant_id = configuration.tenant_id
       AND session.provider_configuration_version =
             configuration.configuration_version
    `);
    assert.equal(upgraded.rows.length, 1);
    assert.equal(Number(upgraded.rows[0].configuration_version), 1);
    assert.equal(upgraded.rows[0].configuration_state, "CURRENT");
    assert.equal(
      upgraded.rows[0].activated_at.toISOString(),
      "2026-07-26T03:01:00.000Z",
    );
    assert.equal(
      upgraded.rows[0].transaction_id,
      "lgn_01984700-0000-7000-8000-000000000206",
    );
    assert.equal(Number(upgraded.rows[0].login_configuration_version), 1);
    assert.equal(
      upgraded.rows[0].session_id,
      "ses_01984700-0000-7000-8000-000000000207",
    );
    assert.equal(Number(upgraded.rows[0].session_configuration_version), 1);
    assert.equal(upgraded.rows[0].mirror_matches_current, true);
  });

  await t.test("PG-02 persists one complete synthetic identity session", async () => {
    await resetDatabase();
    const runtime = createRuntime();
    const bootstrapped = await bootstrapActive(runtime);
    const { started, completed } = await startAndCompleteLogin(
      runtime,
      bootstrapped.created.tenantId,
      bootstrapped.projected.providerConnectionId,
    );
    const resolved = await runtime.identity.resolveSession(portalContext, {
      sessionToken: completed.sessionToken,
      expectedTenantId: bootstrapped.created.tenantId,
    });
    assert.equal(resolved.identityAccountId, bootstrapped.account.accountId);
    assert.equal(resolved.authorizationStatus, "NOT_EVALUATED");

    const persisted = await pool.query(`
      SELECT
        (SELECT state_hash
           FROM aios_core.identity_login_transaction
          WHERE transaction_id = $1) AS state_hash,
        (SELECT token_hash
           FROM aios_core.identity_session
          WHERE session_id = $2) AS token_hash,
        (SELECT count(*) FROM aios_core.identity_event) AS events,
        (SELECT count(*) FROM aios_core.identity_outbox) AS outbox
    `, [started.transactionId, completed.sessionId]);
    assert.match(persisted.rows[0].state_hash, /^sha256:[a-f0-9]{64}$/);
    assert.match(persisted.rows[0].token_hash, /^sha256:[a-f0-9]{64}$/);
    assert.notEqual(persisted.rows[0].state_hash, started.state);
    assert.notEqual(persisted.rows[0].token_hash, completed.sessionToken);
    assert.equal(Number(persisted.rows[0].events), 2);
    assert.equal(Number(persisted.rows[0].outbox), 2);
  });

  await t.test("PG-03 applies 32 deliveries of one C03 event once", async () => {
    await resetDatabase();
    const runtime = createRuntime();
    const created = await runtime.tenantRegistry.execute(tenantOperator, {
      kind: "CREATE_SYNTHETIC_TENANT",
      idempotencyKey: "c04-pg-race-create",
      creationKey: "p1:SYNTHETIC-SEED-001:c04-pg-race",
      fixtureRef: FIXTURE_REF,
      configRefs: ["fixture://SYNTHETIC-SEED-001"],
      correlationId: "c04-pg-race",
    });
    const tenant = await runtime.tenantRegistry.snapshot(
      tenantRegistryContext,
      created.tenantId,
    );
    const event = tenant.outbox[0];
    const settled = await Promise.allSettled(
      Array.from({ length: 32 }, (_, index) =>
        runtime.identity.execute(
          identityProjectionWorker,
          identityCommandFromTenantEvent(
            event,
            `c04-pg-race-delivery-${index + 1}`,
          ),
        ),
      ),
    );
    assert.equal(
      settled.filter(({ status }) => status === "rejected").length,
      0,
    );
    assert.equal(
      settled.filter(
        ({ status, value }) =>
          status === "fulfilled" && value.duplicate === false,
      ).length,
      1,
    );
    const counts = await pool.query(`
      SELECT
        (SELECT count(*) FROM aios_core.identity_provider) AS providers,
        (SELECT count(*) FROM aios_core.identity_tenant_projection) AS projections,
        (SELECT count(*) FROM aios_core.identity_source_receipt) AS source_receipts,
        (SELECT count(*) FROM aios_core.identity_event) AS events,
        (SELECT count(*) FROM aios_core.identity_outbox) AS outbox,
        (SELECT count(*) FROM aios_core.identity_command_receipt) AS commands
    `);
    assert.deepEqual(
      Object.fromEntries(
        Object.entries(counts.rows[0]).map(([key, value]) => [
          key,
          Number(value),
        ]),
      ),
      {
        providers: 1,
        projections: 1,
        source_receipts: 1,
        events: 1,
        outbox: 1,
        commands: 32,
      },
    );
  });

  await t.test("PG-03B preserves an early Tenant suspension", async () => {
    await resetDatabase();
    const runtime = createRuntime();
    const created = await runtime.tenantRegistry.execute(tenantOperator, {
      kind: "CREATE_SYNTHETIC_TENANT",
      idempotencyKey: "c04-pg-early-suspend-create",
      creationKey: "p1:SYNTHETIC-SEED-001:c04-pg-early-suspend",
      fixtureRef: FIXTURE_REF,
      configRefs: ["fixture://SYNTHETIC-SEED-001"],
      correlationId: "c04-pg-early-suspend",
    });
    await runtime.tenantRegistry.execute(tenantOperator, {
      kind: "SUSPEND_TENANT",
      idempotencyKey: "c04-pg-early-suspend",
      tenantId: created.tenantId,
      expectedVersion: created.lifecycleVersion,
      reasonRef: "synthetic://c04-pg-early-suspend",
      correlationId: "c04-pg-early-suspend",
    });
    const suspended = await runtime.tenantRegistry.snapshot(
      tenantRegistryContext,
      created.tenantId,
    );
    const event = suspended.outbox.find(
      ({ type }) => type === "product.tenant.suspended.v1",
    );
    const projected = await runtime.identity.execute(
      identityProjectionWorker,
      identityCommandFromTenantEvent(event, "c04-pg-early-suspend-project"),
    );
    assert.equal(projected.projectionState, "SUSPENDED");
    const snapshot = await runtime.identity.snapshot(
      identityProjectionWorker,
      { tenantId: created.tenantId },
    );
    assert.equal(snapshot.projectionState, "SUSPENDED");
    assert.equal(snapshot.provider.status, "ACTIVE");
  });

  await t.test("PG-03C restores READY when ACTIVE arrives before resume", async () => {
    await resetDatabase();
    const runtime = createRuntime();
    const bootstrapped = await bootstrapActive(runtime);
    const suspended = await runtime.tenantRegistry.execute(tenantOperator, {
      kind: "SUSPEND_TENANT",
      idempotencyKey: "c04-pg-out-of-order-suspend",
      tenantId: bootstrapped.created.tenantId,
      expectedVersion: bootstrapped.active.lifecycleVersion,
      reasonRef: "synthetic://c04-pg-out-of-order-suspend",
      correlationId: "c04-pg-out-of-order",
    });
    const suspendedSnapshot = await runtime.tenantRegistry.snapshot(
      tenantRegistryContext,
      suspended.tenantId,
    );
    const suspendedEvent = suspendedSnapshot.outbox.find(
      ({ type }) => type === "product.tenant.suspended.v1",
    );
    await runtime.identity.execute(
      identityProjectionWorker,
      identityCommandFromTenantEvent(
        suspendedEvent,
        "c04-pg-out-of-order-project-suspended",
      ),
    );

    const resumed = await runtime.tenantRegistry.execute(tenantOperator, {
      kind: "RESUME_TENANT",
      idempotencyKey: "c04-pg-out-of-order-resume",
      tenantId: suspended.tenantId,
      expectedVersion: suspended.lifecycleVersion,
      correlationId: "c04-pg-out-of-order",
    });
    const resumedSnapshot = await runtime.tenantRegistry.snapshot(
      tenantRegistryContext,
      resumed.tenantId,
    );
    const delayedResumeEvent = resumedSnapshot.outbox.find(
      ({ type, data }) =>
        type === "product.tenant.resume-requested.v1" &&
        data.generation === resumed.generation,
    );
    for (const [index, projection] of PROJECTIONS.entries()) {
      await runtime.tenantRegistry.execute(tenantProjectionWorker, {
        kind: "RECORD_PROJECTION_RESULT",
        idempotencyKey: `c04-pg-out-of-order-ready-${projection}`,
        tenantId: resumed.tenantId,
        generation: resumed.generation,
        operationId: resumed.operationId,
        projection,
        outcome: "SUCCEEDED",
        attempt: 1,
        sourceEventId: `c04-pg-out-of-order-source-${index + 1}`,
        correlationId: "c04-pg-out-of-order",
      });
    }
    await runtime.tenantRegistry.execute(tenantReconciler, {
      kind: "RECONCILE_TENANT",
      idempotencyKey: "c04-pg-out-of-order-reconcile",
      tenantId: resumed.tenantId,
      correlationId: "c04-pg-out-of-order",
    });
    const activeSnapshot = await runtime.tenantRegistry.snapshot(
      tenantRegistryContext,
      resumed.tenantId,
    );
    const activeEvent = activeSnapshot.outbox.find(
      ({ type, data }) =>
        type === "product.tenant.activated.v1" &&
        data.generation === resumed.generation,
    );

    const restored = await runtime.identity.execute(
      identityProjectionWorker,
      identityCommandFromTenantEvent(
        activeEvent,
        "c04-pg-out-of-order-project-active",
      ),
    );
    const staleResume = await runtime.identity.execute(
      identityProjectionWorker,
      identityCommandFromTenantEvent(
        delayedResumeEvent,
        "c04-pg-out-of-order-project-resume",
      ),
    );
    const identitySnapshot = await runtime.identity.snapshot(
      identityProjectionWorker,
      { tenantId: resumed.tenantId },
    );

    assert.equal(restored.projectionState, "READY");
    assert.equal(restored.generation, resumed.generation);
    assert.equal(restored.applied, true);
    assert.equal(staleResume.stale, true);
    assert.equal(staleResume.applied, false);
    assert.equal(identitySnapshot.projectionState, "READY");
    assert.equal(identitySnapshot.generation, resumed.generation);
  });

  await t.test("PG-04 exchanges one concurrent login callback once", async () => {
    await resetDatabase();
    const runtime = createRuntime();
    const bootstrapped = await bootstrapActive(runtime);
    const started = await runtime.identity.startLogin(portalContext, {
      tenantId: bootstrapped.created.tenantId,
      providerConnectionId: bootstrapped.projected.providerConnectionId,
      returnRoute: "PORTAL_HOME",
    });
    let releaseExchange;
    let markExchangeStarted;
    const exchangeStarted = new Promise((resolve) => {
      markExchangeStarted = resolve;
    });
    const exchangeReleased = new Promise((resolve) => {
      releaseExchange = resolve;
    });
    runtime.broker.beforeExchange = async () => {
      markExchangeStarted();
      await exchangeReleased;
    };
    const callback = {
      transactionId: started.transactionId,
      state: started.state,
      authorizationCode: "c04-pg-concurrent-code",
      codeVerifier: started.codeVerifier,
    };
    const first = runtime.identity.completeLogin(portalContext, callback);
    await exchangeStarted;
    const replays = await Promise.allSettled(
      Array.from({ length: 15 }, () =>
        runtime.identity.completeLogin(portalContext, callback),
      ),
    );
    releaseExchange();
    await first;
    assert.equal(
      replays.every(
        ({ status, reason }) =>
          status === "rejected" && reason.code === "LOGIN_REPLAY_DETECTED",
      ),
      true,
    );
    assert.equal(runtime.broker.exchangeCount, 1);
    const sessions = await pool.query(
      "SELECT count(*) FROM aios_core.identity_session",
    );
    assert.equal(Number(sessions.rows[0].count), 1);
  });

  await t.test("PG-04B fences both login and termination commit orders", async () => {
    await resetDatabase();
    const loginFirst = createRuntime();
    const firstBootstrap = await bootstrapActive(loginFirst);
    const firstStarted = await loginFirst.identity.startLogin(portalContext, {
      tenantId: firstBootstrap.created.tenantId,
      providerConnectionId: firstBootstrap.projected.providerConnectionId,
      returnRoute: "PORTAL_HOME",
    });
    loginFirst.identityStoreControl.beforeSessionRead = async (readCount) => {
      if (readCount !== 1) return;
      await loginFirst.identity.execute(identityProvisioningWorker, {
        kind: "APPLY_SYNTHETIC_ACCOUNT_SNAPSHOT",
        idempotencyKey: "c04-pg-login-first-terminate",
        tenantId: firstBootstrap.created.tenantId,
        providerConnectionId: firstBootstrap.projected.providerConnectionId,
        fixtureUserId: "northstar-fasteners-user-ava",
        sourceEventId: "c04-pg-login-first-terminate-source",
        sourceRevision: 2,
        desiredState: "TERMINATED",
        correlationId: "c04-pg-login-first-terminate",
      });
    };
    await assert.rejects(
      loginFirst.identity.completeLogin(portalContext, {
        transactionId: firstStarted.transactionId,
        state: firstStarted.state,
        authorizationCode: "c04-pg-login-first-code",
        codeVerifier: firstStarted.codeVerifier,
      }),
      (error) => error.code === "AUTHENTICATION_FAILED",
    );
    const afterLoginFirst = await pool.query(`
      SELECT
        (SELECT count(*) FROM aios_core.identity_session) AS sessions,
        (SELECT count(*) FROM aios_core.identity_session
          WHERE status = 'ACTIVE') AS active_sessions,
        (SELECT state FROM aios_core.identity_account LIMIT 1) AS account_state
    `);
    assert.equal(Number(afterLoginFirst.rows[0].sessions), 1);
    assert.equal(Number(afterLoginFirst.rows[0].active_sessions), 0);
    assert.equal(afterLoginFirst.rows[0].account_state, "TERMINATED");

    await resetDatabase();
    const terminationFirst = createRuntime();
    const secondBootstrap = await bootstrapActive(terminationFirst);
    const secondStarted = await terminationFirst.identity.startLogin(
      portalContext,
      {
        tenantId: secondBootstrap.created.tenantId,
        providerConnectionId: secondBootstrap.projected.providerConnectionId,
        returnRoute: "PORTAL_HOME",
      },
    );
    terminationFirst.broker.beforeExchange = async () => {
      await terminationFirst.identity.execute(identityProvisioningWorker, {
        kind: "APPLY_SYNTHETIC_ACCOUNT_SNAPSHOT",
        idempotencyKey: "c04-pg-termination-first",
        tenantId: secondBootstrap.created.tenantId,
        providerConnectionId: secondBootstrap.projected.providerConnectionId,
        fixtureUserId: "northstar-fasteners-user-ava",
        sourceEventId: "c04-pg-termination-first-source",
        sourceRevision: 2,
        desiredState: "TERMINATED",
        correlationId: "c04-pg-termination-first",
      });
    };
    await assert.rejects(
      terminationFirst.identity.completeLogin(portalContext, {
        transactionId: secondStarted.transactionId,
        state: secondStarted.state,
        authorizationCode: "c04-pg-termination-first-code",
        codeVerifier: secondStarted.codeVerifier,
      }),
      (error) => error.code === "AUTHENTICATION_FAILED",
    );
    const afterTerminationFirst = await pool.query(`
      SELECT
        (SELECT count(*) FROM aios_core.identity_session) AS sessions,
        (SELECT state FROM aios_core.identity_account LIMIT 1) AS account_state
    `);
    assert.equal(Number(afterTerminationFirst.rows[0].sessions), 0);
    assert.equal(afterTerminationFirst.rows[0].account_state, "TERMINATED");
  });

  await t.test("PG-04C rotates provider keys through versioned configuration", async () => {
    await resetDatabase();
    const runtime = createRuntime();
    const bootstrapped = await bootstrapActive(runtime);
    const started = await runtime.identity.startLogin(portalContext, {
      tenantId: bootstrapped.created.tenantId,
      providerConnectionId: bootstrapped.projected.providerConnectionId,
      returnRoute: "PORTAL_HOME",
    });
    const rotated = await runtime.identity.execute(identityProviderManager, {
      kind: "ROTATE_SYNTHETIC_PROVIDER_KEYS",
      idempotencyKey: "c04-pg-rotate-v2",
      tenantId: bootstrapped.created.tenantId,
      providerConnectionId: bootstrapped.projected.providerConnectionId,
      expectedConfigurationVersion: 1,
      allowedKeyIds: ["synthetic-k2"],
      emergency: false,
      correlationId: "c04-pg-rotate-v2",
    });
    assert.equal(rotated.configurationVersion, 2);
    runtime.broker.assertions.set("c04-pg-grace-code", {
      protocol: "OIDC",
      signatureVerified: true,
      synthetic: true,
      issuer: ISSUER,
      audience: [CLIENT_ID],
      authorizedParty: CLIENT_ID,
      subject: "northstar-fasteners-user-ava",
      nonce: runtime.broker.starts.at(-1).nonce,
      issuedAt: NOW,
      notBefore: NOW,
      expiresAt: "2026-07-26T05:00:00.000Z",
      authenticationTime: NOW,
      authenticationMethods: ["pwd", "mfa"],
      algorithm: "RS256",
      keyId: "synthetic-k1",
      configurationVersion: 1,
    });
    const graceSession = await runtime.identity.completeLogin(
      portalContext,
      {
        transactionId: started.transactionId,
        state: started.state,
        authorizationCode: "c04-pg-grace-code",
        codeVerifier: started.codeVerifier,
      },
    );
    assert.equal(graceSession.providerConfigurationVersion, 1);

    const nextStarted = await runtime.identity.startLogin(portalContext, {
      tenantId: bootstrapped.created.tenantId,
      providerConnectionId: bootstrapped.projected.providerConnectionId,
      returnRoute: "PORTAL_HOME",
    });
    runtime.broker.assertions.set("c04-pg-current-code", {
      protocol: "OIDC",
      signatureVerified: true,
      synthetic: true,
      issuer: ISSUER,
      audience: [CLIENT_ID],
      authorizedParty: CLIENT_ID,
      subject: "northstar-fasteners-user-ava",
      nonce: runtime.broker.starts.at(-1).nonce,
      issuedAt: NOW,
      notBefore: NOW,
      expiresAt: "2026-07-26T05:00:00.000Z",
      authenticationTime: NOW,
      authenticationMethods: ["pwd", "mfa"],
      algorithm: "RS256",
      keyId: "synthetic-k2",
      configurationVersion: 2,
    });
    const currentSession = await runtime.identity.completeLogin(
      portalContext,
      {
        transactionId: nextStarted.transactionId,
        state: nextStarted.state,
        authorizationCode: "c04-pg-current-code",
        codeVerifier: nextStarted.codeVerifier,
      },
    );
    assert.equal(currentSession.providerConfigurationVersion, 2);

    await assert.rejects(
      runtime.identity.execute(identityProviderManager, {
        kind: "RETIRE_SYNTHETIC_PROVIDER_CONFIGURATION",
        idempotencyKey: "c04-pg-retire-v1-too-early",
        tenantId: bootstrapped.created.tenantId,
        providerConnectionId: bootstrapped.projected.providerConnectionId,
        configurationVersion: 1,
        correlationId: "c04-pg-retire-v1-too-early",
      }),
      (error) => error.code === "PROVIDER_CONFIGURATION_CONFLICT",
    );
    runtime.setTime("2026-07-26T04:05:00.000Z");
    await runtime.identity.execute(identityProviderManager, {
      kind: "RETIRE_SYNTHETIC_PROVIDER_CONFIGURATION",
      idempotencyKey: "c04-pg-retire-v1-after-grace",
      tenantId: bootstrapped.created.tenantId,
      providerConnectionId: bootstrapped.projected.providerConnectionId,
      configurationVersion: 1,
      correlationId: "c04-pg-retire-v1-after-grace",
    });
    const configurations = await pool.query(`
      SELECT configuration_version, state
        FROM aios_core.identity_provider_configuration
       ORDER BY configuration_version
    `);
    assert.deepEqual(
      configurations.rows.map(({ configuration_version, state }) => [
        Number(configuration_version),
        state,
      ]),
      [
        [1, "RETIRED"],
        [2, "CURRENT"],
      ],
    );
    const sessionVersions = await pool.query(`
      SELECT provider_configuration_version
        FROM aios_core.identity_session
       ORDER BY provider_configuration_version
    `);
    assert.deepEqual(
      sessionVersions.rows.map(
        ({ provider_configuration_version }) =>
          Number(provider_configuration_version),
      ),
      [1, 2],
    );
  });

  await t.test("PG-04D emergency rotation retires every grace version", async () => {
    await resetDatabase();
    const runtime = createRuntime();
    const bootstrapped = await bootstrapActive(runtime);
    const pendingV1 = await runtime.identity.startLogin(portalContext, {
      tenantId: bootstrapped.created.tenantId,
      providerConnectionId: bootstrapped.projected.providerConnectionId,
      returnRoute: "PORTAL_HOME",
    });
    await runtime.identity.execute(identityProviderManager, {
      kind: "ROTATE_SYNTHETIC_PROVIDER_KEYS",
      idempotencyKey: "c04-pg-normal-v2-before-emergency",
      tenantId: bootstrapped.created.tenantId,
      providerConnectionId: bootstrapped.projected.providerConnectionId,
      expectedConfigurationVersion: 1,
      allowedKeyIds: ["synthetic-k2"],
      emergency: false,
      correlationId: "c04-pg-normal-v2-before-emergency",
    });
    await runtime.identity.execute(identityProviderManager, {
      kind: "ROTATE_SYNTHETIC_PROVIDER_KEYS",
      idempotencyKey: "c04-pg-emergency-v3",
      tenantId: bootstrapped.created.tenantId,
      providerConnectionId: bootstrapped.projected.providerConnectionId,
      expectedConfigurationVersion: 2,
      allowedKeyIds: ["synthetic-k3"],
      emergency: true,
      correlationId: "c04-pg-emergency-v3",
    });

    await assert.rejects(
      runtime.identity.completeLogin(portalContext, {
        transactionId: pendingV1.transactionId,
        state: pendingV1.state,
        authorizationCode: "must-not-be-exchanged-after-emergency",
        codeVerifier: pendingV1.codeVerifier,
      }),
      (error) => error.code === "PROVIDER_CONFIGURATION_RETIRED",
    );
    assert.equal(runtime.broker.exchangeCount, 0);
    const configurations = await pool.query(`
      SELECT configuration_version, state
        FROM aios_core.identity_provider_configuration
       ORDER BY configuration_version
    `);
    assert.deepEqual(
      configurations.rows.map(({ configuration_version, state }) => [
        Number(configuration_version),
        state,
      ]),
      [
        [1, "RETIRED"],
        [2, "RETIRED"],
        [3, "CURRENT"],
      ],
    );
  });

  await t.test("PG-05 rolls back every C04 row when commit is interrupted", async () => {
    await resetDatabase();
    const normalRuntime = createRuntime();
    const created = await normalRuntime.tenantRegistry.execute(
      tenantOperator,
      {
        kind: "CREATE_SYNTHETIC_TENANT",
        idempotencyKey: "c04-pg-crash-create",
        creationKey: "p1:SYNTHETIC-SEED-001:c04-pg-crash",
        fixtureRef: FIXTURE_REF,
        configRefs: ["fixture://SYNTHETIC-SEED-001"],
        correlationId: "c04-pg-crash",
      },
    );
    const tenant = await normalRuntime.tenantRegistry.snapshot(
      tenantRegistryContext,
      created.tenantId,
    );
    const crashRuntime = createRuntime({
      identityPool: crashBeforeCommitPool(),
    });
    await assert.rejects(
      crashRuntime.identity.execute(
        identityProjectionWorker,
        identityCommandFromTenantEvent(
          tenant.outbox[0],
          "c04-pg-crash-project",
        ),
      ),
      (error) => error.code === "STORE_UNAVAILABLE",
    );
    const counts = await pool.query(`
      SELECT
        (SELECT count(*) FROM aios_core.identity_provider) AS providers,
        (SELECT count(*) FROM aios_core.identity_tenant_projection) AS projections,
        (SELECT count(*) FROM aios_core.identity_source_receipt) AS source_receipts,
        (SELECT count(*) FROM aios_core.identity_event) AS events,
        (SELECT count(*) FROM aios_core.identity_outbox) AS outbox,
        (SELECT count(*) FROM aios_core.identity_command_receipt) AS commands
    `);
    assert.deepEqual(
      Object.values(counts.rows[0]).map(Number),
      [0, 0, 0, 0, 0, 0],
    );
  });

  await t.test("PG-06 database guards reject security-state rewrites", async () => {
    await resetDatabase();
    const runtime = createRuntime();
    const bootstrapped = await bootstrapActive(runtime);
    const { completed } = await startAndCompleteLogin(
      runtime,
      bootstrapped.created.tenantId,
      bootstrapped.projected.providerConnectionId,
    );
    for (const query of [
      {
        text: `UPDATE aios_core.identity_provider
                  SET issuer = 'https://attacker.example'
                WHERE provider_connection_id = $1`,
        values: [bootstrapped.projected.providerConnectionId],
      },
      {
        text: `UPDATE aios_core.identity_account
                  SET subject = 'rebound-subject'
                WHERE account_id = $1`,
        values: [bootstrapped.account.accountId],
      },
      {
        text: `UPDATE aios_core.identity_tenant_projection
                  SET state = 'SUSPENDED'
                WHERE tenant_id = $1`,
        values: [bootstrapped.created.tenantId],
      },
      {
        text: `UPDATE aios_core.identity_source_receipt
                  SET result = '{}'::jsonb
                WHERE tenant_id = $1`,
        values: [bootstrapped.created.tenantId],
      },
    ]) {
      await assert.rejects(
        pool.query(query),
        (error) => error.code === "23000",
      );
    }
    await runtime.identity.execute(
      {
        actorId: "syn_svc_c04_pg_session",
        capabilities: ["IDENTITY_SESSION_REVOKE"],
        synthetic: true,
      },
      {
        kind: "REVOKE_SESSION",
        idempotencyKey: "c04-pg-revoke",
        tenantId: bootstrapped.created.tenantId,
        sessionId: completed.sessionId,
        reasonRef: "synthetic://c04-pg-logout",
        correlationId: "c04-pg-logout",
      },
    );
    await assert.rejects(
      pool.query(
        `UPDATE aios_core.identity_session
            SET status = 'ACTIVE', revoked_at = NULL
          WHERE session_id = $1`,
        [completed.sessionId],
      ),
      (error) => error.code === "23000",
    );
  });
});
