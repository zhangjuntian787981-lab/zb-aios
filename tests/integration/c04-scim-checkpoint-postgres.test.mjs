import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import pg from "pg";
import {
  createKeycloakScimProvisioningAdapter,
  KeycloakScimProvisioningError,
} from "../../lib/keycloak-scim-provisioning-adapter.mjs";
import { createPostgresScimCheckpointStore } from "../../lib/postgres-scim-checkpoint-store.mjs";

const { Pool } = pg;
const migrationUrl = new URL(
  "../../implementation/p1/c04/postgresql/0005_scim_checkpoint.sql",
  import.meta.url,
);
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
const providerMigrationUrl = new URL(
  "../../implementation/p1/c04/postgresql/0004_versioned_provider_configuration.sql",
  import.meta.url,
);
const migrationSql = await readFile(migrationUrl, "utf8");
const c03MigrationSql = await readFile(c03MigrationUrl, "utf8");
const c04MigrationSql = await readFile(c04MigrationUrl, "utf8");
const outboxMigrationSql = await readFile(outboxMigrationUrl, "utf8");
const providerMigrationSql = await readFile(providerMigrationUrl, "utf8");

const ORIGIN = "https://scim.c04-synthetic.example";
const REALM = "synthetic";
const ISSUER = `${ORIGIN}/realms/${REALM}`;
const AUDIENCE = `${ISSUER}/scim/v2`;
const ACCESS_TOKEN = [
  "eyJhbGciOiJub25lIn0",
  Buffer.from(
    JSON.stringify({
      iss: ISSUER,
      aud: AUDIENCE,
      exp: 4102444800,
    }),
  ).toString("base64url"),
  "synthetic-signature",
].join(".");
const NAMESPACE_A = Object.freeze({
  tenantId: "stn_01984710-0000-7000-8000-000000000001",
  providerConnectionId:
    "idp_01984710-0000-7000-8000-000000000001",
});
const NAMESPACE_B = Object.freeze({
  tenantId: "stn_01984710-0000-7000-8000-000000000002",
  providerConnectionId:
    "idp_01984710-0000-7000-8000-000000000002",
});
const FORGED_NAMESPACE = Object.freeze({
  tenantId: "stn_01984710-0000-7000-8000-000000000003",
  providerConnectionId:
    "idp_01984710-0000-7000-8000-000000000003",
});

function postgresConfig() {
  if (process.env.C04_SCIM_CHECKPOINT_TEST_EPHEMERAL !== "1") {
    throw new Error(
      "C04_SCIM_CHECKPOINT_TEST_EPHEMERAL=1 is required.",
    );
  }
  for (const name of [
    "C04_SCIM_CHECKPOINT_TEST_PGHOST",
    "C04_SCIM_CHECKPOINT_TEST_PGPORT",
    "C04_SCIM_CHECKPOINT_TEST_PGDATABASE",
    "C04_SCIM_CHECKPOINT_TEST_PGUSER",
  ]) {
    if (!process.env[name]) throw new Error(`${name} is required.`);
  }
  return {
    host: process.env.C04_SCIM_CHECKPOINT_TEST_PGHOST,
    port: Number(process.env.C04_SCIM_CHECKPOINT_TEST_PGPORT),
    database: process.env.C04_SCIM_CHECKPOINT_TEST_PGDATABASE,
    user: process.env.C04_SCIM_CHECKPOINT_TEST_PGUSER,
    max: 8,
  };
}

function command({
  externalId,
  userName,
  sourceRevision,
  familyName,
  desiredState = "ACTIVE",
}) {
  return {
    externalId,
    userName,
    sourceRevision,
    desiredState,
    profile: {
      givenName: "Synthetic",
      familyName,
      email: `${userName}@c04-synthetic.example`,
    },
  };
}

function jsonResponse(status, value) {
  return { status, body: JSON.stringify(value) };
}

function fakeScimTransport() {
  const byExternalId = new Map();
  const byResourceId = new Map();
  let nextResourceId = 0;

  function save(value, resourceId) {
    const resource = structuredClone({ ...value, id: resourceId });
    byExternalId.set(resource.externalId, resource);
    byResourceId.set(resourceId, resource);
    return resource;
  }

  return {
    snapshot(externalId) {
      return structuredClone(byExternalId.get(externalId) ?? null);
    },
    async request({ url, method, body }) {
      const target = new URL(url);
      const usersPath = target.pathname.endsWith("/Users");
      if (usersPath && target.search) {
        const filter = target.searchParams.get("filter");
        const match = /^externalId eq "([^"]+)"$/.exec(filter ?? "");
        const resource = match
          ? byExternalId.get(match[1]) ?? null
          : null;
        return jsonResponse(200, {
          totalResults: resource ? 1 : 0,
          Resources: resource ? [resource] : [],
        });
      }

      const parsedBody = body === undefined ? null : JSON.parse(body);
      if (usersPath && method === "POST") {
        nextResourceId += 1;
        return jsonResponse(
          201,
          save(parsedBody, `synthetic-resource-${nextResourceId}`),
        );
      }

      const resourceId = decodeURIComponent(
        target.pathname.slice(target.pathname.lastIndexOf("/") + 1),
      );
      if (method === "PUT") {
        return jsonResponse(200, save(parsedBody, resourceId));
      }
      if (method === "GET" && byResourceId.has(resourceId)) {
        return jsonResponse(200, byResourceId.get(resourceId));
      }
      return jsonResponse(404, {});
    },
  };
}

function createAdapter({
  checkpointStore,
  transport,
  getAccessToken = async () => ({ accessToken: ACCESS_TOKEN }),
}) {
  return createKeycloakScimProvisioningAdapter({
    origin: ORIGIN,
    realm: REALM,
    audience: AUDIENCE,
    checkpointStore,
    request: transport.request,
    getAccessToken,
  });
}

function wait(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

function createStore(namespace = NAMESPACE_A) {
  return createPostgresScimCheckpointStore({
    pool,
    ...namespace,
  });
}

async function expectConstraint(promise, constraint) {
  await assert.rejects(
    promise,
    (error) =>
      error.code === "23000" &&
      error.constraint === constraint,
  );
}

const pool = new Pool(postgresConfig());

async function seedNamespace(namespace, suffix) {
  const client = await pool.connect();
  const now = "2026-07-26T08:00:00.000Z";
  const redirectRoutes = {
    PORTAL_HOME: `https://portal-${suffix}.c04-synthetic.example/auth/callback`,
  };
  try {
    await client.query("BEGIN");
    await client.query(
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
       )
       VALUES (
         $1,
         'SYNTHETIC',
         'PROVISIONING',
         1,
         1,
         $2,
         $3,
         $4,
         '[]'::jsonb,
         $5,
         $6,
         $7,
         $7
       )`,
      [
        namespace.tenantId,
        `p1:scim-checkpoint:${suffix}`,
        `fixture://scim-checkpoint-${suffix}`,
        `sha256:${suffix.repeat(64)}`,
        `sns_01984710-0000-7000-8000-00000000000${suffix}`,
        `op_01984710-0000-7000-8000-00000000000${suffix}`,
        now,
      ],
    );
    await client.query(
      `INSERT INTO aios_core.identity_provider (
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
       )
       VALUES (
         $1,
         $2,
         'SYNTHETIC',
         'OIDC',
         $3,
         $4,
         $5,
         1,
         '["RS256"]'::jsonb,
         '["synthetic-k1"]'::jsonb,
         '["mfa"]'::jsonb,
         3600,
         '["OIDC"]'::jsonb,
         'SCIM_REQUIRED',
         'ACTIVE',
         $6,
         $6
       )`,
      [
        namespace.providerConnectionId,
        namespace.tenantId,
        `https://idp-${suffix}.c04-synthetic.example/realms/synthetic`,
        `synthetic-client-${suffix}`,
        redirectRoutes,
        now,
      ],
    );
    await client.query(
      `INSERT INTO aios_core.identity_provider_configuration (
         provider_connection_id,
         tenant_id,
         configuration_version,
         redirect_routes,
         allowed_algorithms,
         allowed_key_ids,
         required_authentication_methods,
         max_authentication_age_seconds,
         upstream_protocols,
         state,
         activated_at,
         grace_until,
         retired_at,
         retirement_mode
       )
       VALUES (
         $1,
         $2,
         1,
         $3,
         '["RS256"]'::jsonb,
         '["synthetic-k1"]'::jsonb,
         '["mfa"]'::jsonb,
         3600,
         '["OIDC"]'::jsonb,
         'CURRENT',
         $4,
         NULL,
         NULL,
         NULL
       )`,
      [
        namespace.providerConnectionId,
        namespace.tenantId,
        redirectRoutes,
        now,
      ],
    );
    await client.query("COMMIT");
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
}

test("PostgreSQL SCIM checkpoints serialize adapters and enforce tombstones", async (t) => {
  t.after(async () => {
    await pool.end();
  });

  const safety = await pool.query(
    "SELECT current_database() AS database, to_regnamespace('aios_core') AS schema",
  );
  assert.match(
    safety.rows[0].database,
    /^c04_scim_checkpoint_test_[0-9]+$/,
  );
  assert.equal(safety.rows[0].schema, null);
  await pool.query(c03MigrationSql);
  await pool.query(c04MigrationSql);
  await pool.query(outboxMigrationSql);
  await pool.query(providerMigrationSql);
  await seedNamespace(NAMESPACE_A, "1");
  await seedNamespace(NAMESPACE_B, "2");
  await pool.query(migrationSql);
  const version = await pool.query("SHOW server_version_num");
  assert.equal(Math.trunc(Number(version.rows[0].server_version_num) / 10000), 17);

  await t.test("tenant and provider namespaces isolate locks and names", async () => {
    const externalId = "synthetic-directory-shared";
    const userName = "synthetic-shared";
    const storeA = createStore(NAMESPACE_A);
    const storeB = createStore(NAMESPACE_B);
    let releaseA;
    let observeA;
    const gateA = new Promise((resolve) => {
      releaseA = resolve;
    });
    const enteredA = new Promise((resolve) => {
      observeA = resolve;
    });
    const heldA = storeA.runExclusive(externalId, async () => {
      observeA();
      await gateA;
    });
    await enteredA;
    await Promise.race([
      storeB.runExclusive(externalId, async () => {}),
      wait(2_000).then(() => {
        throw new Error("another namespace was blocked by the advisory lock");
      }),
    ]);
    releaseA();
    await heldA;

    const pending = {
      externalId,
      userName,
      sourceRevision: 1,
      desiredState: "ACTIVE",
      profile: {
        givenName: "Synthetic",
        familyName: "Shared",
        email: "synthetic-shared@c04-synthetic.example",
      },
      status: "PENDING",
      resourceId: null,
    };
    await Promise.all([
      storeA.runExclusive(externalId, () =>
        storeA.transact(externalId, () => ({
          next: pending,
          value: null,
        })),
      ),
      storeB.runExclusive(externalId, () =>
        storeB.transact(externalId, () => ({
          next: pending,
          value: null,
        })),
      ),
    ]);
    const rows = await pool.query(
      `SELECT tenant_id, provider_connection_id
         FROM aios_core.scim_provisioning_checkpoint
        WHERE external_id = $1
          AND user_name = $2
        ORDER BY tenant_id`,
      [externalId, userName],
    );
    assert.deepEqual(rows.rows, [
      {
        tenant_id: NAMESPACE_A.tenantId,
        provider_connection_id: NAMESPACE_A.providerConnectionId,
      },
      {
        tenant_id: NAMESPACE_B.tenantId,
        provider_connection_id: NAMESPACE_B.providerConnectionId,
      },
    ]);
  });

  await t.test("a forged but well-formed store namespace fails closed", async () => {
    const externalId = "synthetic-directory-forged";
    const store = createStore(FORGED_NAMESPACE);
    const pending = {
      externalId,
      userName: "synthetic-forged",
      sourceRevision: 1,
      desiredState: "ACTIVE",
      profile: {
        givenName: "Synthetic",
        familyName: "Forged",
        email: "synthetic-forged@c04-synthetic.example",
      },
      status: "PENDING",
      resourceId: null,
    };

    await assert.rejects(
      store.runExclusive(externalId, () =>
        store.transact(externalId, () => ({
          next: pending,
          value: null,
        })),
      ),
      (error) => error.code === "CHECKPOINT_STORE_UNAVAILABLE",
    );
    const rows = await pool.query(
      `SELECT count(*)::integer AS count
         FROM aios_core.scim_provisioning_checkpoint
        WHERE tenant_id = $1
          AND provider_connection_id = $2`,
      [
        FORGED_NAMESPACE.tenantId,
        FORGED_NAMESPACE.providerConnectionId,
      ],
    );
    assert.equal(rows.rows[0].count, 0);
  });

  await t.test("two stores and adapters apply revisions in lock order", async () => {
    const externalId = "synthetic-directory-concurrent";
    const userName = "synthetic-concurrent";
    const transport = fakeScimTransport();
    const storeA = createStore();
    const storeB = createStore();
    let releaseFirstToken;
    let observeFirstToken;
    const firstTokenGate = new Promise((resolve) => {
      releaseFirstToken = resolve;
    });
    const firstTokenObserved = new Promise((resolve) => {
      observeFirstToken = resolve;
    });
    let secondTokenCalls = 0;
    const adapterA = createAdapter({
      checkpointStore: storeA,
      transport,
      getAccessToken: async () => {
        observeFirstToken();
        await firstTokenGate;
        return { accessToken: ACCESS_TOKEN };
      },
    });
    const adapterB = createAdapter({
      checkpointStore: storeB,
      transport,
      getAccessToken: async () => {
        secondTokenCalls += 1;
        return { accessToken: ACCESS_TOKEN };
      },
    });

    const first = adapterA.apply(
      command({
        externalId,
        userName,
        sourceRevision: 1,
        familyName: "RevisionOne",
      }),
    );
    await firstTokenObserved;
    const second = adapterB.apply(
      command({
        externalId,
        userName,
        sourceRevision: 2,
        familyName: "RevisionTwo",
      }),
    );
    await wait(100);
    assert.equal(secondTokenCalls, 0);
    releaseFirstToken();
    await Promise.all([first, second]);

    const checkpoint = await pool.query(
      `SELECT source_revision, status, desired_state
         FROM aios_core.scim_provisioning_checkpoint
        WHERE tenant_id = $1
          AND provider_connection_id = $2
          AND external_id = $3`,
      [NAMESPACE_A.tenantId, NAMESPACE_A.providerConnectionId, externalId],
    );
    assert.deepEqual(checkpoint.rows[0], {
      source_revision: "2",
      status: "CONFIRMED",
      desired_state: "ACTIVE",
    });
    assert.equal(
      transport.snapshot(externalId).name.familyName,
      "RevisionTwo",
    );
  });

  await t.test("a callback exception releases the lock for termination", async () => {
    const externalId = "synthetic-directory-recovery";
    const userName = "synthetic-recovery";
    const transport = fakeScimTransport();
    const failing = createAdapter({
      checkpointStore: createStore(),
      transport,
      getAccessToken: async () => {
        throw new Error("synthetic token callback failure");
      },
    });
    await assert.rejects(
      failing.apply(
        command({
          externalId,
          userName,
          sourceRevision: 1,
          familyName: "Pending",
        }),
      ),
      (error) =>
        error instanceof KeycloakScimProvisioningError &&
        error.code === "TOKEN_REQUEST_FAILED",
    );

    const terminating = createAdapter({
      checkpointStore: createStore(),
      transport,
    });
    const result = await Promise.race([
      terminating.apply(
        command({
          externalId,
          userName,
          sourceRevision: 2,
          familyName: "Terminated",
          desiredState: "TERMINATED",
        }),
      ),
      wait(2_000).then(() => {
        throw new Error("termination remained blocked by a leaked lock");
      }),
    ]);
    assert.equal(result.state, "TERMINATED");

    const checkpoint = await pool.query(
      `SELECT source_revision, status, desired_state
         FROM aios_core.scim_provisioning_checkpoint
        WHERE tenant_id = $1
          AND provider_connection_id = $2
          AND external_id = $3`,
      [NAMESPACE_A.tenantId, NAMESPACE_A.providerConnectionId, externalId],
    );
    assert.deepEqual(checkpoint.rows[0], {
      source_revision: "2",
      status: "CONFIRMED",
      desired_state: "TERMINATED",
    });
    assert.equal(transport.snapshot(externalId).active, false);
  });

  await t.test("direct SQL cannot bypass checkpoint invariants", async () => {
    const profile = {
      givenName: "Direct",
      familyName: "Sql",
      email: "direct-sql@c04-synthetic.example",
    };
    await assert.rejects(
      pool.query(
        `INSERT INTO aios_core.scim_provisioning_checkpoint (
           tenant_id,
           provider_connection_id,
           external_id,
           user_name,
           source_revision,
           desired_state,
           profile,
           status,
           resource_id
         )
         VALUES ($1, $2, $3, $4, 1, 'ACTIVE', $5, 'PENDING', NULL)`,
        [
          FORGED_NAMESPACE.tenantId,
          FORGED_NAMESPACE.providerConnectionId,
          "synthetic-directory-forged-sql",
          "synthetic-forged-sql",
          profile,
        ],
      ),
      (error) =>
        error.code === "23503" &&
        error.constraint === "scim_checkpoint_provider_fkey",
    );
    for (const [externalId, userName, status, resourceId] of [
      [
        "synthetic-directory-initial-confirmed",
        "synthetic-initial-confirmed",
        "CONFIRMED",
        "synthetic-resource-initial",
      ],
      [
        "synthetic-directory-initial-resource",
        "synthetic-initial-resource",
        "PENDING",
        "synthetic-resource-initial",
      ],
    ]) {
      await expectConstraint(
        pool.query(
          `INSERT INTO aios_core.scim_provisioning_checkpoint (
             tenant_id,
             provider_connection_id,
             external_id,
             user_name,
             source_revision,
             desired_state,
             profile,
             status,
             resource_id
           )
           VALUES ($1, $2, $3, $4, 1, 'ACTIVE', $5, $6, $7)`,
          [
            NAMESPACE_A.tenantId,
            NAMESPACE_A.providerConnectionId,
            externalId,
            userName,
            profile,
            status,
            resourceId,
          ],
        ),
        "scim_checkpoint_initial_state_guard",
      );
    }
    await pool.query(
      `INSERT INTO aios_core.scim_provisioning_checkpoint (
         tenant_id,
         provider_connection_id,
         external_id,
         user_name,
         source_revision,
         desired_state,
         profile,
         status,
         resource_id
       )
       VALUES ($1, $2, $3, $4, 1, 'ACTIVE', $5, 'PENDING', NULL)`,
      [
        NAMESPACE_A.tenantId,
        NAMESPACE_A.providerConnectionId,
        "synthetic-directory-direct",
        "synthetic-direct",
        profile,
      ],
    );

    await expectConstraint(
      pool.query(
        `UPDATE aios_core.scim_provisioning_checkpoint
            SET tenant_id = $4,
                provider_connection_id = $5,
                external_id = 'synthetic-directory-rebound'
          WHERE tenant_id = $1
            AND provider_connection_id = $2
            AND external_id = $3`,
        [
          NAMESPACE_A.tenantId,
          NAMESPACE_A.providerConnectionId,
          "synthetic-directory-direct",
          NAMESPACE_B.tenantId,
          NAMESPACE_B.providerConnectionId,
        ],
      ),
      "scim_checkpoint_binding_guard",
    );
    await expectConstraint(
      pool.query(
        `UPDATE aios_core.scim_provisioning_checkpoint
            SET user_name = 'synthetic-rebound'
          WHERE tenant_id = $1
            AND provider_connection_id = $2
            AND external_id = 'synthetic-directory-direct'`,
        [NAMESPACE_A.tenantId, NAMESPACE_A.providerConnectionId],
      ),
      "scim_checkpoint_binding_guard",
    );

    await pool.query(
      `UPDATE aios_core.scim_provisioning_checkpoint
          SET source_revision = 2,
              desired_state = 'TERMINATED',
              updated_at = statement_timestamp()
        WHERE tenant_id = $1
          AND provider_connection_id = $2
          AND external_id = 'synthetic-directory-direct'`,
      [NAMESPACE_A.tenantId, NAMESPACE_A.providerConnectionId],
    );
    await expectConstraint(
      pool.query(
        `UPDATE aios_core.scim_provisioning_checkpoint
            SET source_revision = 1
          WHERE tenant_id = $1
            AND provider_connection_id = $2
            AND external_id = 'synthetic-directory-direct'`,
        [NAMESPACE_A.tenantId, NAMESPACE_A.providerConnectionId],
      ),
      "scim_checkpoint_revision_guard",
    );
    await expectConstraint(
      pool.query(
        `UPDATE aios_core.scim_provisioning_checkpoint
            SET profile = profile ||
                '{"familyName":"ChangedAtSameRevision"}'::jsonb
          WHERE tenant_id = $1
            AND provider_connection_id = $2
            AND external_id = 'synthetic-directory-direct'`,
        [NAMESPACE_A.tenantId, NAMESPACE_A.providerConnectionId],
      ),
      "scim_checkpoint_content_guard",
    );
    await expectConstraint(
      pool.query(
        `UPDATE aios_core.scim_provisioning_checkpoint
            SET source_revision = 3,
                desired_state = 'ACTIVE'
          WHERE tenant_id = $1
            AND provider_connection_id = $2
            AND external_id = 'synthetic-directory-direct'`,
        [NAMESPACE_A.tenantId, NAMESPACE_A.providerConnectionId],
      ),
      "scim_checkpoint_terminal_guard",
    );
    await expectConstraint(
      pool.query(
        `DELETE FROM aios_core.scim_provisioning_checkpoint
          WHERE tenant_id = $1
            AND provider_connection_id = $2
            AND external_id = 'synthetic-directory-direct'`,
        [NAMESPACE_A.tenantId, NAMESPACE_A.providerConnectionId],
      ),
      "scim_checkpoint_no_delete",
    );
    await assert.rejects(
      pool.query(
        `INSERT INTO aios_core.scim_provisioning_checkpoint (
           tenant_id,
           provider_connection_id,
           external_id,
           user_name,
           source_revision,
           desired_state,
           profile,
           status,
           resource_id
         )
         VALUES (
           $1,
           $2,
           'synthetic-directory-other',
           'synthetic-direct',
           1,
           'ACTIVE',
           $3,
           'PENDING',
           NULL
         )`,
        [NAMESPACE_A.tenantId, NAMESPACE_A.providerConnectionId, profile],
      ),
      (error) =>
        error.code === "23505" &&
        error.constraint === "scim_checkpoint_user_name_key",
    );
  });
});
