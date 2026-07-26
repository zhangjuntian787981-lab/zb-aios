import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test, { after, before } from "node:test";
import pg from "pg";
import {
  AuditEvidenceError,
  createAuditEvidenceService,
  createMemoryAuditEvidenceStore,
  createSyntheticAuditEvidenceCatalog,
  verifyAuditExport,
} from "../../lib/c18-audit-evidence.mjs";
import {
  createPostgresAuditEvidenceStore,
} from "../../lib/c18-audit-evidence-postgres-store.mjs";
import {
  createC18AuditOutboxWorker,
} from "../../lib/c18-audit-outbox-worker.mjs";

const { Pool } = pg;
const migrationPaths = [
  "../../implementation/p1/c03/postgresql/0001_tenant_registry.sql",
  "../../implementation/p1/c07/postgresql/0011_tenant_data_isolation.sql",
  "../../implementation/p1/c07/postgresql/0012_tenant_data_runtime_roles.sql",
  "../../implementation/p1/c18/postgresql/0023_audit_evidence.sql",
  "../../implementation/p1/c18/postgresql/0024_audit_evidence_runtime_roles.sql",
];
const migrations = await Promise.all(
  migrationPaths.map((path) =>
    readFile(new URL(path, import.meta.url), "utf8"),
  ),
);
const catalog = createSyntheticAuditEvidenceCatalog(
  JSON.parse(
    await readFile(
      new URL(
        "../../implementation/p1/c18/synthetic-evidence-catalog.v1.json",
        import.meta.url,
      ),
      "utf8",
    ),
  ),
);
const TENANTS = [
  {
    tenantId: "stn_018f0000-0000-7000-8000-000000000010",
    fixtureId: "northstar",
    bundleRef:
      "fixture://c18/northstar/bundles/completed-analysis-v1",
    namespaceId: "sns_01984910-3000-7000-8000-000000000031",
    operationId: "op_01984910-3000-7000-8000-000000000041",
  },
  {
    tenantId: "stn_01984910-3000-7000-8000-000000000002",
    fixtureId: "blue-harbor",
    bundleRef:
      "fixture://c18/blue-harbor/bundles/completed-analysis-v1",
    namespaceId: "sns_01984910-3000-7000-8000-000000000032",
    operationId: "op_01984910-3000-7000-8000-000000000042",
  },
  {
    tenantId: "stn_01984910-3000-7000-8000-000000000003",
    fixtureId: "cedar",
    bundleRef:
      "fixture://c18/cedar/bundles/completed-analysis-v1",
    namespaceId: "sns_01984910-3000-7000-8000-000000000033",
    operationId: "op_01984910-3000-7000-8000-000000000043",
  },
];
const WRITER_LOGIN = "c18_test_writer_login";
const READER_LOGIN = "c18_test_reader_login";
const WORKER_LOGIN = "c18_test_worker_login";
const SCOPE_LOGIN = "c18_test_scope_login";
const HUMAN = "prn_018f0000-0000-7000-8000-000000000001";
const ACTOR = "prn_018f0000-0000-7000-8000-000000000002";
const DELEGATION =
  "dlg_018f0000-0000-7000-8000-000000000020";
const HASH =
  "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const PROJECTIONS = [
  "AUTHORIZATION",
  "IDENTITY",
  "KNOWLEDGE",
  "SECRET_REFS",
  "STORAGE",
];

function configuration(user = process.env.C18_TEST_PGUSER, max = 40) {
  if (process.env.C18_TEST_EPHEMERAL !== "1") {
    throw new Error("C18_TEST_EPHEMERAL=1 is required.");
  }
  for (const name of [
    "C18_TEST_PGHOST",
    "C18_TEST_PGPORT",
    "C18_TEST_PGDATABASE",
    "C18_TEST_PGUSER",
  ]) {
    if (!process.env[name]) throw new Error(`${name} is required.`);
  }
  return {
    host: process.env.C18_TEST_PGHOST,
    port: Number(process.env.C18_TEST_PGPORT),
    database: process.env.C18_TEST_PGDATABASE,
    user,
    max,
  };
}

function instant(offsetMilliseconds = 0) {
  return new Date(Date.now() + offsetMilliseconds).toISOString();
}

function deterministicIds(start = 3000) {
  let counter = start;
  return () => {
    counter += 1;
    return `018f0000-0000-7000-8000-${String(counter).padStart(12, "0")}`;
  };
}

function identity(tenantId) {
  return {
    tenantId,
    tenantKind: "SYNTHETIC",
    identityAccountId: "sia_synthetic",
    identityLinkId: "lnk_synthetic",
    sessionId: `session-${tenantId}`,
    humanSubject: {
      principalId: HUMAN,
      principalType: "HUMAN",
      lifecycleVersion: 1,
      securityEpoch: 1,
    },
    workloadActor: {
      principalId: ACTOR,
      principalType: "SERVICE",
      lifecycleVersion: 1,
      securityEpoch: 1,
    },
    purposeRef: "synthetic://c18/purpose/audit",
    delegationChain: [
      {
        delegationId: DELEGATION,
        delegatorPrincipalId: HUMAN,
        delegatePrincipalId: ACTOR,
        purposeRef: "synthetic://c18/purpose/audit",
        lifecycleVersion: 1,
        expiresAt: "2030-01-01T00:00:00.000Z",
      },
    ],
    trustSource:
      "VERIFIED_SESSION_IDENTITY_LINK_AND_WORKLOAD_CONTEXT",
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

function scope(tenant, correlationId = "c18-read") {
  const authorization = catalog.resolve(
    tenant.tenantId,
    tenant.bundleRef,
  ).authorization;
  return {
    trustSource: "C07_VERIFIED_TENANT_SCOPE",
    tenantId: tenant.tenantId,
    tenantKind: "SYNTHETIC",
    lifecycleVersion: 2,
    correlationId,
    decisionId: authorization.decisionId,
    evidenceRef: authorization.evidenceRef,
    policyVersion: authorization.version,
  };
}

async function seedTenant(adminPool, tenant, index) {
  const createdAt = instant(-60_000 + index * 1000);
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
      `c18-creation-${tenant.fixtureId}`,
      `fixture://c18/tenant/${tenant.fixtureId}`,
      HASH,
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
        `c18-${tenant.fixtureId}-${projection.toLowerCase()}`,
        createdAt,
      ],
    );
  }
  await adminPool.query(
    `UPDATE aios_core.tenant_registry
        SET state='ACTIVE',lifecycle_version=2,updated_at=$2
      WHERE tenant_id=$1`,
    [tenant.tenantId, instant(-30_000 + index * 1000)],
  );
  await adminPool.query(
    `INSERT INTO aios_data.tenant_data_lifecycle (
       tenant_id,tenant_kind,lifecycle_version,generation,operation_id,
       state,last_event_id,updated_at
     ) VALUES ($1,'SYNTHETIC',2,1,$2,'ACTIVE',$3,$4)`,
    [
      tenant.tenantId,
      tenant.operationId,
      `c18-active-${tenant.fixtureId}`,
      instant(-30_000 + index * 1000),
    ],
  );
}

let adminPool;
let writerPool;
let readerPool;
let outboxPool;
let scopePool;
let store;
let idFactory;
const clocks = new Map();

before(async () => {
  adminPool = new Pool(configuration());
  for (const migration of migrations) await adminPool.query(migration);
  await adminPool.query(
    `CREATE ROLE ${WRITER_LOGIN}
       LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE INHERIT NOREPLICATION
       NOBYPASSRLS;
     CREATE ROLE ${READER_LOGIN}
       LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE INHERIT NOREPLICATION
       NOBYPASSRLS;
     CREATE ROLE ${WORKER_LOGIN}
       LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE INHERIT NOREPLICATION
       NOBYPASSRLS;
     CREATE ROLE ${SCOPE_LOGIN}
       LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE INHERIT NOREPLICATION
       NOBYPASSRLS;
     GRANT aios_c18_writer TO ${WRITER_LOGIN};
     GRANT aios_c18_reader TO ${READER_LOGIN};
     GRANT aios_c18_outbox_worker TO ${WORKER_LOGIN};
     GRANT aios_c07_scope_runtime TO ${SCOPE_LOGIN};`,
  );
  for (const [index, tenant] of TENANTS.entries()) {
    await seedTenant(adminPool, tenant, index);
    clocks.set(tenant.tenantId, instant(index * 10));
  }
  writerPool = new Pool(configuration(WRITER_LOGIN));
  readerPool = new Pool(configuration(READER_LOGIN));
  outboxPool = new Pool(configuration(WORKER_LOGIN));
  scopePool = new Pool(configuration(SCOPE_LOGIN));
  store = createPostgresAuditEvidenceStore({
    writerPool,
    readerPool,
    outboxPool,
    scopePool,
  });
  idFactory = deterministicIds();
});

after(async () => {
  await Promise.allSettled([
    writerPool?.end(),
    readerPool?.end(),
    outboxPool?.end(),
    scopePool?.end(),
    adminPool?.end(),
  ]);
});

function serviceFor(tenant) {
  return createAuditEvidenceService({
    catalog,
    store,
    idFactory,
    clock: () => clocks.get(tenant.tenantId),
    stablePrincipalRegistry: {
      async resolveActionIdentity() {
        return identity(tenant.tenantId);
      },
    },
    tenantRegistry: {
      async admitNewRequest() {
        return {
          tenantId: tenant.tenantId,
          tenantKind: "SYNTHETIC",
          lifecycleVersion: 2,
        };
      },
    },
    tenantScopeFactory({ authorization, correlationId }) {
      return {
        ...scope(tenant, correlationId),
        decisionId: authorization.decisionId,
        evidenceRef: authorization.evidenceRef,
        policyVersion: authorization.version,
      };
    },
  });
}

function request(tenant, suffix) {
  return {
    sessionToken: "synthetic-session",
    delegationId: DELEGATION,
    idempotencyKey: `c18-${tenant.fixtureId}-${suffix}`,
    correlationId: `c18-${tenant.fixtureId}-${suffix}`,
    evidenceBundleRef: tenant.bundleRef,
  };
}

test("migrations enforce FORCE RLS and distinct least-privilege roles", async () => {
  const tables = await adminPool.query(
    `SELECT relname,relrowsecurity,relforcerowsecurity
       FROM pg_class
      WHERE relnamespace='aios_audit'::regnamespace
        AND relkind='r'
      ORDER BY relname`,
  );
  assert.equal(tables.rows.length, 4);
  assert.ok(
    tables.rows.every(
      (row) => row.relrowsecurity && row.relforcerowsecurity,
    ),
  );
  const roles = await adminPool.query(
    `SELECT rolname,rolsuper,rolbypassrls
       FROM pg_roles
      WHERE rolname IN (
        'aios_c18_writer',
        'aios_c18_reader',
        'aios_c18_outbox_worker'
      )
      ORDER BY rolname`,
  );
  assert.equal(roles.rows.length, 3);
  assert.ok(
    roles.rows.every((row) => !row.rolsuper && !row.rolbypassrls),
  );
  const privileges = await adminPool.query(
    `SELECT
       has_table_privilege(
         'aios_c18_reader',
         'aios_audit.audit_event',
         'SELECT'
       ) AS reader_select,
       has_table_privilege(
         'aios_c18_reader',
         'aios_audit.audit_event',
         'UPDATE'
       ) AS reader_update,
       has_table_privilege(
         'aios_c18_writer',
         'aios_audit.audit_event',
         'DELETE'
       ) AS writer_delete,
       has_table_privilege(
         'aios_c18_outbox_worker',
         'aios_audit.audit_outbox',
         'UPDATE'
       ) AS worker_outbox_update,
       has_table_privilege(
         'aios_c18_outbox_worker',
         'aios_audit.audit_event',
         'SELECT'
       ) AS worker_event_select`,
  );
  assert.deepEqual(privileges.rows[0], {
    reader_select: true,
    reader_update: false,
    writer_delete: false,
    worker_outbox_update: true,
    worker_event_select: false,
  });
});

test("AuditEvent, C18 Outbox and receipt commit atomically", async () => {
  const tenant = TENANTS[0];
  const service = serviceFor(tenant);
  const result = await service.append(
    context(tenant.tenantId),
    request(tenant, "atomic"),
  );
  assert.equal(result.sequence, 1);
  const counts = await adminPool.query(
    `SELECT
       (SELECT count(*)::int FROM aios_audit.audit_event
         WHERE tenant_id=$1) AS events,
       (SELECT count(*)::int FROM aios_audit.audit_outbox
         WHERE tenant_id=$1) AS outbox,
       (SELECT count(*)::int FROM aios_audit.audit_command_receipt
         WHERE tenant_id=$1) AS receipts`,
    [tenant.tenantId],
  );
  assert.deepEqual(counts.rows[0], {
    events: 1,
    outbox: 1,
    receipts: 1,
  });
  const duplicate = await service.append(
    context(tenant.tenantId),
    request(tenant, "atomic"),
  );
  assert.equal(duplicate.eventId, result.eventId);
  assert.equal(duplicate.duplicate, true);
});

test("concurrent PostgreSQL appends preserve one linear Tenant chain", async () => {
  const tenant = TENANTS[0];
  const service = serviceFor(tenant);
  await Promise.all(
    Array.from({ length: 20 }, (_, index) =>
      service.append(
        context(tenant.tenantId),
        request(tenant, `parallel-${index}`),
      ),
    ),
  );
  const exported = await store.exportChain(scope(tenant));
  assert.equal(exported.events.length, 21);
  assert.deepEqual(
    exported.events.map((event) => event.sequence),
    Array.from({ length: 21 }, (_, index) => index + 1),
  );
  assert.equal(verifyAuditExport(exported).eventCount, 21);
});

test("three Tenant chains stay isolated under the shared reader", async () => {
  for (const tenant of TENANTS.slice(1)) {
    await serviceFor(tenant).append(
      context(tenant.tenantId),
      request(tenant, "isolated"),
    );
  }
  const exports = await Promise.all(
    TENANTS.map((tenant) => store.exportChain(scope(tenant))),
  );
  assert.deepEqual(
    exports.map((document) => document.events.length),
    [21, 1, 1],
  );
  for (const [index, document] of exports.entries()) {
    assert.ok(
      document.events.every(
        (event) => event.tenantId === TENANTS[index].tenantId,
      ),
    );
  }
});

test("business reader cannot UPDATE or DELETE immutable audit history", async () => {
  await assert.rejects(
    readerPool.query(
      `UPDATE aios_audit.audit_event
          SET payload_sha256=$1`,
      [HASH],
    ),
    (error) => error.code === "42501",
  );
  await assert.rejects(
    readerPool.query("DELETE FROM aios_audit.audit_event"),
    (error) => error.code === "42501",
  );
  await assert.rejects(
    writerPool.query("DELETE FROM aios_audit.audit_event"),
    (error) => error.code === "42501",
  );
  await assert.rejects(
    outboxPool.query("SELECT * FROM aios_audit.audit_event"),
    (error) => error.code === "42501",
  );
  await assert.rejects(
    writerPool.query(
      "UPDATE aios_audit.audit_outbox SET status='FAILED'",
    ),
    (error) => error.code === "42501",
  );
});

test("database check rejects prohibited body even for migration owner path", async () => {
  const tenant = TENANTS[1];
  const client = await adminPool.connect();
  try {
    await client.query("BEGIN");
    await assert.rejects(
      client.query(
        `INSERT INTO aios_audit.audit_event (
           tenant_id,tenant_kind,event_id,sequence,previous_event_hash,
           event_hash,payload_sha256,payload,created_at
         ) VALUES (
           $1,'SYNTHETIC',
           'aev_018f0000-0000-7000-8000-000000009999',
           99,$2,$3,$4,$5::jsonb,$6::timestamptz
         )`,
        [
          tenant.tenantId,
          HASH,
          HASH,
          HASH,
          JSON.stringify({
            schemaVersion: "c18-audit-event.v1",
            tenantId: tenant.tenantId,
            tenantKind: "SYNTHETIC",
            retentionClass: "AUDIT_7Y",
            prompt: "forbidden plaintext",
          }),
          instant(),
        ],
      ),
      (error) => error.constraint === "audit_event_metadata_only",
    );
  } finally {
    await client.query("ROLLBACK");
    client.release();
  }
});

test("Outbox crash and ACK loss retry the same event ID under Worker role", async () => {
  const tenant = TENANTS[2];
  const service = serviceFor(tenant);
  const appended = await service.append(
    context(tenant.tenantId),
    request(tenant, "delivery"),
  );
  const base = Date.now();
  const crashed = await store.claimOutbox(
    scope(tenant, "delivery-worker"),
    {
      workerId: "crashed-worker",
      now: new Date(base).toISOString(),
      leaseExpiresAt: new Date(base + 10).toISOString(),
      limit: 100,
    },
  );
  assert.equal(crashed.length, 2);
  const accepted = new Set();
  let ackLost = true;
  const worker = createC18AuditOutboxWorker({
    store,
    publisher: {
      async publish({ eventId }) {
        accepted.add(eventId);
        if (ackLost) {
          ackLost = false;
          throw new Error("ACK lost");
        }
        return { eventId };
      },
    },
  });
  const first = await worker.runOnce(
    scope(tenant, "delivery-worker"),
    {
      workerId: "audit-worker",
      now: new Date(base + 20).toISOString(),
      leaseExpiresAt: new Date(base + 30_000).toISOString(),
      retryAt: new Date(base + 1000).toISOString(),
      limit: 100,
    },
  );
  assert.equal(first.requeued, 1);
  assert.equal(first.published, 1);
  const second = await worker.runOnce(
    scope(tenant, "delivery-worker"),
    {
      workerId: "audit-worker",
      now: new Date(base + 2000).toISOString(),
      leaseExpiresAt: new Date(base + 60_000).toISOString(),
      retryAt: new Date(base + 3000).toISOString(),
      limit: 100,
    },
  );
  assert.equal(second.published, 1);
  assert.ok(accepted.has(appended.eventId));
});

test("bounded retention query and export recovery preserve the full chain", async () => {
  const tenant = TENANTS[0];
  const records = await store.query(scope(tenant, "retention-query"), {
    fromSequence: 2,
    toSequence: 4,
    fromOccurredAt: "2020-01-01T00:00:00.000Z",
    toOccurredAt: "2030-01-01T00:00:00.000Z",
    limit: 2,
  });
  assert.deepEqual(
    records.map((event) => event.sequence),
    [2, 3],
  );
  assert.ok(
    records.every(
      (event) => event.payload.retentionClass === "AUDIT_7Y",
    ),
  );
  const exported = await store.exportChain(scope(tenant, "export"));
  const restored = createMemoryAuditEvidenceStore({
    restoredExports: [exported],
  });
  const restoredExport = await restored.exportChain(
    scope(tenant, "export"),
  );
  assert.deepEqual(
    verifyAuditExport(restoredExport),
    verifyAuditExport(exported),
  );
  const tampered = structuredClone(exported);
  tampered.events.at(-1).eventHash = HASH;
  assert.throws(
    () => verifyAuditExport(tampered),
    (error) =>
      error instanceof AuditEvidenceError &&
      error.code === "AUDIT_CHAIN_TAMPERED",
  );
});
