import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test, { after, before } from "node:test";
import pg from "pg";
import {
  AuditEvidenceError,
  createAuditEvidenceService,
  createMemoryAuditEvidenceStore,
  createSyntheticAuditEvidenceCatalog,
  createSyntheticAuditEvidenceRegistry,
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
const evidenceRegistry = createSyntheticAuditEvidenceRegistry(
  JSON.parse(
    await readFile(
      new URL(
        "../../implementation/p1/c18/synthetic-evidence-registry.v1.json",
        import.meta.url,
      ),
      "utf8",
    ),
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
  { evidenceRegistry },
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
const RECOVERY_LOGIN = "c18_test_recovery_login";
const RESTORE_LOGIN = "c18_test_restore_login";
const RETENTION_LOGIN = "c18_test_retention_login";
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

function configuration(
  user = process.env.C18_TEST_PGUSER,
  max = 40,
  database = process.env.C18_TEST_PGDATABASE,
) {
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
    database,
    user,
    max,
  };
}

function restoreConfiguration(
  user = process.env.C18_RESTORE_TEST_PGUSER,
  max = 40,
) {
  for (const name of [
    "C18_RESTORE_TEST_PGHOST",
    "C18_RESTORE_TEST_PGPORT",
    "C18_RESTORE_TEST_PGDATABASE",
    "C18_RESTORE_TEST_PGUSER",
  ]) {
    if (!process.env[name]) throw new Error(`${name} is required.`);
  }
  return {
    host: process.env.C18_RESTORE_TEST_PGHOST,
    port: Number(process.env.C18_RESTORE_TEST_PGPORT),
    database: process.env.C18_RESTORE_TEST_PGDATABASE,
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
    sessionId: "session-synthetic",
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
        expiresAt: "2027-07-26T00:00:00.000Z",
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

async function prepareDatabase(selectedAdminPool) {
  for (const migration of migrations) {
    await selectedAdminPool.query(migration);
  }
  await selectedAdminPool.query(
    `CREATE ROLE ${WRITER_LOGIN}
       LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE INHERIT NOREPLICATION
       NOBYPASSRLS;
     CREATE ROLE ${READER_LOGIN}
       LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE INHERIT NOREPLICATION
       NOBYPASSRLS;
     CREATE ROLE ${WORKER_LOGIN}
       LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE INHERIT NOREPLICATION
       NOBYPASSRLS;
     CREATE ROLE ${RECOVERY_LOGIN}
       LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE INHERIT NOREPLICATION
       NOBYPASSRLS;
     CREATE ROLE ${RESTORE_LOGIN}
       LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE INHERIT NOREPLICATION
       NOBYPASSRLS;
     CREATE ROLE ${RETENTION_LOGIN}
       LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE INHERIT NOREPLICATION
       NOBYPASSRLS;
     CREATE ROLE ${SCOPE_LOGIN}
       LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE INHERIT NOREPLICATION
       NOBYPASSRLS;
     GRANT aios_c18_writer TO ${WRITER_LOGIN};
     GRANT aios_c18_reader TO ${READER_LOGIN};
     GRANT aios_c18_outbox_worker TO ${WORKER_LOGIN};
     GRANT aios_c18_recovery_reader TO ${RECOVERY_LOGIN};
     GRANT aios_c18_recovery_writer TO ${RESTORE_LOGIN};
     GRANT aios_c18_retention_worker TO ${RETENTION_LOGIN};
     GRANT aios_c07_scope_runtime TO ${SCOPE_LOGIN};`,
  );
  for (const [index, tenant] of TENANTS.entries()) {
    await seedTenant(selectedAdminPool, tenant, index);
  }
}

let adminPool;
let writerPool;
let readerPool;
let outboxPool;
let recoveryPool;
let restorePool;
let retentionPool;
let scopePool;
let targetAdminPool;
let targetWriterPool;
let targetReaderPool;
let targetOutboxPool;
let targetRecoveryPool;
let targetRestorePool;
let targetRetentionPool;
let targetScopePool;
let targetStore;
let store;
let idFactory;
const clocks = new Map();

before(async () => {
  adminPool = new Pool(configuration());
  await prepareDatabase(adminPool);
  for (const [index, tenant] of TENANTS.entries()) {
    clocks.set(tenant.tenantId, instant(index * 10));
  }
  writerPool = new Pool(configuration(WRITER_LOGIN));
  readerPool = new Pool(configuration(READER_LOGIN));
  outboxPool = new Pool(configuration(WORKER_LOGIN));
  recoveryPool = new Pool(configuration(RECOVERY_LOGIN));
  restorePool = new Pool(configuration(RESTORE_LOGIN));
  retentionPool = new Pool(configuration(RETENTION_LOGIN));
  scopePool = new Pool(configuration(SCOPE_LOGIN));
  store = createPostgresAuditEvidenceStore({
    writerPool,
    readerPool,
    outboxPool,
    recoveryPool,
    restorePool,
    retentionPool,
    scopePool,
  });
  targetAdminPool = new Pool(restoreConfiguration());
  await prepareDatabase(targetAdminPool);
  targetWriterPool = new Pool(restoreConfiguration(WRITER_LOGIN));
  targetReaderPool = new Pool(restoreConfiguration(READER_LOGIN));
  targetOutboxPool = new Pool(restoreConfiguration(WORKER_LOGIN));
  targetRecoveryPool = new Pool(
    restoreConfiguration(RECOVERY_LOGIN),
  );
  targetRestorePool = new Pool(restoreConfiguration(RESTORE_LOGIN));
  targetRetentionPool = new Pool(
    restoreConfiguration(RETENTION_LOGIN),
  );
  targetScopePool = new Pool(restoreConfiguration(SCOPE_LOGIN));
  targetStore = createPostgresAuditEvidenceStore({
    writerPool: targetWriterPool,
    readerPool: targetReaderPool,
    outboxPool: targetOutboxPool,
    recoveryPool: targetRecoveryPool,
    restorePool: targetRestorePool,
    retentionPool: targetRetentionPool,
    scopePool: targetScopePool,
  });
  idFactory = deterministicIds();
});

after(async () => {
  await Promise.allSettled([
    writerPool?.end(),
    readerPool?.end(),
    outboxPool?.end(),
    recoveryPool?.end(),
    restorePool?.end(),
    retentionPool?.end(),
    scopePool?.end(),
    adminPool?.end(),
    targetWriterPool?.end(),
    targetReaderPool?.end(),
    targetOutboxPool?.end(),
    targetRecoveryPool?.end(),
    targetRestorePool?.end(),
    targetRetentionPool?.end(),
    targetScopePool?.end(),
    targetAdminPool?.end(),
  ]);
});

function serviceFor(tenant, selectedStore = store) {
  return createAuditEvidenceService({
    catalog,
    store: selectedStore,
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
  assert.deepEqual(
    tables.rows.map((row) => row.relname),
    [
      "audit_command_receipt",
      "audit_delivery_intent",
      "audit_event",
      "audit_head",
      "audit_outbox",
    ],
  );
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
        'aios_c18_outbox_worker',
        'aios_c18_recovery_reader',
        'aios_c18_recovery_writer',
        'aios_c18_retention_worker'
      )
      ORDER BY rolname`,
  );
  assert.equal(roles.rows.length, 6);
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
         'aios_c18_writer',
         'aios_audit.audit_outbox',
         'SELECT'
       ) AS writer_outbox_select,
       has_table_privilege(
         'aios_c18_outbox_worker',
         'aios_audit.audit_outbox',
         'UPDATE'
       ) AS worker_outbox_update,
       has_table_privilege(
         'aios_c18_outbox_worker',
         'aios_audit.audit_event',
         'SELECT'
       ) AS worker_event_select,
       has_table_privilege(
         'aios_c18_recovery_reader',
         'aios_audit.audit_command_receipt',
         'SELECT'
       ) AS recovery_receipt_select,
       has_table_privilege(
         'aios_c18_recovery_reader',
         'aios_audit.audit_head',
         'SELECT'
       ) AS recovery_head_select,
       has_table_privilege(
         'aios_c18_recovery_writer',
         'aios_audit.audit_event',
         'INSERT'
       ) AS restore_event_insert,
       has_table_privilege(
         'aios_c18_recovery_writer',
         'aios_audit.audit_event',
         'SELECT'
       ) AS restore_event_select,
       has_table_privilege(
         'aios_c18_recovery_writer',
         'aios_audit.audit_event',
         'UPDATE'
       ) AS restore_event_update,
       has_table_privilege(
         'aios_c18_recovery_writer',
         'aios_audit.audit_event',
         'DELETE'
       ) AS restore_event_delete,
       has_table_privilege(
         'aios_c18_retention_worker',
         'aios_audit.audit_outbox',
         'DELETE'
       ) AS retention_outbox_delete,
       has_table_privilege(
         'aios_c18_retention_worker',
         'aios_audit.audit_event',
         'DELETE'
       ) AS retention_event_delete,
       has_table_privilege(
         'aios_c18_retention_worker',
         'aios_audit.audit_delivery_intent',
         'DELETE'
       ) AS retention_intent_delete,
       has_table_privilege(
         'aios_c18_retention_worker',
         'aios_audit.audit_command_receipt',
         'DELETE'
       ) AS retention_receipt_delete`,
  );
  assert.deepEqual(privileges.rows[0], {
    reader_select: true,
    reader_update: false,
    writer_delete: false,
    writer_outbox_select: false,
    worker_outbox_update: true,
    worker_event_select: false,
    recovery_receipt_select: true,
    recovery_head_select: true,
    restore_event_insert: true,
    restore_event_select: false,
    restore_event_update: false,
    restore_event_delete: false,
    retention_outbox_delete: true,
    retention_event_delete: false,
    retention_intent_delete: false,
    retention_receipt_delete: false,
  });
  const unscopedRestoreProbe = await restorePool.query(
    "SELECT aios_audit.restore_target_is_empty($1) AS is_empty",
    [TENANTS[0].tenantId],
  );
  assert.equal(unscopedRestoreProbe.rows[0].is_empty, false);
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
       (SELECT count(*)::int FROM aios_audit.audit_delivery_intent
         WHERE tenant_id=$1) AS intents,
       (SELECT count(*)::int FROM aios_audit.audit_command_receipt
         WHERE tenant_id=$1) AS receipts`,
    [tenant.tenantId],
  );
  assert.deepEqual(counts.rows[0], {
    events: 1,
    outbox: 1,
    intents: 1,
    receipts: 1,
  });
  const duplicate = await service.append(
    context(tenant.tenantId),
    request(tenant, "atomic"),
  );
  assert.equal(duplicate.eventId, result.eventId);
  assert.equal(duplicate.duplicate, true);
});

test("Event requires both immutable DeliveryIntent and CommandReceipt at commit", async () => {
  const constraints = await adminPool.query(
    `SELECT conname,condeferrable,condeferred
       FROM pg_constraint
      WHERE conname IN (
        'audit_event_delivery_intent_pair',
        'audit_event_receipt_pair'
      )
      ORDER BY conname`,
  );
  assert.deepEqual(constraints.rows, [
    {
      conname: "audit_event_delivery_intent_pair",
      condeferrable: true,
      condeferred: true,
    },
    {
      conname: "audit_event_receipt_pair",
      condeferrable: true,
      condeferred: true,
    },
  ]);

  const tenant = TENANTS[1];
  const eventId = "aev_018f0000-0000-7000-8000-000000009998";
  const createdAt = instant();
  const event = {
    specversion: "1.0",
    id: eventId,
    source: "/aios-core/audit-evidence",
    type: "product.aios.audit-evidence-recorded.v1",
    time: createdAt,
    datacontenttype: "application/json",
    subject: tenant.tenantId,
    dataschema: "synthetic://c18/schemas/audit-event.v1",
    tenantkind: "SYNTHETIC",
    correlationid: "missing-receipt",
    synthetic: true,
    data: {},
  };
  const client = await adminPool.connect();
  try {
    await client.query("BEGIN");
    await client.query(
      `INSERT INTO aios_audit.audit_event (
         tenant_id,tenant_kind,event_id,sequence,previous_event_hash,
         event_hash,payload_sha256,payload,created_at
       ) VALUES ($1,'SYNTHETIC',$2,998,$3,$3,$3,$4::jsonb,$5)`,
      [
        tenant.tenantId,
        eventId,
        HASH,
        JSON.stringify({
          schemaVersion: "c18-audit-event.v1",
          tenantId: tenant.tenantId,
          tenantKind: "SYNTHETIC",
          retentionClass: "AUDIT_7Y",
        }),
        createdAt,
      ],
    );
    await client.query(
      `INSERT INTO aios_audit.audit_delivery_intent (
         tenant_id,tenant_kind,event_id,event,retention_class,
         legal_hold,created_at
       ) VALUES ($1,'SYNTHETIC',$2,$3::jsonb,'AUDIT_7Y',false,$4)`,
      [tenant.tenantId, eventId, JSON.stringify(event), createdAt],
    );
    await client.query(
      `INSERT INTO aios_audit.audit_outbox (
         tenant_id,tenant_kind,event_id,status,attempt_count,
         lease_version,leased_by,lease_until,available_at,published_at,
         last_error_code,created_at
       ) VALUES (
         $1,'SYNTHETIC',$2,'PENDING',0,0,NULL,NULL,$3,NULL,NULL,$3
       )`,
      [tenant.tenantId, eventId, createdAt],
    );
    await assert.rejects(
      client.query("COMMIT"),
      (error) => error.constraint === "audit_event_receipt_pair",
    );
  } finally {
    await client.query("ROLLBACK").catch(() => {});
    client.release();
  }
});

test("Event cannot commit without its initial C18 Outbox row", async () => {
  const tenant = TENANTS[1];
  const eventId = "aev_018f0000-0000-7000-8000-000000009994";
  const createdAt = instant();
  const event = {
    specversion: "1.0",
    id: eventId,
    source: "/aios-core/audit-evidence",
    type: "product.aios.audit-evidence-recorded.v1",
    time: createdAt,
    datacontenttype: "application/json",
    subject: tenant.tenantId,
    dataschema: "synthetic://c18/schemas/audit-event.v1",
    tenantkind: "SYNTHETIC",
    correlationid: "missing-outbox",
    synthetic: true,
    data: {},
  };
  const client = await adminPool.connect();
  try {
    await client.query("BEGIN");
    await client.query(
      `INSERT INTO aios_audit.audit_event (
         tenant_id,tenant_kind,event_id,sequence,previous_event_hash,
         event_hash,payload_sha256,payload,created_at
       ) VALUES ($1,'SYNTHETIC',$2,994,$3,$3,$3,$4::jsonb,$5)`,
      [
        tenant.tenantId,
        eventId,
        HASH,
        JSON.stringify({
          schemaVersion: "c18-audit-event.v1",
          tenantId: tenant.tenantId,
          tenantKind: "SYNTHETIC",
          retentionClass: "AUDIT_7Y",
        }),
        createdAt,
      ],
    );
    await client.query(
      `INSERT INTO aios_audit.audit_delivery_intent (
         tenant_id,tenant_kind,event_id,event,retention_class,
         legal_hold,created_at
       ) VALUES ($1,'SYNTHETIC',$2,$3::jsonb,'AUDIT_7Y',false,$4)`,
      [tenant.tenantId, eventId, JSON.stringify(event), createdAt],
    );
    await client.query(
      `INSERT INTO aios_audit.audit_command_receipt (
         tenant_id,tenant_kind,idempotency_key,request_hash,
         event_id,created_at
       ) VALUES ($1,'SYNTHETIC','missing-outbox',$3,$2,$4)`,
      [tenant.tenantId, eventId, HASH, createdAt],
    );
    await assert.rejects(
      client.query("COMMIT"),
      (error) => error.constraint === "audit_event_outbox_pair",
    );
  } finally {
    await client.query("ROLLBACK").catch(() => {});
    client.release();
  }
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

test("dedicated recovery writer restores into a fresh PostgreSQL", async () => {
  const tenant = TENANTS[0];
  const tenantScope = scope(tenant, "fresh-postgres-restore");
  const exported = await store.exportChain(tenantScope);
  const restored = await targetStore.restoreChain(
    tenantScope,
    exported,
  );
  assert.equal(restored.restored, true);
  assert.equal(restored.eventCount, exported.events.length);
  assert.equal(
    restored.deliveryIntentCount,
    exported.deliveryIntents.length,
  );
  assert.equal(restored.receiptCount, exported.receipts.length);

  const targetExport = await targetStore.exportChain(tenantScope);
  assert.deepEqual(
    verifyAuditExport(targetExport),
    verifyAuditExport(exported),
  );
  assert.deepEqual(targetExport.head, exported.head);
  assert.deepEqual(
    targetExport.deliveryIntents,
    exported.deliveryIntents,
  );
  const replayed = await serviceFor(tenant, targetStore).append(
    context(tenant.tenantId),
    request(tenant, "atomic"),
  );
  assert.equal(replayed.eventId, exported.events[0].eventId);
  assert.equal(replayed.duplicate, true);
  const continued = await serviceFor(tenant, targetStore).append(
    context(tenant.tenantId),
    request(tenant, "restored-continuation"),
  );
  assert.equal(continued.sequence, exported.events.length + 1);
  assert.equal(
    continued.previousEventHash,
    exported.head.lastEventHash,
  );

  const [claim] = await targetStore.claimOutbox(tenantScope, {
    workerId: "restored-worker",
    leaseDurationSeconds: 30,
    limit: 1,
  });
  await targetStore.failOutbox(tenantScope, {
    eventId: claim.eventId,
    workerId: "restored-worker",
    leaseVersion: claim.leaseVersion,
    retryDelaySeconds: 1,
    errorCode: "RESTORE_LEASE_TEST",
  });
  const afterLease = await targetStore.exportChain(tenantScope);
  assert.equal(
    afterLease.outbox.find(({ eventId }) => eventId === claim.eventId)
      .status,
    "FAILED",
  );
  assert.equal(
    verifyAuditExport(afterLease).eventCount,
    exported.events.length + 1,
  );
  assert.deepEqual(
    await targetStore.purgePublishedOutbox(tenantScope, { limit: 500 }),
    [],
  );

  await assert.rejects(
    targetRestorePool.query(
      "SELECT * FROM aios_audit.audit_event",
    ),
    (error) => error.code === "42501",
  );
  await assert.rejects(
    targetRestorePool.query(
      "DELETE FROM aios_audit.audit_event",
    ),
    (error) => error.code === "42501",
  );
  await assert.rejects(
    targetStore.restoreChain(tenantScope, exported),
    (error) =>
      error instanceof AuditEvidenceError &&
      error.code === "RECOVERY_TARGET_NOT_EMPTY",
  );
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
  for (const immutableTable of [
    "audit_event",
    "audit_delivery_intent",
    "audit_command_receipt",
  ]) {
    await assert.rejects(
      retentionPool.query(
        `DELETE FROM aios_audit.${immutableTable}`,
      ),
      (error) => error.code === "42501",
    );
  }
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

test("database trigger bounds lease, retry and publish times independently", async () => {
  const tenant = TENANTS[0];
  const pending = await adminPool.query(
    `SELECT event_id
       FROM aios_audit.audit_outbox
      WHERE tenant_id=$1
        AND status='PENDING'
      ORDER BY created_at,event_id
      LIMIT 1`,
    [tenant.tenantId],
  );
  const eventId = pending.rows[0].event_id;
  const client = await adminPool.connect();
  try {
    await client.query("BEGIN");
    await assert.rejects(
      client.query(
        `UPDATE aios_audit.audit_outbox
            SET status='PROCESSING',
                attempt_count=attempt_count+1,
                lease_version=lease_version+1,
                leased_by='unbounded-worker',
                lease_until=statement_timestamp() + interval '301 seconds',
                last_error_code=NULL
          WHERE tenant_id=$1
            AND event_id=$2`,
        [tenant.tenantId, eventId],
      ),
      (error) => error.constraint === "audit_outbox_transition_guard",
    );
    await client.query("ROLLBACK");

    await client.query("BEGIN");
    await client.query(
      `UPDATE aios_audit.audit_outbox
          SET status='PROCESSING',
              attempt_count=attempt_count+1,
              lease_version=lease_version+1,
              leased_by='bounded-worker',
              lease_until=statement_timestamp() + interval '30 seconds',
              last_error_code=NULL
        WHERE tenant_id=$1
          AND event_id=$2`,
      [tenant.tenantId, eventId],
    );
    await assert.rejects(
      client.query(
        `UPDATE aios_audit.audit_outbox
            SET status='FAILED',
                leased_by=NULL,
                lease_until=NULL,
                available_at=statement_timestamp()
                  + interval '3601 seconds',
                published_at=NULL,
                last_error_code='SPOOFED_RETRY'
          WHERE tenant_id=$1
            AND event_id=$2`,
        [tenant.tenantId, eventId],
      ),
      (error) => error.constraint === "audit_outbox_transition_guard",
    );
    await client.query("ROLLBACK");

    await client.query("BEGIN");
    await client.query(
      `UPDATE aios_audit.audit_outbox
          SET status='PROCESSING',
              attempt_count=attempt_count+1,
              lease_version=lease_version+1,
              leased_by='bounded-worker',
              lease_until=statement_timestamp() + interval '30 seconds',
              last_error_code=NULL
        WHERE tenant_id=$1
          AND event_id=$2`,
      [tenant.tenantId, eventId],
    );
    await assert.rejects(
      client.query(
        `UPDATE aios_audit.audit_outbox
            SET status='PUBLISHED',
                leased_by=NULL,
                lease_until=NULL,
                published_at='2020-01-01T00:00:00.000Z',
                last_error_code=NULL
          WHERE tenant_id=$1
            AND event_id=$2`,
        [tenant.tenantId, eventId],
      ),
      (error) => error.constraint === "audit_outbox_transition_guard",
    );
    await client.query("ROLLBACK");
  } finally {
    await client.query("ROLLBACK").catch(() => {});
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
  const crashed = await store.claimOutbox(
    scope(tenant, "delivery-worker"),
    {
      workerId: "crashed-worker",
      leaseDurationSeconds: 1,
      limit: 100,
    },
  );
  assert.equal(crashed.length, 2);
  await new Promise((resolve) => setTimeout(resolve, 1100));
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
      leaseDurationSeconds: 30,
      retryDelaySeconds: 1,
      limit: 100,
    },
  );
  assert.equal(first.requeued, 1);
  assert.equal(first.published, 1);
  await new Promise((resolve) => setTimeout(resolve, 1100));
  const second = await worker.runOnce(
    scope(tenant, "delivery-worker"),
    {
      workerId: "audit-worker",
      leaseDurationSeconds: 30,
      retryDelaySeconds: 1,
      limit: 100,
    },
  );
  assert.equal(second.published, 1);
  assert.ok(accepted.has(appended.eventId));
  await assert.rejects(
    store.claimOutbox(scope(tenant, "delivery-worker"), {
      workerId: "invalid-worker",
      leaseDurationSeconds: 301,
      limit: 1,
    }),
    (error) =>
      error instanceof AuditEvidenceError &&
      error.code === "INVALID_INPUT",
  );
});

test("retention role deletes only expired published state and keeps immutable intent", async () => {
  const tenant = TENANTS[1];
  const createdAt = "2020-01-01T00:00:00.000Z";
  const eventIds = [
    "aev_018f0000-0000-7000-8000-000000009996",
    "aev_018f0000-0000-7000-8000-000000009997",
    "aev_018f0000-0000-7000-8000-000000009995",
    "aev_018f0000-0000-7000-8000-000000009999",
  ];
  const client = await adminPool.connect();
  try {
    await client.query("BEGIN");
    for (const [index, eventId] of eventIds.entries()) {
      const eventHash = `sha256:${String(index + 1).repeat(64)}`;
      const rowCreatedAt = index === 2 ? instant() : createdAt;
      const event = {
        specversion: "1.0",
        id: eventId,
        source: "/aios-core/audit-evidence",
        type: "product.aios.audit-evidence-recorded.v1",
        time: rowCreatedAt,
        datacontenttype: "application/json",
        subject: tenant.tenantId,
        dataschema: "synthetic://c18/schemas/audit-event.v1",
        tenantkind: "SYNTHETIC",
        correlationid: `retention-${index}`,
        synthetic: true,
        data: {},
      };
      await client.query(
        `INSERT INTO aios_audit.audit_event (
           tenant_id,tenant_kind,event_id,sequence,previous_event_hash,
           event_hash,payload_sha256,payload,created_at
         ) VALUES ($1,'SYNTHETIC',$2,$3,$4,$5,$4,$6::jsonb,$7)`,
        [
          tenant.tenantId,
          eventId,
          996 + index,
          HASH,
          eventHash,
          JSON.stringify({
            schemaVersion: "c18-audit-event.v1",
            tenantId: tenant.tenantId,
            tenantKind: "SYNTHETIC",
            retentionClass: "AUDIT_7Y",
          }),
          rowCreatedAt,
        ],
      );
      await client.query(
        `INSERT INTO aios_audit.audit_delivery_intent (
           tenant_id,tenant_kind,event_id,event,retention_class,
           legal_hold,created_at
         ) VALUES (
           $1,'SYNTHETIC',$2,$3::jsonb,'AUDIT_7Y',$4,$5
         )`,
        [
          tenant.tenantId,
          eventId,
          JSON.stringify(event),
          index === 1,
          rowCreatedAt,
        ],
      );
      await client.query(
        `INSERT INTO aios_audit.audit_command_receipt (
           tenant_id,tenant_kind,idempotency_key,request_hash,
           event_id,created_at
         ) VALUES ($1,'SYNTHETIC',$2,$3,$4,$5)`,
        [
          tenant.tenantId,
          `retention-${index}`,
          HASH,
          eventId,
          rowCreatedAt,
        ],
      );
      await client.query(
        `INSERT INTO aios_audit.audit_outbox (
           tenant_id,tenant_kind,event_id,status,attempt_count,
           lease_version,leased_by,lease_until,available_at,
           published_at,last_error_code,created_at
         ) VALUES (
           $1,'SYNTHETIC',$2,'PUBLISHED',1,1,NULL,NULL,$3,$3,NULL,$3
         )`,
        [tenant.tenantId, eventId, rowCreatedAt],
      );
    }
    await client.query("COMMIT");
  } finally {
    client.release();
  }

  const purged = await store.purgePublishedOutbox(
    scope(tenant, "retention-worker"),
    { limit: 1 },
  );
  assert.deepEqual(purged, [eventIds[0]]);
  const rows = await adminPool.query(
    `SELECT
       (SELECT count(*)::int
          FROM aios_audit.audit_delivery_intent
         WHERE event_id=ANY($1::text[])) AS intents,
       (SELECT array_agg(event_id ORDER BY event_id)
          FROM aios_audit.audit_outbox
         WHERE event_id=ANY($1::text[])) AS outbox`,
    [eventIds],
  );
  assert.deepEqual(rows.rows[0], {
    intents: 4,
    outbox: [eventIds[1], eventIds[2], eventIds[3]].sort(),
  });
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
  assert.equal(exported.schemaVersion, "c18-audit-recovery.v1");
  assert.equal(exported.receipts.length, exported.events.length);
  assert.equal(exported.outbox.length, exported.events.length);
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
  const replayed = await serviceFor(tenant, restored).append(
    context(tenant.tenantId),
    request(tenant, "atomic"),
  );
  assert.equal(replayed.eventId, exported.events[0].eventId);
  assert.equal(replayed.duplicate, true);
  const tampered = structuredClone(exported);
  tampered.events.at(-1).eventHash = HASH;
  assert.throws(
    () => verifyAuditExport(tampered),
    (error) =>
      error instanceof AuditEvidenceError &&
      error.code === "AUDIT_CHAIN_TAMPERED",
  );
});
