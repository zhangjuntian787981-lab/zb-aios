import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test, { after, before } from "node:test";
import pg from "pg";
import {
  createAuditEvidenceService,
  createSyntheticAuditEvidenceCatalog,
  createSyntheticAuditEvidenceRegistry,
  verifyAuditExport,
} from "../../lib/c18-audit-evidence.mjs";
import {
  createPostgresAuditEvidenceStore,
} from "../../lib/c18-audit-evidence-postgres-store.mjs";

const { Pool } = pg;
const TENANT = {
  tenantId: "stn_018f0000-0000-7000-8000-000000000010",
  bundleRef:
    "fixture://c18/northstar/bundles/completed-analysis-v1",
};
const RETENTION_TENANT = {
  tenantId: "stn_01984910-3000-7000-8000-000000000002",
  bundleRef:
    "fixture://c18/blue-harbor/bundles/completed-analysis-v1",
};
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
const RETENTION_EVENT_IDS = [
  "aev_018f0000-0000-7000-8000-000000009996",
  "aev_018f0000-0000-7000-8000-000000009997",
  "aev_018f0000-0000-7000-8000-000000009995",
  "aev_018f0000-0000-7000-8000-000000009999",
];
const COLUMN_PRIVILEGES = new Set([
  "SELECT",
  "INSERT",
  "UPDATE",
  "REFERENCES",
]);
const schemaCapability = (objectName) => ({
  kind: "schema",
  objectName,
  privilege: "USAGE",
});
const tableCapabilities = (objectName, privileges) =>
  privileges.flatMap((privilege) => [
    { kind: "table", objectName, privilege },
    ...(COLUMN_PRIVILEGES.has(privilege)
      ? [{ kind: "column", objectName, privilege }]
      : []),
  ]);
const functionCapability = (objectName) => ({
  kind: "function",
  objectName,
  privilege: "EXECUTE",
});
const scopedCapabilities = [
  schemaCapability("aios_data"),
  functionCapability(
    "aios_data.runtime_scope_allows(text,text)",
  ),
  functionCapability("aios_data.acquire_runtime_fence()"),
];
const auditValidationCapabilities = [
  functionCapability(
    "aios_audit.jsonb_has_exact_keys(jsonb,text[])",
  ),
  functionCapability(
    "aios_audit.metadata_string_matches(jsonb,text,integer)",
  ),
  functionCapability(
    "aios_audit.metadata_positive_integer(jsonb)",
  ),
  functionCapability("aios_audit.metadata_shape(jsonb,text)"),
  functionCapability("aios_audit.metadata_only(jsonb)"),
];
const C18_TABLES = [
  "audit_head",
  "audit_event",
  "audit_delivery_intent",
  "audit_outbox",
  "audit_command_receipt",
];
const expectedCapabilities = {
  aios_c18_writer: [
    schemaCapability("aios_audit"),
    ...scopedCapabilities,
    ...tableCapabilities(
      "aios_audit.audit_head",
      ["SELECT", "INSERT", "UPDATE"],
    ),
    ...["audit_event", "audit_command_receipt"].flatMap((name) =>
      tableCapabilities(
        `aios_audit.${name}`,
        ["SELECT", "INSERT"],
      ),
    ),
    ...["audit_delivery_intent", "audit_outbox"].flatMap((name) =>
      tableCapabilities(`aios_audit.${name}`, ["INSERT"]),
    ),
    ...auditValidationCapabilities,
  ],
  aios_c18_reader: [
    schemaCapability("aios_audit"),
    ...scopedCapabilities,
    ...["audit_head", "audit_event"].flatMap((name) =>
      tableCapabilities(`aios_audit.${name}`, ["SELECT"]),
    ),
  ],
  aios_c18_outbox_worker: [
    schemaCapability("aios_audit"),
    ...scopedCapabilities,
    ...tableCapabilities(
      "aios_audit.audit_delivery_intent",
      ["SELECT"],
    ),
    ...tableCapabilities(
      "aios_audit.audit_outbox",
      ["SELECT", "UPDATE"],
    ),
  ],
  aios_c18_recovery_reader: [
    schemaCapability("aios_audit"),
    ...scopedCapabilities,
    ...C18_TABLES.flatMap((name) =>
      tableCapabilities(`aios_audit.${name}`, ["SELECT"]),
    ),
  ],
  aios_c18_recovery_writer: [
    schemaCapability("aios_audit"),
    ...scopedCapabilities,
    ...C18_TABLES.flatMap((name) =>
      tableCapabilities(`aios_audit.${name}`, ["INSERT"]),
    ),
    ...auditValidationCapabilities,
    functionCapability(
      "aios_audit.restore_target_is_empty(text)",
    ),
  ],
  aios_c18_retention_worker: [
    schemaCapability("aios_audit"),
    ...scopedCapabilities,
    ...tableCapabilities(
      "aios_audit.audit_delivery_intent",
      ["SELECT"],
    ),
    ...tableCapabilities(
      "aios_audit.audit_outbox",
      ["SELECT", "DELETE"],
    ),
  ],
  aios_c07_scope_runtime: [
    schemaCapability("aios_data"),
    functionCapability(
      "aios_data.issue_runtime_scope_signature(text,text,bigint,text,text,text,text,integer,xid8,integer,uuid)",
    ),
  ],
};
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

function configuration(user = process.env.C18_TEST_PGUSER) {
  if (
    process.env.C18_TEST_EPHEMERAL !== "1" ||
    process.env.C18_TEST_RESTORED !== "1"
  ) {
    throw new Error("Restored ephemeral C18 PostgreSQL is required.");
  }
  for (const name of [
    "C18_TEST_SOURCE_SYSTEM_IDENTIFIER",
    "C18_TEST_EXPECTED_EVENT_COUNT",
    "C18_TEST_EXPECTED_HEAD_HASH",
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
    max: 1,
  };
}

async function assertExactCapabilities(admin, role, expected) {
  const result = await admin.query(
    `WITH protected_schemas AS (
       SELECT oid,nspname
         FROM pg_namespace
        WHERE nspname ~ '^aios_'
     ),
     expected_input AS (
       SELECT *
         FROM jsonb_to_recordset($1::jsonb)
           AS entry(kind text, "objectName" text, privilege text)
     ),
     expected AS (
       SELECT kind,
              CASE kind
                WHEN 'schema' THEN (
                  SELECT oid::text
                    FROM pg_namespace
                   WHERE nspname="objectName"
                )
                WHEN 'table' THEN to_regclass("objectName")::oid::text
                WHEN 'column' THEN to_regclass("objectName")::oid::text
                WHEN 'sequence' THEN to_regclass("objectName")::oid::text
                WHEN 'function' THEN
                  to_regprocedure("objectName")::oid::text
              END AS object_oid,
              privilege
         FROM expected_input
     ),
     schema_privileges(privilege) AS (
       VALUES ('USAGE'),('CREATE')
     ),
     relation_privileges(privilege) AS (
       VALUES
         ('SELECT'),('INSERT'),('UPDATE'),('DELETE'),
         ('TRUNCATE'),('REFERENCES'),('TRIGGER')
     ),
     column_privileges(privilege) AS (
       VALUES ('SELECT'),('INSERT'),('UPDATE'),('REFERENCES')
     ),
     sequence_privileges(privilege) AS (
       VALUES ('SELECT'),('UPDATE'),('USAGE')
     ),
     actual AS (
       SELECT 'schema'::text AS kind,
              schema.oid::text AS object_oid,privilege
         FROM protected_schemas AS schema
         CROSS JOIN schema_privileges
        WHERE has_schema_privilege($2::name,schema.oid,privilege)
       UNION ALL
       SELECT 'table',relation.oid::text,privilege
         FROM protected_schemas AS schema
         JOIN pg_class AS relation
           ON relation.relnamespace=schema.oid
          AND relation.relkind IN ('r','p','v','m','f')
         CROSS JOIN relation_privileges
        WHERE has_table_privilege($2::name,relation.oid,privilege)
       UNION ALL
       SELECT 'column',relation.oid::text,privilege
         FROM protected_schemas AS schema
         JOIN pg_class AS relation
           ON relation.relnamespace=schema.oid
          AND relation.relkind IN ('r','p','v','m','f')
         CROSS JOIN column_privileges
        WHERE has_any_column_privilege(
          $2::name,
          relation.oid,
          privilege
        )
       UNION ALL
       SELECT 'sequence',relation.oid::text,privilege
         FROM protected_schemas AS schema
         JOIN pg_class AS relation
           ON relation.relnamespace=schema.oid
          AND relation.relkind='S'
         CROSS JOIN sequence_privileges
        WHERE has_sequence_privilege($2::name,relation.oid,privilege)
       UNION ALL
       SELECT 'function',routine.oid::text,'EXECUTE'
         FROM protected_schemas AS schema
         JOIN pg_proc AS routine ON routine.pronamespace=schema.oid
        WHERE has_function_privilege($2::name,routine.oid,'EXECUTE')
     ),
     mismatch AS (
       (
         SELECT kind,object_oid,privilege FROM actual
         EXCEPT
         SELECT kind,object_oid,privilege FROM expected
       )
       UNION ALL
       (
         SELECT kind,object_oid,privilege FROM expected
         EXCEPT
         SELECT kind,object_oid,privilege FROM actual
       )
     )
     SELECT
       NOT EXISTS (SELECT 1 FROM mismatch)
       AND NOT EXISTS (
         SELECT 1 FROM expected WHERE object_oid IS NULL
       ) AS privileges_safe`,
    [JSON.stringify(expected), role],
  );
  assert.equal(result.rows[0]?.privileges_safe, true, role);
}

function deterministicIds(start = 9000) {
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

function scope(tenant, correlationId) {
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

function request(suffix) {
  return {
    sessionToken: "synthetic-session",
    delegationId: DELEGATION,
    idempotencyKey: `c18-restored-${suffix}`,
    correlationId: `c18-restored-${suffix}`,
    evidenceBundleRef: TENANT.bundleRef,
  };
}

function serviceFor(selectedStore, createdAt) {
  return createAuditEvidenceService({
    catalog,
    store: selectedStore,
    idFactory: deterministicIds(),
    clock: () => createdAt,
    stablePrincipalRegistry: {
      async resolveActionIdentity() {
        return identity(TENANT.tenantId);
      },
    },
    tenantRegistry: {
      async admitNewRequest() {
        return {
          tenantId: TENANT.tenantId,
          tenantKind: "SYNTHETIC",
          lifecycleVersion: 2,
        };
      },
    },
    tenantScopeFactory({ authorization, correlationId }) {
      return {
        ...scope(TENANT, correlationId),
        decisionId: authorization.decisionId,
        evidenceRef: authorization.evidenceRef,
        policyVersion: authorization.version,
      };
    },
  });
}

async function assertScopeCleared(pool) {
  const result = await pool.query(
    `SELECT current_setting('aios.tenant_id', true) AS tenant_id,
            current_setting('aios.tenant_kind', true) AS tenant_kind,
            current_setting('aios.lifecycle_version', true)
              AS lifecycle_version,
            current_setting('aios.correlation_id', true)
              AS correlation_id,
            current_setting('aios.decision_id', true) AS decision_id,
            current_setting('aios.evidence_ref', true) AS evidence_ref,
            current_setting('aios.policy_version', true)
              AS policy_version,
            current_setting('aios.backend_pid', true) AS backend_pid,
            current_setting('aios.transaction_id', true) AS transaction_id,
            current_setting('aios.expires_epoch_ms', true)
              AS expires_epoch_ms,
            current_setting('aios.scope_nonce', true) AS scope_nonce,
            current_setting('aios.scope_signature', true)
              AS scope_signature`,
  );
  assert.ok(
    Object.values(result.rows[0]).every(
      (value) => value === null || value === "",
    ),
  );
}

let adminPool;
let writerPool;
let readerPool;
let outboxPool;
let recoveryPool;
let restorePool;
let retentionPool;
let scopePool;
let store;

before(async () => {
  adminPool = new Pool(configuration());
  const system = await adminPool.query(
    "SELECT system_identifier::text FROM pg_control_system()",
  );
  assert.notEqual(
    system.rows[0].system_identifier,
    process.env.C18_TEST_SOURCE_SYSTEM_IDENTIFIER,
  );
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
  ]);
});

test("fresh-cluster restore preserves owner, ACL, RLS and runtime roles", async () => {
  const schema = await adminPool.query(
    `SELECT pg_get_userbyid(nspowner) AS owner,
            EXISTS (
              SELECT 1
                FROM aclexplode(
                  COALESCE(nspacl,acldefault('n',nspowner))
                )
               WHERE grantee=0
            ) AS public_acl
       FROM pg_namespace
      WHERE nspname='aios_audit'`,
  );
  assert.deepEqual(schema.rows[0], {
    owner: "aios_c18_owner",
    public_acl: false,
  });
  const tables = await adminPool.query(
    `SELECT relname,pg_get_userbyid(relowner) AS owner,
            relrowsecurity,relforcerowsecurity,
            EXISTS (
              SELECT 1
                FROM aclexplode(
                  COALESCE(relacl,acldefault('r',relowner))
                )
               WHERE grantee=0
            ) AS public_acl
       FROM pg_class
      WHERE relnamespace='aios_audit'::regnamespace
        AND relkind='r'
      ORDER BY relname`,
  );
  assert.deepEqual(
    tables.rows.map(({ relname }) => relname),
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
      (row) =>
        row.owner === "aios_c18_owner" &&
        row.relrowsecurity &&
        row.relforcerowsecurity &&
        !row.public_acl,
    ),
  );
  const functions = await adminPool.query(
    `SELECT proname,pg_get_userbyid(proowner) AS owner,
            EXISTS (
              SELECT 1
                FROM aclexplode(
                  COALESCE(proacl,acldefault('f',proowner))
                )
               WHERE grantee=0
            ) AS public_acl
       FROM pg_proc
      WHERE pronamespace='aios_audit'::regnamespace
      ORDER BY proname`,
  );
  assert.ok(
    functions.rows.every(
      (row) =>
        row.owner === "aios_c18_owner" &&
        !row.public_acl,
    ),
  );
  const roles = await adminPool.query(
    `SELECT rolname,rolcanlogin,rolsuper,rolbypassrls,
            rolcreatedb,rolcreaterole,rolreplication
      FROM pg_roles
      WHERE rolname IN (
        'aios_c07_owner',
        'aios_c07_lifecycle_runtime',
        'aios_c07_data_runtime',
        'aios_c07_scope_runtime',
        'aios_c07_restore_runtime',
        'aios_c18_owner',
        'aios_c18_writer',
        'aios_c18_reader',
        'aios_c18_outbox_worker',
        'aios_c18_recovery_reader',
        'aios_c18_recovery_writer',
        'aios_c18_retention_worker'
      )
      ORDER BY rolname`,
  );
  assert.equal(roles.rowCount, 12);
  assert.ok(
    roles.rows.every(
      (row) =>
        !row.rolcanlogin &&
        !row.rolsuper &&
        !row.rolbypassrls &&
        !row.rolcreatedb &&
        !row.rolcreaterole &&
        !row.rolreplication,
    ),
  );
  for (const [role, expected] of Object.entries(
    expectedCapabilities,
  )) {
    await assertExactCapabilities(adminPool, role, expected);
  }
  const privileges = await adminPool.query(
    `SELECT
       has_table_privilege(
         'aios_c18_reader','aios_audit.audit_event','SELECT'
       ) AS reader_select,
       has_table_privilege(
         'aios_c18_reader','aios_audit.audit_event','UPDATE'
       ) AS reader_update,
       has_table_privilege(
         'aios_c18_writer','aios_audit.audit_event','DELETE'
       ) AS writer_delete,
       has_table_privilege(
         'aios_c18_writer','aios_audit.audit_outbox','SELECT'
       ) AS writer_outbox_select,
       has_table_privilege(
         'aios_c18_outbox_worker','aios_audit.audit_outbox','UPDATE'
       ) AS worker_outbox_update,
       has_table_privilege(
         'aios_c18_outbox_worker','aios_audit.audit_event','SELECT'
       ) AS worker_event_select,
       has_table_privilege(
         'aios_c18_recovery_reader',
         'aios_audit.audit_command_receipt','SELECT'
       ) AS recovery_receipt_select,
       has_table_privilege(
         'aios_c18_recovery_writer','aios_audit.audit_event','INSERT'
       ) AS restore_event_insert,
       has_table_privilege(
         'aios_c18_recovery_writer','aios_audit.audit_event','SELECT'
       ) AS restore_event_select,
       has_table_privilege(
         'aios_c18_retention_worker','aios_audit.audit_outbox','DELETE'
       ) AS retention_outbox_delete,
       has_table_privilege(
         'aios_c18_retention_worker','aios_audit.audit_event','DELETE'
       ) AS retention_event_delete`,
  );
  assert.deepEqual(privileges.rows[0], {
    reader_select: true,
    reader_update: false,
    writer_delete: false,
    writer_outbox_select: false,
    worker_outbox_update: true,
    worker_event_select: false,
    recovery_receipt_select: true,
    restore_event_insert: true,
    restore_event_select: false,
    retention_outbox_delete: true,
    retention_event_delete: false,
  });
});

test("fresh-cluster restore verifies and continues the audit chain", async () => {
  const tenantScope = scope(TENANT, "c18-restored-export");
  const restored = await store.exportChain(tenantScope);
  const expectedEventCount = Number(
    process.env.C18_TEST_EXPECTED_EVENT_COUNT,
  );
  assert.equal(Number.isSafeInteger(expectedEventCount), true);
  assert.deepEqual(verifyAuditExport(restored), {
    tenantId: TENANT.tenantId,
    eventCount: expectedEventCount,
    deliveryIntentCount: expectedEventCount,
    receiptCount: expectedEventCount,
    recoverableOutboxCount: expectedEventCount,
    headEventHash: process.env.C18_TEST_EXPECTED_HEAD_HASH,
  });
  assert.equal(
    restored.head.lastEventHash,
    process.env.C18_TEST_EXPECTED_HEAD_HASH,
  );

  const createdAt = new Date(
    Date.parse(restored.head.updatedAt) + 1,
  ).toISOString();
  const appended = await serviceFor(store, createdAt).append(
    context(TENANT.tenantId),
    request("continuation"),
  );
  assert.equal(appended.sequence, expectedEventCount + 1);
  assert.equal(
    appended.previousEventHash,
    process.env.C18_TEST_EXPECTED_HEAD_HASH,
  );
  const continued = await store.exportChain(
    scope(TENANT, "c18-restored-continuation"),
  );
  const verification = verifyAuditExport(continued);
  assert.equal(verification.eventCount, expectedEventCount + 1);
  assert.equal(continued.head.lastSequence, expectedEventCount + 1);
  assert.equal(continued.head.lastEventId, appended.eventId);
  assert.equal(continued.head.lastEventHash, appended.eventHash);

  await assert.rejects(
    readerPool.query(
      "UPDATE aios_audit.audit_event SET payload_sha256=$1",
      [process.env.C18_TEST_EXPECTED_HEAD_HASH],
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
  await assertScopeCleared(writerPool);
  await assertScopeCleared(readerPool);
  await assertScopeCleared(recoveryPool);
  await assertScopeCleared(scopePool);
});

test("fresh-cluster restore preserves lease, retention and scope cleanup", async () => {
  const deliveryScope = scope(TENANT, "c18-restored-delivery");
  const [claimed] = await store.claimOutbox(deliveryScope, {
    workerId: "restored-worker",
    leaseDurationSeconds: 30,
    limit: 1,
  });
  assert.ok(claimed);
  const failed = await store.failOutbox(deliveryScope, {
    eventId: claimed.eventId,
    workerId: "restored-worker",
    leaseVersion: claimed.leaseVersion,
    retryDelaySeconds: 1,
    errorCode: "RESTORED_LEASE_TEST",
  });
  assert.equal(failed.status, "FAILED");
  const afterLease = await store.exportChain(
    scope(TENANT, "c18-restored-after-lease"),
  );
  assert.equal(
    afterLease.outbox.find(
      ({ eventId }) => eventId === claimed.eventId,
    ).status,
    "FAILED",
  );
  verifyAuditExport(afterLease);

  const retentionScope = scope(
    RETENTION_TENANT,
    "c18-restored-retention",
  );
  assert.deepEqual(
    await store.purgePublishedOutbox(retentionScope, { limit: 10 }),
    [RETENTION_EVENT_IDS[3]],
  );
  assert.deepEqual(
    await store.purgePublishedOutbox(retentionScope, { limit: 10 }),
    [],
  );
  const retained = await adminPool.query(
    `SELECT
       (SELECT count(*)::int
          FROM aios_audit.audit_delivery_intent
         WHERE event_id=ANY($1::text[])) AS intents,
       (SELECT array_agg(event_id ORDER BY event_id)
          FROM aios_audit.audit_outbox
         WHERE event_id=ANY($1::text[])) AS outbox`,
    [RETENTION_EVENT_IDS],
  );
  assert.deepEqual(retained.rows[0], {
    intents: 4,
    outbox: [RETENTION_EVENT_IDS[1], RETENTION_EVENT_IDS[2]].sort(),
  });
  await assertScopeCleared(outboxPool);
  await assertScopeCleared(recoveryPool);
  await assertScopeCleared(retentionPool);
  await assertScopeCleared(scopePool);
});
