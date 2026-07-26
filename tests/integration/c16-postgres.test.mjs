import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import test from "node:test";
import pg from "pg";
import {
  ToolGatewayError,
  createSyntheticToolCatalog,
  createToolGateway,
  toolGatewaySha256,
} from "../../lib/tool-gateway.mjs";
import {
  createC16EphemeralCredentialBroker,
} from "../../lib/c16-ephemeral-credential-broker.mjs";
import {
  createC16SyntheticToolAdapter,
} from "../../lib/c16-synthetic-tool-adapter.mjs";
import {
  PostgresToolGatewayStoreError,
  createPostgresToolGatewayStore,
} from "../../lib/postgres-tool-gateway-store.mjs";

const { Pool } = pg;
const migrationPaths = [
  "../../implementation/p1/c03/postgresql/0001_tenant_registry.sql",
  "../../implementation/p1/c07/postgresql/0011_tenant_data_isolation.sql",
  "../../implementation/p1/c07/postgresql/0012_tenant_data_runtime_roles.sql",
  "../../implementation/p1/c18/postgresql/0023_audit_evidence.sql",
  "../../implementation/p1/c18/postgresql/0024_audit_evidence_runtime_roles.sql",
  "../../implementation/p1/c16/postgresql/0029_tool_gateway.sql",
  "../../implementation/p1/c16/postgresql/0030_tool_gateway_runtime_roles.sql",
];
const migrations = await Promise.all(
  migrationPaths.map((file) =>
    readFile(new URL(file, import.meta.url), "utf8"),
  ),
);
const catalogDocument = JSON.parse(
  await readFile(
    new URL(
      "../../implementation/p1/c16/operation-catalog.v1.json",
      import.meta.url,
    ),
    "utf8",
  ),
);
const fixtureDocument = JSON.parse(
  await readFile(
    new URL(
      "../../implementation/p1/c16/synthetic-tool-fixtures.v1.json",
      import.meta.url,
    ),
    "utf8",
  ),
);
const TENANT_IDS = [
  "stn_018f0000-0000-7000-8000-000000000010",
  "stn_018f0000-0000-7000-8000-000000000011",
  "stn_018f0000-0000-7000-8000-000000000012",
];
const APPROVAL_REFS = ["SYN-APR-0001", "SYN-APR-0002", "SYN-APR-0003"];
const HUMAN = "prn_018f0000-0000-7000-8000-000000000001";
const ACTOR = "prn_018f0000-0000-7000-8000-000000000002";
const DELEGATION =
  "dlg_018f0000-0000-7000-8000-000000000020";
const RUNTIME_LOGIN = "c16_test_runtime_login";
const TOOL_WORKER_LOGIN = "c16_test_tool_worker_login";
const AUDIT_LOGIN = "c16_test_audit_login";
const RECOVERY_LOGIN = "c16_test_recovery_login";
const SCOPE_LOGIN = "c16_test_scope_login";
const C16_TABLES = [
  "audit_intent",
  "audit_outbox",
  "tool_call",
  "tool_confirmation",
];
const C16_ROLES = [
  "aios_c16_owner",
  "aios_c16_runtime",
  "aios_c16_worker",
  "aios_c16_audit_worker",
  "aios_c16_recovery_reader",
];
const APPLICATION_ROLES = C16_ROLES.slice(1);
const TABLE_PRIVILEGES = ["SELECT", "INSERT", "UPDATE", "DELETE"];
const EXPECTED_TABLE_PRIVILEGES = {
  aios_c16_runtime: {
    SELECT: ["tool_call", "tool_confirmation"],
    INSERT: [
      "audit_intent",
      "audit_outbox",
      "tool_call",
      "tool_confirmation",
    ],
  },
  aios_c16_worker: {
    SELECT: ["tool_call"],
    INSERT: ["audit_intent", "audit_outbox"],
    UPDATE: ["tool_call"],
  },
  aios_c16_audit_worker: {
    SELECT: ["audit_intent", "audit_outbox"],
    UPDATE: ["audit_outbox"],
  },
  aios_c16_recovery_reader: {
    SELECT: C16_TABLES,
  },
};
const PROJECTIONS = [
  "AUTHORIZATION",
  "IDENTITY",
  "KNOWLEDGE",
  "SECRET_REFS",
  "STORAGE",
];

function config(user = process.env.C16_TEST_PGUSER, max = 30) {
  if (process.env.C16_TEST_EPHEMERAL !== "1") {
    throw new Error("C16_TEST_EPHEMERAL=1 is required.");
  }
  for (const name of [
    "C16_TEST_PGHOST",
    "C16_TEST_PGPORT",
    "C16_TEST_PGDATABASE",
    "C16_TEST_PGUSER",
  ]) {
    if (!process.env[name]) throw new Error(`${name} is required.`);
  }
  return {
    host: process.env.C16_TEST_PGHOST,
    port: Number(process.env.C16_TEST_PGPORT),
    database: process.env.C16_TEST_PGDATABASE,
    user,
    max,
  };
}

function digest(value) {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

function ids(start) {
  let value = start;
  return () => {
    value += 1;
    return `018f0000-0000-7000-8000-${String(value).padStart(12, "0")}`;
  };
}

function identity(tenantId, epoch = 1) {
  return {
    tenantId,
    tenantKind: "SYNTHETIC",
    identityAccountId: "sia_synthetic",
    identityLinkId: "lnk_synthetic",
    sessionId: "ses_synthetic",
    humanSubject: {
      principalId: HUMAN,
      principalType: "HUMAN",
      lifecycleVersion: 1,
      securityEpoch: epoch,
    },
    workloadActor: {
      principalId: ACTOR,
      principalType: "AGENT",
      lifecycleVersion: 1,
      securityEpoch: 1,
    },
    purposeRef: "synthetic://c06/purpose/tool-call",
    delegationChain: [
      {
        delegationId: DELEGATION,
        delegatorPrincipalId: HUMAN,
        delegatePrincipalId: ACTOR,
        purposeRef: "synthetic://c06/purpose/tool-call",
        lifecycleVersion: 1,
        expiresAt: "2031-01-01T00:00:00.000Z",
      },
    ],
    trustSource:
      "VERIFIED_SESSION_IDENTITY_LINK_AND_WORKLOAD_CONTEXT",
    authorizationStatus: "NOT_EVALUATED",
  };
}

function serverContext(tenantId) {
  return {
    synthetic: true,
    routeTrustSource: "VERIFIED_ROUTE_DESCRIPTOR",
    tenantId,
    workloadTrustSource: "VERIFIED_WORKLOAD_CONTEXT",
    workloadActorPrincipalId: ACTOR,
  };
}

function scope(tenantId, suffix) {
  return {
    trustSource: "C07_VERIFIED_TENANT_SCOPE",
    tenantId,
    tenantKind: "SYNTHETIC",
    lifecycleVersion: 2,
    correlationId: `c16-${suffix}`,
    decisionId: `decision-${suffix}`,
    evidenceRef: `evidence://c16/${suffix}`,
    policyVersion: "c06-v1",
  };
}

async function seedTenant(adminPool, tenantId, index) {
  const createdAt = `2026-07-26T08:0${index}:00.000Z`;
  const namespaceId =
    `sns_01984910-6000-7000-8000-${String(index + 71).padStart(12, "0")}`;
  const operationId =
    `op_01984910-6000-7000-8000-${String(index + 81).padStart(12, "0")}`;
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
      tenantId,
      `c16-creation-${index}`,
      `fixture://c16/tenants/${index}`,
      digest(`c16-origin-${index}`),
      namespaceId,
      operationId,
      createdAt,
    ],
  );
  await adminPool.query(
    `INSERT INTO aios_core.tenant_projection (
       tenant_id,generation,projection,desired_action,status,
       attempt_count,source_event_id,updated_at
     )
     SELECT $1,1,projection,'PROVISION','READY',1,
            'c16-ready-' || lower(projection),$2::timestamptz
       FROM unnest($3::text[]) AS projection`,
    [tenantId, createdAt, PROJECTIONS],
  );
  await adminPool.query(
    `UPDATE aios_core.tenant_registry
        SET state='ACTIVE',lifecycle_version=2,
            updated_at='2026-07-26T09:00:00.000Z'
      WHERE tenant_id=$1`,
    [tenantId],
  );
  await adminPool.query(
    `INSERT INTO aios_data.tenant_data_lifecycle (
       tenant_id,tenant_kind,lifecycle_version,generation,
       operation_id,state,last_event_id,updated_at
     ) VALUES (
       $1,'SYNTHETIC',2,1,$2,'ACTIVE',$3,
       '2026-07-26T09:00:00.000Z'
     )`,
    [tenantId, operationId, `c16-active-${index}`],
  );
}

function createStore(pools) {
  return createPostgresToolGatewayStore({
    runtimePool: pools.runtime,
    toolWorkerPool: pools.toolWorker,
    auditWorkerPool: pools.audit,
    recoveryPool: pools.recovery,
    scopePool: pools.scope,
  });
}

function createHarness(store, tenantId, approvalRef, start) {
  const mutable = {
    now: new Date().toISOString(),
    epoch: 1,
  };
  const broker = createC16EphemeralCredentialBroker({
    idFactory: ids(start + 100),
    clock: () => mutable.now,
  });
  const adapter = createC16SyntheticToolAdapter({
    credentialBroker: broker,
    fixtureDocument,
  });
  const gateway = createToolGateway({
    tenantRegistry: {
      async admitNewRequest() {
        return {
          tenantId,
          tenantKind: "SYNTHETIC",
          lifecycleVersion: 2,
        };
      },
    },
    stablePrincipalRegistry: {
      async resolveActionIdentity() {
        return identity(tenantId, mutable.epoch);
      },
    },
    authorizer: {
      async enforce(_context, request, descriptor) {
        const current = identity(tenantId, mutable.epoch);
        return {
          trustSource: "C06_BOUND_DECISION_EVIDENCE",
          operationId: descriptor.operationId,
          decisionId: `c06-${descriptor.operationId}`,
          evidenceRef: `evidence://c16/${descriptor.operationId}`,
          policyVersion: "c06-v1",
          tenantId,
          surface: "TOOL_CALL",
          resourceId: request.resourceId,
          humanPrincipalId: HUMAN,
          humanSecurityEpoch: mutable.epoch,
          workloadActorPrincipalId: ACTOR,
          workloadActorSecurityEpoch: 1,
          leafDelegationId: DELEGATION,
          delegationChainSha256: toolGatewaySha256(
            current.delegationChain,
          ),
          purposeRef: current.purposeRef,
        };
      },
    },
    catalog: createSyntheticToolCatalog(catalogDocument),
    store,
    credentialBroker: broker,
    adapter,
    idFactory: ids(start),
    clock: () => mutable.now,
  });
  const confirmRequest = {
    sessionToken: "synthetic-session",
    delegationId: DELEGATION,
    correlationId: `confirm-${start}`,
    operationId: "synthetic.approval.status.get",
    idempotencyKey: `confirm-${start}`,
    params: { approvalRef },
  };
  return {
    gateway,
    adapter,
    context: serverContext(tenantId),
    confirmRequest,
    executeRequest(confirmation) {
      return {
        sessionToken: "synthetic-session",
        delegationId: DELEGATION,
        correlationId: `execute-${start}`,
        operationId: "synthetic.approval.status.get",
        idempotencyKey: `execute-${start}`,
        confirmationId: confirmation.confirmationId,
        confirmationSha256: confirmation.confirmationSha256,
        expectedParamSha256: confirmation.normalizedParamSha256,
      };
    },
  };
}

test("C16 PostgreSQL transactions, isolation, roles and recovery are real", async (t) => {
  const adminPool = new Pool(config());
  const pools = {
    runtime: new Pool(config(RUNTIME_LOGIN)),
    toolWorker: new Pool(config(TOOL_WORKER_LOGIN)),
    audit: new Pool(config(AUDIT_LOGIN)),
    recovery: new Pool(config(RECOVERY_LOGIN)),
    scope: new Pool(config(SCOPE_LOGIN)),
  };
  t.after(async () => {
    await Promise.all(Object.values(pools).map((pool) => pool.end()));
    await adminPool.end();
  });

  const safety = await adminPool.query(
    `SELECT current_database() AS database,
            to_regnamespace('aios_tool') AS tool_schema`,
  );
  assert.match(safety.rows[0].database, /^c16_test_[0-9]+$/);
  assert.equal(safety.rows[0].tool_schema, null);

  for (const migration of migrations) await adminPool.query(migration);
  await adminPool.query(
    `REVOKE ALL PRIVILEGES ON SCHEMA aios_core FROM PUBLIC;
     REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA aios_core
       FROM PUBLIC;
     REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA aios_core
       FROM PUBLIC;
     REVOKE ALL PRIVILEGES ON ALL FUNCTIONS IN SCHEMA aios_core
       FROM PUBLIC;`,
  );
  for (const login of [
    RUNTIME_LOGIN,
    TOOL_WORKER_LOGIN,
    AUDIT_LOGIN,
    RECOVERY_LOGIN,
    SCOPE_LOGIN,
  ]) {
    await adminPool.query(`CREATE ROLE ${login} LOGIN`);
  }
  await adminPool.query(
    `GRANT aios_c16_runtime TO ${RUNTIME_LOGIN};
     GRANT aios_c16_worker TO ${TOOL_WORKER_LOGIN};
     GRANT aios_c16_audit_worker TO ${AUDIT_LOGIN};
     GRANT aios_c16_recovery_reader TO ${RECOVERY_LOGIN};
     GRANT aios_c07_scope_runtime TO ${SCOPE_LOGIN};`,
  );
  for (const [index, tenantId] of TENANT_IDS.entries()) {
    await seedTenant(adminPool, tenantId, index);
  }
  const store = createStore(pools);
  const records = [];

  await t.test("three Tenants persist isolated idempotent calls", async () => {
    for (const [index, tenantId] of TENANT_IDS.entries()) {
      const harness = createHarness(
        store,
        tenantId,
        APPROVAL_REFS[index],
        7000 + index * 200,
      );
      const [left, right] = await Promise.all([
        harness.gateway.confirm(
          harness.context,
          harness.confirmRequest,
        ),
        harness.gateway.confirm(
          harness.context,
          harness.confirmRequest,
        ),
      ]);
      assert.equal(left.confirmationId, right.confirmationId);
      const [result, replay] = await Promise.all([
        harness.gateway.execute(
          harness.context,
          harness.executeRequest(left),
        ),
        harness.gateway.execute(
          harness.context,
          harness.executeRequest(left),
        ),
      ]);
      assert.equal(result.status, "SUCCEEDED");
      assert.equal(replay.status, "SUCCEEDED");
      assert.equal(replay.callId, result.callId);
      assert.equal(result.replayed || replay.replayed, true);
      assert.equal(harness.adapter.snapshot().newExecutionCount, 1);
      await assert.rejects(
        harness.gateway.execute(
          harness.context,
          {
            ...harness.executeRequest(left),
            correlationId: `replay-${index}`,
            idempotencyKey: `different-execute-${index}`,
          },
        ),
        (error) =>
          error instanceof ToolGatewayError &&
          error.code === "CONFIRMATION_REPLAYED",
      );
      assert.equal(harness.adapter.snapshot().newExecutionCount, 1);
      records.push({ tenantId, confirmation: left, result });
    }
    const counts = await adminPool.query(
      `SELECT tenant_id,count(*)::int AS count
         FROM aios_tool.tool_call
        GROUP BY tenant_id ORDER BY tenant_id`,
    );
    assert.deepEqual(counts.rows.map(({ count }) => count), [1, 1, 1]);
    assert.equal(
      await store.getConfirmation(
        scope(TENANT_IDS[1], "cross-tenant"),
        records[0].confirmation.confirmationId,
      ),
      null,
    );
    const cleared = await pools.runtime.query(
      `SELECT current_setting('aios.tenant_id', true) AS tenant_id,
              current_setting('aios.scope_signature', true)
                AS scope_signature`,
    );
    assert.ok(
      Object.values(cleared.rows[0]).every(
        (value) => value === null || value === "",
      ),
    );
  });

  await t.test("expired audit lease is reclaimed and stale receipt is fenced", async () => {
    const tenantId = TENANT_IDS[0];
    const first = await store.claimAudit(
      scope(tenantId, "lease-first"),
      {
        workerId: "c16-expired-worker",
        limit: 1,
        leaseDurationSeconds: 1,
      },
    );
    assert.equal(first.length, 1);
    await new Promise((resolve) => setTimeout(resolve, 1100));
    const reclaimed = await store.claimAudit(
      scope(tenantId, "lease-reclaim"),
      {
        workerId: "c16-current-worker",
        limit: 1,
        leaseDurationSeconds: 30,
      },
    );
    assert.equal(reclaimed[0].leaseVersion, first[0].leaseVersion + 1);
    await assert.rejects(
      store.failAudit(scope(tenantId, "stale"), {
        intentId: first[0].intentId,
        workerId: "c16-expired-worker",
        leaseVersion: first[0].leaseVersion,
        retryDelaySeconds: 0,
        errorCode: "STALE_RETRY",
      }),
      (error) =>
        error instanceof PostgresToolGatewayStoreError &&
        error.code === "STALE_OUTBOX_LEASE",
    );
    const published = await store.completeAudit(
      scope(tenantId, "current"),
      {
        intentId: reclaimed[0].intentId,
        workerId: "c16-current-worker",
        leaseVersion: reclaimed[0].leaseVersion,
        ackIntentId: reclaimed[0].intentId,
      },
    );
    assert.equal(published.status, "PUBLISHED");
  });

  await t.test("roles are least-privilege and every table forces RLS", async () => {
    const runtime = await pools.runtime.connect();
    const toolWorker = await pools.toolWorker.connect();
    const audit = await pools.audit.connect();
    const recovery = await pools.recovery.connect();
    try {
      await assert.rejects(
        runtime.query("SELECT metadata FROM aios_tool.audit_intent"),
        (error) => error.code === "42501",
      );
      await assert.rejects(
        toolWorker.query(
          "SELECT confirmation_id FROM aios_tool.tool_confirmation",
        ),
        (error) => error.code === "42501",
      );
      await assert.rejects(
        audit.query("SELECT call_id FROM aios_tool.tool_call"),
        (error) => error.code === "42501",
      );
      await assert.rejects(
        recovery.query("DELETE FROM aios_tool.audit_outbox"),
        (error) => error.code === "42501",
      );
    } finally {
      runtime.release();
      toolWorker.release();
      audit.release();
      recovery.release();
    }
    const rls = await adminPool.query(
      `SELECT relname,relrowsecurity,relforcerowsecurity
         FROM pg_class
        WHERE relnamespace='aios_tool'::regnamespace
          AND relkind='r'
        ORDER BY relname`,
    );
    assert.equal(rls.rowCount, 4);
    assert.ok(
      rls.rows.every(
        (row) => row.relrowsecurity && row.relforcerowsecurity,
      ),
    );
    const publicAcl = await adminPool.query(
      `SELECT count(*)::int AS count
         FROM information_schema.role_table_grants
        WHERE table_schema='aios_tool'
          AND grantee='PUBLIC'`,
    );
    assert.equal(publicAcl.rows[0].count, 0);
    const roles = await adminPool.query(
      `SELECT rolname,rolcanlogin,rolsuper,rolinherit,rolcreatedb,
              rolcreaterole,rolreplication,rolbypassrls
         FROM pg_roles
        WHERE rolname=ANY($1::text[])
        ORDER BY rolname`,
      [C16_ROLES],
    );
    assert.deepEqual(
      roles.rows.map((row) => row.rolname),
      [...C16_ROLES].sort(),
    );
    for (const row of roles.rows) {
      assert.equal(row.rolcanlogin, false);
      assert.equal(row.rolsuper, false);
      assert.equal(row.rolinherit, false);
      assert.equal(row.rolcreatedb, false);
      assert.equal(row.rolcreaterole, false);
      assert.equal(row.rolreplication, false);
      assert.equal(row.rolbypassrls, false);
    }
    const privileges = await adminPool.query(
      `SELECT role_name,table_name,privilege,
              has_table_privilege(
                role_name,
                format('aios_tool.%I',table_name),
                privilege
              ) AS allowed
         FROM unnest($1::text[]) AS role_name
        CROSS JOIN unnest($2::text[]) AS table_name
        CROSS JOIN unnest($3::text[]) AS privilege
        ORDER BY role_name,table_name,privilege`,
      [APPLICATION_ROLES, C16_TABLES, TABLE_PRIVILEGES],
    );
    for (const row of privileges.rows) {
      const allowed =
        EXPECTED_TABLE_PRIVILEGES[row.role_name][row.privilege] ?? [];
      assert.equal(
        row.allowed,
        allowed.includes(row.table_name),
        `${row.role_name} ${row.privilege} ${row.table_name}`,
      );
    }
    await assert.rejects(
      adminPool.query(
        `UPDATE aios_tool.tool_confirmation
            SET expires_at=expires_at + interval '1 second'
          WHERE tenant_id=$1 AND confirmation_id=$2`,
        [TENANT_IDS[0], records[0].confirmation.confirmationId],
      ),
      (error) => error.code === "55000",
    );
  });

  await t.test("role closure and every adjacent direct grant fail closed", async () => {
    await adminPool.query(
      `CREATE SCHEMA aios_c16_adjacent_test;
       CREATE TABLE aios_c16_adjacent_test.sample (value integer);
       CREATE SEQUENCE aios_tool.c16_test_sequence;
       CREATE FUNCTION aios_tool.c16_test_function()
       RETURNS integer LANGUAGE sql IMMUTABLE AS 'SELECT 1';
       REVOKE ALL ON SCHEMA aios_c16_adjacent_test FROM PUBLIC;
       REVOKE ALL ON ALL TABLES IN SCHEMA aios_c16_adjacent_test
         FROM PUBLIC;
       REVOKE ALL ON SEQUENCE aios_tool.c16_test_sequence
         FROM PUBLIC;
       REVOKE ALL ON FUNCTION aios_tool.c16_test_function()
         FROM PUBLIC;`,
    );
    const cases = [
      {
        name: "transitive-role",
        login: "c16_bad_transitive_login",
        setup:
          `CREATE ROLE c16_bad_bridge NOLOGIN;
           CREATE ROLE c16_bad_transitive_login LOGIN;
           GRANT aios_c16_runtime TO c16_bad_bridge;
           GRANT c16_bad_bridge TO c16_bad_transitive_login;`,
      },
      {
        name: "predefined-read-role",
        login: "c16_bad_read_all_login",
        setup:
          `CREATE ROLE c16_bad_read_all_login LOGIN;
           GRANT aios_c16_runtime TO c16_bad_read_all_login;
           GRANT pg_read_all_data TO c16_bad_read_all_login;`,
      },
      {
        name: "high-attributes",
        login: "c16_bad_attribute_login",
        setup:
          `CREATE ROLE c16_bad_attribute_login LOGIN
             CREATEDB CREATEROLE REPLICATION BYPASSRLS;
           GRANT aios_c16_runtime TO c16_bad_attribute_login;`,
      },
      {
        name: "direct-table",
        login: "c16_bad_table_login",
        setup:
          `CREATE ROLE c16_bad_table_login LOGIN;
           GRANT aios_c16_runtime TO c16_bad_table_login;
           GRANT UPDATE ON aios_tool.tool_call
             TO c16_bad_table_login;`,
      },
      {
        name: "direct-column",
        login: "c16_bad_column_login",
        setup:
          `CREATE ROLE c16_bad_column_login LOGIN;
           GRANT aios_c16_runtime TO c16_bad_column_login;
           GRANT UPDATE (result) ON aios_tool.tool_call
             TO c16_bad_column_login;`,
      },
      {
        name: "direct-sequence",
        login: "c16_bad_sequence_login",
        setup:
          `CREATE ROLE c16_bad_sequence_login LOGIN;
           GRANT aios_c16_runtime TO c16_bad_sequence_login;
           GRANT USAGE ON SEQUENCE aios_tool.c16_test_sequence
             TO c16_bad_sequence_login;`,
      },
      {
        name: "direct-function",
        login: "c16_bad_function_login",
        setup:
          `CREATE ROLE c16_bad_function_login LOGIN;
           GRANT aios_c16_runtime TO c16_bad_function_login;
           GRANT EXECUTE ON FUNCTION aios_tool.c16_test_function()
             TO c16_bad_function_login;`,
      },
      {
        name: "adjacent-schema",
        login: "c16_bad_adjacent_login",
        setup:
          `CREATE ROLE c16_bad_adjacent_login LOGIN;
           GRANT aios_c16_runtime TO c16_bad_adjacent_login;
           GRANT USAGE ON SCHEMA aios_c16_adjacent_test
             TO c16_bad_adjacent_login;
           GRANT SELECT ON aios_c16_adjacent_test.sample
             TO c16_bad_adjacent_login;`,
      },
    ];
    for (const item of cases) {
      await adminPool.query(item.setup);
      const unsafe = new Pool(config(item.login));
      const unsafeStore = createPostgresToolGatewayStore({
        runtimePool: unsafe,
        toolWorkerPool: pools.toolWorker,
        auditWorkerPool: pools.audit,
        recoveryPool: pools.recovery,
        scopePool: pools.scope,
      });
      try {
        await assert.rejects(
          unsafeStore.getConfirmation(
            scope(TENANT_IDS[0], item.name),
            records[0].confirmation.confirmationId,
          ),
          (error) =>
            error instanceof PostgresToolGatewayStoreError &&
            error.code === "INVALID_CONFIGURATION",
          item.name,
        );
      } finally {
        await unsafe.end();
      }
    }
    await adminPool.query(
      `DROP OWNED BY
         c16_bad_transitive_login,
         c16_bad_bridge,
         c16_bad_read_all_login,
         c16_bad_attribute_login,
         c16_bad_table_login,
         c16_bad_column_login,
         c16_bad_sequence_login,
         c16_bad_function_login,
         c16_bad_adjacent_login;
       DROP ROLE
         c16_bad_transitive_login,
         c16_bad_bridge,
         c16_bad_read_all_login,
         c16_bad_attribute_login,
         c16_bad_table_login,
         c16_bad_column_login,
         c16_bad_sequence_login,
         c16_bad_function_login,
         c16_bad_adjacent_login;
       DROP FUNCTION aios_tool.c16_test_function();
       DROP SEQUENCE aios_tool.c16_test_sequence;
       DROP SCHEMA aios_c16_adjacent_test CASCADE;`,
    );
  });

  await t.test("metadata-only audit rejects a body-bearing mutation", async () => {
    const selected = await adminPool.query(
      `SELECT metadata
         FROM aios_tool.audit_intent
        WHERE tenant_id=$1
        ORDER BY created_at,intent_id
        LIMIT 1`,
      [TENANT_IDS[0]],
    );
    const metadataBase = {
      ...selected.rows[0].metadata,
      intentId: "tai_018f0000-0000-7000-8000-000000009999",
      content: "forbidden body",
    };
    delete metadataBase.intentSha256;
    const metadata = {
      ...metadataBase,
      intentSha256: toolGatewaySha256(metadataBase),
    };
    await assert.rejects(
      adminPool.query(
        `INSERT INTO aios_tool.audit_intent (
           tenant_id,tenant_kind,intent_id,event_type,subject_id,
           intent_sha256,metadata,created_at
         ) VALUES (
           $1,'SYNTHETIC',$2,$3,$4,$5,$6::jsonb,
           statement_timestamp()
         )`,
        [
          TENANT_IDS[0],
          metadata.intentId,
          metadata.eventType,
          metadata.subjectId,
          metadata.intentSha256,
          JSON.stringify(metadata),
        ],
      ),
      (error) =>
        error.constraint === "c16_audit_intent_metadata_only",
    );
  });

  await t.test("recovery snapshot is metadata-only and unsafe pools fail", async () => {
    const snapshot = await store.readRecoverySnapshot(
      scope(TENANT_IDS[0], "recovery"),
    );
    assert.equal(snapshot.confirmations.length, 1);
    assert.equal(snapshot.calls.length, 1);
    assert.ok(snapshot.auditOutbox.length >= 2);
    const serialized = JSON.stringify(snapshot);
    assert.equal(serialized.includes("normalizedParams"), false);
    assert.equal(serialized.includes("cap_"), false);

    await adminPool.query(
      `CREATE ROLE c16_test_unsafe_login LOGIN;
       GRANT aios_c16_runtime TO c16_test_unsafe_login;
       GRANT aios_c16_audit_worker TO c16_test_unsafe_login;`,
    );
    const unsafe = new Pool(config("c16_test_unsafe_login"));
    t.after(() => unsafe.end());
    const unsafeStore = createPostgresToolGatewayStore({
      runtimePool: unsafe,
      toolWorkerPool: pools.toolWorker,
      auditWorkerPool: pools.audit,
      recoveryPool: pools.recovery,
      scopePool: pools.scope,
    });
    await assert.rejects(
      unsafeStore.getConfirmation(
        scope(TENANT_IDS[0], "unsafe"),
        records[0].confirmation.confirmationId,
      ),
      (error) =>
        error instanceof PostgresToolGatewayStoreError &&
        error.code === "INVALID_CONFIGURATION",
    );

    const ownerMixed = createPostgresToolGatewayStore({
      runtimePool: adminPool,
      toolWorkerPool: pools.toolWorker,
      auditWorkerPool: pools.audit,
      recoveryPool: pools.recovery,
      scopePool: pools.scope,
    });
    await assert.rejects(
      ownerMixed.getConfirmation(
        scope(TENANT_IDS[0], "owner-mixed"),
        records[0].confirmation.confirmationId,
      ),
      (error) =>
        error instanceof PostgresToolGatewayStoreError &&
        error.code === "INVALID_CONFIGURATION",
    );
  });
});
