import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test, { after, before } from "node:test";
import pg from "pg";
import {
  createObservabilityService,
  createSyntheticObservabilityCatalog,
  ObservabilityError,
} from "../../lib/c19-observability.mjs";
import {
  createPostgresObservabilityStore,
} from "../../lib/c19-observability-postgres-store.mjs";

const { Pool } = pg;
const migrationPaths = [
  "../../implementation/p1/c03/postgresql/0001_tenant_registry.sql",
  "../../implementation/p1/c07/postgresql/0011_tenant_data_isolation.sql",
  "../../implementation/p1/c07/postgresql/0012_tenant_data_runtime_roles.sql",
  "../../implementation/p1/c19/postgresql/0033_observability_usage.sql",
  "../../implementation/p1/c19/postgresql/0034_observability_runtime_roles.sql",
];
const migrations = await Promise.all(
  migrationPaths.map((path) =>
    readFile(new URL(path, import.meta.url), "utf8"),
  ),
);
const catalog = createSyntheticObservabilityCatalog(
  JSON.parse(
    await readFile(
      new URL(
        "../../implementation/p1/c19/synthetic-observability-catalog.v1.json",
        import.meta.url,
      ),
      "utf8",
    ),
  ),
);
const TENANTS = catalog.tenantIds();
const PRINCIPALS = [
  "prn_018f0000-0000-7000-8000-000000000001",
  "prn_018f0000-0000-7000-8000-000000000202",
  "prn_018f0000-0000-7000-8000-000000000203",
];
const IDENTITY_CONTEXTS = [
  "fixture://c19/northstar/identity-context/ava",
  "fixture://c19/blue-harbor/identity-context/ava",
  "fixture://c19/cedar/identity-context/ava",
];
const WRITER_LOGIN = "c19_test_writer_login";
const READER_LOGIN = "c19_test_reader_login";
const SCOPE_LOGIN = "c19_test_scope_login";
const HASH =
  "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const PROJECTIONS = [
  "AUTHORIZATION",
  "IDENTITY",
  "KNOWLEDGE",
  "SECRET_REFS",
  "STORAGE",
];

function configuration(user = process.env.C19_TEST_PGUSER) {
  if (process.env.C19_TEST_EPHEMERAL !== "1") {
    throw new Error("C19_TEST_EPHEMERAL=1 is required.");
  }
  return {
    host: process.env.C19_TEST_PGHOST,
    port: Number(process.env.C19_TEST_PGPORT),
    database: process.env.C19_TEST_PGDATABASE,
    user,
    max: 30,
  };
}

async function seedTenant(pool, tenantId, index) {
  const createdAt = `2026-07-26T10:0${index}:00.000Z`;
  const suffix = String(index + 1).padStart(12, "0");
  await pool.query(
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
      `c19-creation-${index}`,
      `fixture://c19/tenant/${index}`,
      HASH,
      `sns_018f0000-0000-7000-8000-${suffix}`,
      `op_018f0000-0000-7000-8000-${suffix}`,
      createdAt,
    ],
  );
  for (const projection of PROJECTIONS) {
    await pool.query(
      `INSERT INTO aios_core.tenant_projection (
         tenant_id,generation,projection,desired_action,status,
         attempt_count,source_event_id,updated_at
       ) VALUES ($1,1,$2,'PROVISION','READY',1,$3,$4)`,
      [
        tenantId,
        projection,
        `c19-${index}-${projection.toLowerCase()}`,
        createdAt,
      ],
    );
  }
  await pool.query(
    `UPDATE aios_core.tenant_registry
        SET state='ACTIVE',lifecycle_version=2
      WHERE tenant_id=$1`,
    [tenantId],
  );
  await pool.query(
    `INSERT INTO aios_data.tenant_data_lifecycle (
       tenant_id,tenant_kind,lifecycle_version,generation,operation_id,
       state,last_event_id,updated_at
     ) VALUES ($1,'SYNTHETIC',2,1,$2,'ACTIVE',$3,$4)`,
    [
      tenantId,
      `op_018f0000-0000-7000-8000-${suffix}`,
      `c19-active-${index}`,
      createdAt,
    ],
  );
}

let adminPool;
let writerPool;
let readerPool;
let scopePool;
let store;
let nextId = 5000;
let nextSpan = 0x5000000000000000n;
const runtimeClocks = new Map();

before(async () => {
  adminPool = new Pool(configuration());
  for (const migration of migrations) {
    await adminPool.query(migration);
  }
  await adminPool.query(
    `REVOKE ALL ON SCHEMA aios_core FROM PUBLIC;
     REVOKE ALL ON ALL TABLES IN SCHEMA aios_core FROM PUBLIC;
     REVOKE ALL ON ALL SEQUENCES IN SCHEMA aios_core FROM PUBLIC;
     REVOKE ALL ON ALL FUNCTIONS IN SCHEMA aios_core FROM PUBLIC;
     CREATE ROLE ${WRITER_LOGIN}
       LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE INHERIT NOREPLICATION
       NOBYPASSRLS;
     CREATE ROLE ${READER_LOGIN}
       LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE INHERIT NOREPLICATION
       NOBYPASSRLS;
     CREATE ROLE ${SCOPE_LOGIN}
       LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE INHERIT NOREPLICATION
       NOBYPASSRLS;
     GRANT aios_c19_writer TO ${WRITER_LOGIN};
     GRANT aios_c19_reader TO ${READER_LOGIN};
     GRANT aios_c07_scope_runtime TO ${SCOPE_LOGIN};`,
  );
  for (const [index, tenantId] of TENANTS.entries()) {
    await seedTenant(adminPool, tenantId, index);
  }
  writerPool = new Pool(configuration(WRITER_LOGIN));
  readerPool = new Pool(configuration(READER_LOGIN));
  scopePool = new Pool(configuration(SCOPE_LOGIN));
  store = createPostgresObservabilityStore({
    writerPool,
    readerPool,
    scopePool,
  });
});

after(async () => {
  await Promise.allSettled([
    writerPool?.end(),
    readerPool?.end(),
    scopePool?.end(),
    adminPool?.end(),
  ]);
});

function serviceFor(tenantId, selectedStore = store) {
  const tenantIndex = TENANTS.indexOf(tenantId);
  return createObservabilityService({
    catalog,
    store: selectedStore,
    tenantRegistry: {
      async admitNewRequest({ tenantId: requested, expectedTenantKind }) {
        assert.equal(requested, tenantId);
        assert.equal(expectedTenantKind, "SYNTHETIC");
        return {
          tenantId,
          tenantKind: "SYNTHETIC",
          lifecycleVersion: 2,
        };
      },
    },
    tenantScopeFactory({ tenant, scopeEvidence, correlationId }) {
      return {
        trustSource: "C07_VERIFIED_TENANT_SCOPE",
        tenantId: tenant.tenantId,
        tenantKind: tenant.tenantKind,
        lifecycleVersion: tenant.lifecycleVersion,
        correlationId,
        decisionId: scopeEvidence.decisionId,
        evidenceRef: scopeEvidence.evidenceRef,
        policyVersion: scopeEvidence.policyVersion,
      };
    },
    principalResolver: {
      async resolveActionIdentity({ tenantId: requested, identityContextRef }) {
        assert.equal(requested, tenantId);
        assert.equal(identityContextRef, IDENTITY_CONTEXTS[tenantIndex]);
        return {
          tenantId,
          tenantKind: "SYNTHETIC",
          trustSource:
            "VERIFIED_SESSION_IDENTITY_LINK_AND_WORKLOAD_CONTEXT",
          humanSubject: {
            principalId: PRINCIPALS[tenantIndex],
            principalType: "HUMAN",
            lifecycleVersion: 1,
            securityEpoch: 1,
          },
        };
      },
    },
    clock: () =>
      runtimeClocks.get(tenantId) ??
      "2026-07-26T11:00:00.000Z",
    idFactory: () => {
      nextId += 1;
      return `018f0000-0000-7000-8000-${String(nextId).padStart(12, "0")}`;
    },
    spanIdFactory: () => {
      nextSpan += 1n;
      return nextSpan.toString(16);
    },
  });
}

function context(tenantId) {
  const tenantIndex = TENANTS.indexOf(tenantId);
  return {
    synthetic: true,
    routeTrustSource: "VERIFIED_ROUTE_DESCRIPTOR",
    tenantId,
    identityContextRef: IDENTITY_CONTEXTS[tenantIndex],
  };
}

function withoutDuplicate(value) {
  const result = structuredClone(value);
  delete result.duplicate;
  return result;
}

const TRACE =
  "00-9bf92f3577b34da6a3ce929d0e0e4736-50f067aa0ba902b7-01";

test("real PostgreSQL correlates telemetry and reconciles model, Tool and sandbox cost", async () => {
  const tenantId = TENANTS[0];
  const service = serviceFor(tenantId);
  const signalRequest = {
    idempotencyKey: "idem-c19-pg-signal",
    traceparent: TRACE,
    tracestate: "vendor=value",
    signalType: "SPAN",
    operation: "c14.model.route",
    taskRef: "tsk_018f0000-0000-7000-8000-000000000101",
    status: "OK",
    durationMs: 7,
    errorCode: null,
  };
  const firstSignal = await service.recordSignal(
    context(tenantId),
    signalRequest,
  );
  assert.equal(firstSignal.duplicate, false);
  const signalRetry = await service.recordSignal(
    context(tenantId),
    signalRequest,
  );
  assert.equal(signalRetry.duplicate, true);
  assert.deepEqual(
    withoutDuplicate(signalRetry),
    withoutDuplicate(firstSignal),
  );
  await assert.rejects(
    service.recordSignal(context(tenantId), {
      ...signalRequest,
      durationMs: 8,
    }),
    (error) =>
      error instanceof ObservabilityError &&
      error.code === "IDEMPOTENCY_CONFLICT",
  );
  const reservations = [];
  for (const [index, type] of ["model", "tool", "sandbox"].entries()) {
    reservations.push(
      await service.reserve(context(tenantId), {
        idempotencyKey: `idem-c19-pg-reserve-${index}`,
        planRef: `fixture://c19/northstar/plans/${type}`,
        traceparent: TRACE,
        tracestate: null,
      }),
    );
    assert.equal(reservations.at(-1).duplicate, false);
  }
  const reservationRetry = await service.reserve(context(tenantId), {
    idempotencyKey: "idem-c19-pg-reserve-0",
    planRef: "fixture://c19/northstar/plans/model",
    traceparent:
      "00-cbf92f3577b34da6a3ce929d0e0e4736-60f067aa0ba902b7-01",
    tracestate: "retry=new-hop",
  });
  assert.equal(reservationRetry.duplicate, true);
  assert.deepEqual(
    withoutDuplicate(reservationRetry),
    withoutDuplicate(reservations[0]),
  );
  runtimeClocks.set(tenantId, "2026-07-26T13:00:00.000Z");
  const settlements = [];
  for (const [index, type] of ["model", "tool", "sandbox"].entries()) {
    settlements.push(
      await service.settle(context(tenantId), {
        idempotencyKey: `idem-c19-pg-settle-${index}`,
        reservationId: reservations[index].reservation.reservationId,
        receiptRef: `fixture://c19/northstar/receipts/${type}`,
        traceparent: reservations[index].traceContext.traceparent,
        tracestate: null,
      }),
    );
    assert.equal(settlements.at(-1).duplicate, false);
  }
  const settlementRetry = await service.settle(context(tenantId), {
    idempotencyKey: "idem-c19-pg-settle-0",
    reservationId: reservations[0].reservation.reservationId,
    receiptRef: "fixture://c19/northstar/receipts/model",
    traceparent:
      "00-dbf92f3577b34da6a3ce929d0e0e4736-70f067aa0ba902b7-01",
    tracestate: "retry=new-hop",
  });
  assert.equal(settlementRetry.duplicate, true);
  assert.deepEqual(
    withoutDuplicate(settlementRetry),
    withoutDuplicate(settlements[0]),
  );
  const telemetry = await service.telemetryReport(context(tenantId), {
    fromOccurredAt: "2026-07-26T00:00:00.000Z",
    toOccurredAt: "2026-07-27T00:00:00.000Z",
  });
  const cost = await service.costVarianceReport(context(tenantId), {
    fromOccurredAt: "2026-07-26T00:00:00.000Z",
    toOccurredAt: "2026-07-27T00:00:00.000Z",
  });
  assert.equal(telemetry.sli.totalSignals, 1);
  assert.deepEqual(cost.totals, {
    bookedCostMicros: 5380,
    supplierCostMicros: 4825,
    varianceMicros: -555,
  });
  assert.equal(cost.ledgerEvents.length, 6);
  assert.equal(cost.byPrincipal[0].principalId, PRINCIPALS[0]);
  const quota = await service.quotaStatus(context(tenantId));
  assert.deepEqual(
    quota.accounts.map((account) => [
      account.quotaScope,
      account.reservedMicros,
      account.consumedMicros,
    ]),
    [
      ["PRINCIPAL", 0, 5380],
      ["TENANT", 0, 5380],
    ],
  );
});

test("real PostgreSQL locks quota rows so concurrent reservations cannot oversell", async () => {
  const tenantId = TENANTS[1];
  const service = serviceFor(tenantId);
  const results = await Promise.allSettled(
    [1, 2, 3].map((index) =>
      service.reserve(context(tenantId), {
        idempotencyKey: `idem-c19-pg-concurrent-${index}`,
        planRef: "fixture://c19/blue-harbor/plans/sandbox",
        traceparent: TRACE,
        tracestate: null,
      }),
    ),
  );
  assert.equal(
    results.filter((result) => result.status === "fulfilled").length,
    2,
  );
  assert.equal(
    results.filter(
      (result) =>
        result.status === "rejected" &&
        result.reason instanceof ObservabilityError &&
        result.reason.code === "QUOTA_EXCEEDED",
    ).length,
    1,
  );
  const quota = await service.quotaStatus(context(tenantId));
  assert.equal(
    quota.accounts.find(
      (account) => account.quotaScope === "PRINCIPAL",
    ).deniedCount,
    1,
  );
  assert.equal(
    quota.accounts.find(
      (account) => account.quotaScope === "TENANT",
    ).deniedCount,
    0,
  );
  assert.equal(
    quota.alerts.some(
      (alert) => alert.code === "C19_QUOTA_DENIAL",
    ),
    true,
  );
  const admitted = results
    .filter((result) => result.status === "fulfilled")
    .map((result) => result.value);
  const released = await Promise.all(
    admitted.map((result, index) =>
      service.release(context(tenantId), {
        idempotencyKey: `idem-c19-pg-release-${index}`,
        reservationId: result.reservation.reservationId,
        traceparent: result.traceContext.traceparent,
        tracestate: null,
      }),
    ),
  );
  assert.deepEqual(
    await service.release(context(tenantId), {
      idempotencyKey: "idem-c19-pg-release-0",
      reservationId: admitted[0].reservation.reservationId,
      traceparent: TRACE,
      tracestate: "retry=new-hop",
    }),
    released[0],
  );
  const reconciled = await service.quotaStatus(context(tenantId));
  assert.equal(
    reconciled.accounts.every(
      (account) =>
        account.reservedMicros === 0 &&
        account.consumedMicros === 0,
    ),
    true,
  );
  const releaseRows = await adminPool.query(
    `SELECT count(*)::integer AS count
       FROM aios_observability.usage_ledger
      WHERE tenant_id=$1
        AND event_type='QUOTA_RELEASED'`,
    [tenantId],
  );
  assert.equal(releaseRows.rows[0].count, 2);
});

test("real PostgreSQL serializes concurrent retries with one idempotency key", async () => {
  const tenantId = TENANTS[2];
  const service = serviceFor(tenantId);
  const request = {
    idempotencyKey: "idem-c19-pg-identical",
    planRef: "fixture://c19/cedar/plans/model",
    traceparent: TRACE,
    tracestate: null,
  };
  const [first, second] = await Promise.all([
    service.reserve(context(tenantId), request),
    service.reserve(context(tenantId), request),
  ]);
  assert.deepEqual(
    [first.duplicate, second.duplicate].sort(),
    [false, true],
  );
  assert.deepEqual(withoutDuplicate(second), withoutDuplicate(first));
  const rows = await adminPool.query(
    `SELECT count(*)::integer AS count
       FROM aios_observability.usage_ledger
      WHERE tenant_id=$1
        AND reservation_id=$2
        AND event_type='QUOTA_RESERVED'`,
    [tenantId, first.reservation.reservationId],
  );
  assert.equal(rows.rows[0].count, 1);
});

test("FORCE RLS hides rows without signed scope and append-only triggers reject mutation", async () => {
  const hidden = await readerPool.query(
    "SELECT count(*)::integer AS count FROM aios_observability.usage_ledger",
  );
  assert.equal(hidden.rows[0].count, 0);
  await assert.rejects(
    adminPool.query(
      "DELETE FROM aios_observability.usage_ledger",
    ),
    /append-only/,
  );
  const reservation = await adminPool.query(
    `SELECT tenant_id,reservation_id,dimension_type,resource_ref,
            meter_type,unit,rate_version,trace_id,span_id
       FROM (
         SELECT tenant_id,reservation_id,dimension_type,resource_ref,
                meter_type,unit,rate_version,reserve_trace_id AS trace_id,
                reserve_span_id AS span_id
           FROM aios_observability.quota_reservation
       ) candidate
      ORDER BY tenant_id,reservation_id
      LIMIT 1`,
  );
  const row = reservation.rows[0];
  await assert.rejects(
    adminPool.query(
      `INSERT INTO aios_observability.usage_ledger (
         tenant_id,tenant_kind,event_id,event_type,reservation_id,
         task_ref,dimension_type,resource_ref,meter_type,unit,
         quantity,cost_micros,rate_version,receipt_ref,meter_key,
         supplier_cost_micros,variance_micros,trace_id,span_id,occurred_at
       ) VALUES (
         $1,'SYNTHETIC',
         'ule_018f0000-0000-7000-8000-000000009999',
         'QUOTA_RESERVED',$2,
         'tsk_018f0000-0000-7000-8000-000000009999',
         $3,$4,$5,$6,1,1,$7,NULL,NULL,NULL,NULL,$8,$9,
         '2026-07-26T13:00:00.000Z'
       )`,
      [
        row.tenant_id,
        row.reservation_id,
        row.dimension_type,
        row.resource_ref,
        row.meter_type,
        row.unit,
        row.rate_version,
        row.trace_id,
        row.span_id,
      ],
    ),
    /does not match reservation/,
  );
  await assert.rejects(
    adminPool.query(
      `UPDATE aios_observability.quota_account
          SET reserved_micros=reserved_micros - 1
        WHERE tenant_id=$1
          AND reserved_micros > 0`,
      [TENANTS[2]],
    ),
    /quota account does not reconcile/,
  );
});

test("real PostgreSQL rejects excluded facts and arbitrary extension columns", async () => {
  const columns = await adminPool.query(
    `SELECT table_name,column_name
       FROM information_schema.columns
      WHERE table_schema='aios_observability'
      ORDER BY table_name,ordinal_position`,
  );
  const actual = new Set(
    columns.rows.map(
      (row) => `${row.table_name}.${row.column_name}`,
    ),
  );
  for (const prohibited of [
    "project_progress",
    "invoice",
    "business_metric",
    "metadata",
    "payload",
    "body",
  ]) {
    assert.equal(
      [...actual].some((column) => column.endsWith(`.${prohibited}`)),
      false,
      `C19 database exposes ${prohibited}`,
    );
    await assert.rejects(
      adminPool.query(
        `INSERT INTO aios_observability.telemetry_signal
           ("${prohibited}") VALUES ($1)`,
        ["synthetic-invalid-fact"],
      ),
      (error) => error?.code === "42703",
      `PostgreSQL accepted ${prohibited}`,
    );
  }
});

test("PostgreSQL store refuses a pool authenticated with the wrong exact role", async () => {
  const wrongStore = createPostgresObservabilityStore({
    writerPool: readerPool,
    readerPool: writerPool,
    scopePool,
  });
  const service = serviceFor(TENANTS[2], wrongStore);
  await assert.rejects(
    service.recordSignal(context(TENANTS[2]), {
      idempotencyKey: "idem-c19-pg-wrong-role",
      traceparent: TRACE,
      tracestate: null,
      signalType: "LOG",
      operation: "c19.usage.settle",
      taskRef: "tsk_018f0000-0000-7000-8000-000000000103",
      status: "OK",
      durationMs: null,
      errorCode: null,
    }),
    (error) =>
      error instanceof ObservabilityError &&
      error.code === "INVALID_CONFIGURATION",
  );
});

test("PostgreSQL store refuses an otherwise-correct role with an extra direct capability", async () => {
  await adminPool.query(
    `GRANT SELECT ON aios_data.tenant_sql_record TO ${WRITER_LOGIN}`,
  );
  try {
    const service = serviceFor(TENANTS[2]);
    await assert.rejects(
      service.recordSignal(context(TENANTS[2]), {
        idempotencyKey: "idem-c19-pg-extra-capability",
        traceparent: TRACE,
        tracestate: null,
        signalType: "LOG",
        operation: "c19.usage.settle",
        taskRef: "tsk_018f0000-0000-7000-8000-000000000103",
        status: "OK",
        durationMs: null,
        errorCode: null,
      }),
      (error) =>
        error instanceof ObservabilityError &&
        error.code === "INVALID_CONFIGURATION",
    );
  } finally {
    await adminPool.query(
      `REVOKE SELECT ON aios_data.tenant_sql_record FROM ${WRITER_LOGIN}`,
    );
  }
});
