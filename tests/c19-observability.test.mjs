import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import {
  createMemoryObservabilityStore,
  createObservabilityService,
  createSyntheticObservabilityCatalog,
  ObservabilityError,
  parseTraceContext,
  propagateTraceContext,
} from "../lib/c19-observability.mjs";

const catalogDocument = JSON.parse(
  await readFile(
    new URL(
      "../implementation/p1/c19/synthetic-observability-catalog.v1.json",
      import.meta.url,
    ),
    "utf8",
  ),
);
const CATALOG = createSyntheticObservabilityCatalog(catalogDocument);
const TENANT =
  "stn_018f0000-0000-7000-8000-000000000010";
const PRINCIPAL =
  "prn_018f0000-0000-7000-8000-000000000001";
const IDENTITY_CONTEXT =
  "fixture://c19/northstar/identity-context/ava";
const TASK = "tsk_018f0000-0000-7000-8000-000000000101";
const MODEL_PLAN = "fixture://c19/northstar/plans/model";
const TOOL_PLAN = "fixture://c19/northstar/plans/tool";
const SANDBOX_PLAN = "fixture://c19/northstar/plans/sandbox";
const MODEL_RECEIPT = "fixture://c19/northstar/receipts/model";
const TOOL_RECEIPT = "fixture://c19/northstar/receipts/tool";
const SANDBOX_RECEIPT =
  "fixture://c19/northstar/receipts/sandbox";
const SERVER_CONTEXT = {
  synthetic: true,
  routeTrustSource: "VERIFIED_ROUTE_DESCRIPTOR",
  tenantId: TENANT,
  identityContextRef: IDENTITY_CONTEXT,
};

function createHarness() {
  let id = 0;
  let span = 0x1000000000000000n;
  const mutable = {
    now: "2026-07-26T11:00:00.000Z",
  };
  const service = createObservabilityService({
    catalog: CATALOG,
    store: createMemoryObservabilityStore(),
    tenantRegistry: {
      async admitNewRequest({ tenantId, expectedTenantKind }) {
        assert.equal(tenantId, TENANT);
        assert.equal(expectedTenantKind, "SYNTHETIC");
        return {
          tenantId,
          tenantKind: "SYNTHETIC",
          lifecycleVersion: 1,
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
      async resolveActionIdentity({ tenantId, identityContextRef }) {
        assert.equal(tenantId, TENANT);
        assert.equal(identityContextRef, IDENTITY_CONTEXT);
        return {
          tenantId,
          tenantKind: "SYNTHETIC",
          trustSource:
            "VERIFIED_SESSION_IDENTITY_LINK_AND_WORKLOAD_CONTEXT",
          humanSubject: {
            principalId: PRINCIPAL,
            principalType: "HUMAN",
            lifecycleVersion: 1,
            securityEpoch: 1,
          },
        };
      },
    },
    clock: () => mutable.now,
    idFactory: () => {
      id += 1;
      return `018f0000-0000-7000-8000-${String(id).padStart(12, "0")}`;
    },
    spanIdFactory: () => {
      span += 1n;
      return span.toString(16);
    },
  });
  return { service, mutable };
}

test("strict W3C Trace Context propagates one trace across a child span", () => {
  const parent = parseTraceContext({
    traceparent:
      "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
    tracestate: "vendor=value,tenant=synth",
  });

  assert.deepEqual(parent, {
    version: "00",
    traceId: "4bf92f3577b34da6a3ce929d0e0e4736",
    parentId: "00f067aa0ba902b7",
    traceFlags: "01",
    sampled: true,
    traceparent:
      "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
    tracestate: "vendor=value,tenant=synth",
  });

  assert.deepEqual(
    propagateTraceContext(parent, "7a3b4c5d6e7f8091"),
    {
      traceparent:
        "00-4bf92f3577b34da6a3ce929d0e0e4736-7a3b4c5d6e7f8091-01",
      tracestate: "vendor=value,tenant=synth",
    },
  );
});

test("Trace Context rejects malformed, ambiguous and forbidden values", () => {
  const invalid = [
    {},
    {
      traceparent:
        "00-00000000000000000000000000000000-00f067aa0ba902b7-01",
    },
    {
      traceparent:
        "00-4bf92f3577b34da6a3ce929d0e0e4736-0000000000000000-01",
    },
    {
      traceparent:
        "00-4BF92F3577B34DA6A3CE929D0E0E4736-00f067aa0ba902b7-01",
    },
    {
      traceparent:
        "01-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01-extra",
    },
    {
      traceparent:
        "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-02",
    },
    {
      traceparent:
        "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
      tracestate: "vendor=one,vendor=two",
    },
    {
      traceparent:
        "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
      tracestate: "Vendor=value",
    },
    {
      traceparent:
        "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
      tracestate: "vendor=Bearer secretvalue",
    },
    {
      traceparent:
        "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
      tracestate: "\u00a0vendor=value",
    },
  ];

  for (const headers of invalid) {
    assert.throws(
      () => parseTraceContext(headers),
      (error) =>
        error instanceof ObservabilityError &&
        error.code === "INVALID_TRACE_CONTEXT",
    );
  }
});

test("metadata-only telemetry correlates C14, C16, C18 and C19 without high-cardinality labels", async () => {
  const { service } = createHarness();
  let traceContext = {
    traceparent:
      "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
    tracestate: "vendor=value",
  };
  const signals = [
    ["TRACE", "c14.model.route", "OK", 8, null],
    ["SPAN", "c16.tool.execute", "OK", 13, null],
    ["SPAN", "c18.audit.append", "ERROR", 5, "AUDIT_REJECTED"],
    ["LOG", "c19.usage.settle", "OK", null, null],
  ];

  for (const [index, signal] of signals.entries()) {
    const result = await service.recordSignal(SERVER_CONTEXT, {
      idempotencyKey: `idem-c19-signal-${index}`,
      traceparent: traceContext.traceparent,
      tracestate: traceContext.tracestate,
      signalType: signal[0],
      operation: signal[1],
      taskRef: TASK,
      status: signal[2],
      durationMs: signal[3],
      errorCode: signal[4],
    });
    assert.equal(
      parseTraceContext(result.traceContext).traceId,
      "4bf92f3577b34da6a3ce929d0e0e4736",
    );
    assert.equal(
      parseTraceContext(result.traceContext).parentId,
      result.signal.spanId,
    );
    assert.deepEqual(Object.keys(result.metricLabels), [
      "module",
      "operation",
      "signal_type",
      "status",
      "error_code",
    ]);
    assert.equal(JSON.stringify(result.metricLabels).includes(TENANT), false);
    assert.equal(JSON.stringify(result.metricLabels).includes(TASK), false);
    traceContext = result.traceContext;
  }

  const report = await service.telemetryReport(SERVER_CONTEXT, {
    fromOccurredAt: "2026-07-26T00:00:00.000Z",
    toOccurredAt: "2026-07-27T00:00:00.000Z",
  });
  assert.deepEqual(report.sli, {
    totalSignals: 4,
    errorSignals: 1,
    successRatio: 0.75,
    durationCount: 3,
    totalDurationMs: 26,
    maxDurationMs: 13,
  });
  assert.equal(report.traceCount, 1);
  assert.equal(report.records.every((row) => row.tenantId === TENANT), true);
  assert.equal(
    JSON.stringify(report).includes("prompt") ||
      JSON.stringify(report).includes("credential"),
    false,
  );
});

test("telemetry rejects request bodies and arbitrary metadata", async () => {
  const { service } = createHarness();
  await assert.rejects(
    service.recordSignal(SERVER_CONTEXT, {
      idempotencyKey: "idem-c19-prohibited-body",
      traceparent:
        "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
      tracestate: null,
      signalType: "LOG",
      operation: "c19.usage.settle",
      taskRef: TASK,
      status: "OK",
      durationMs: null,
      errorCode: null,
      body: "synthetic prompt content must not be logged",
    }),
    (error) =>
      error instanceof ObservabilityError &&
      error.code === "PROHIBITED_TELEMETRY_FIELD",
  );
  await assert.rejects(
    service.recordSignal(SERVER_CONTEXT, {
      idempotencyKey: "idem-c19-high-card-error",
      traceparent:
        "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
      tracestate: null,
      signalType: "SPAN",
      operation: "c18.audit.append",
      taskRef: TASK,
      status: "ERROR",
      durationMs: 1,
      errorCode: "REQUEST_123456789",
    }),
    (error) =>
      error instanceof ObservabilityError &&
      error.code === "INVALID_INPUT",
  );
});

test("quota reservation, deduplicated settlement and cost variance reconcile all required dimensions", async () => {
  const { service, mutable } = createHarness();
  let traceContext = {
    traceparent:
      "00-6bf92f3577b34da6a3ce929d0e0e4736-10f067aa0ba902b7-01",
    tracestate: "vendor=value",
  };
  const reserved = [];
  for (const [index, planRef] of [
    MODEL_PLAN,
    TOOL_PLAN,
    SANDBOX_PLAN,
  ].entries()) {
    const result = await service.reserve(SERVER_CONTEXT, {
      idempotencyKey: `idem-c19-reserve-${index}`,
      planRef,
      traceparent: traceContext.traceparent,
      tracestate: traceContext.tracestate,
    });
    assert.equal(result.reservation.state, "RESERVED");
    assert.equal(result.reservation.rateVersion, "rates-2026-07-v1");
    reserved.push(result.reservation);
    traceContext = result.traceContext;
  }
  const retriedReservation = await service.reserve(SERVER_CONTEXT, {
    idempotencyKey: "idem-c19-reserve-0",
    planRef: MODEL_PLAN,
    traceparent:
      "00-abf92f3577b34da6a3ce929d0e0e4736-60f067aa0ba902b7-01",
    tracestate: "retry=new-hop",
  });
  assert.deepEqual(retriedReservation, {
    reservation: reserved[0],
    traceContext: {
      traceparent:
        "00-6bf92f3577b34da6a3ce929d0e0e4736-1000000000000001-01",
      tracestate: "vendor=value",
    },
  });
  assert.deepEqual(
    reserved.map((row) => row.reservedCostMicros),
    [4000, 2500, 10000],
  );
  assert.equal(
    reserved.every((row) => row.principalId === PRINCIPAL),
    true,
  );
  const thresholdStatus = await service.quotaStatus(SERVER_CONTEXT);
  assert.deepEqual(
    thresholdStatus.alerts.map((alert) => [
      alert.code,
      alert.quotaScope,
    ]),
    [["C19_QUOTA_THRESHOLD", "PRINCIPAL"]],
  );

  mutable.now = "2026-07-26T13:00:00.000Z";
  const settled = [];
  for (const [index, receiptRef] of [
    MODEL_RECEIPT,
    TOOL_RECEIPT,
    SANDBOX_RECEIPT,
  ].entries()) {
    const result = await service.settle(SERVER_CONTEXT, {
      idempotencyKey: `idem-c19-settle-${index}`,
      reservationId: reserved[index].reservationId,
      receiptRef,
      traceparent: traceContext.traceparent,
      tracestate: traceContext.tracestate,
    });
    assert.equal(result.settlement.state, "SETTLED");
    settled.push(result);
    traceContext = result.traceContext;
  }

  const duplicate = await service.settle(SERVER_CONTEXT, {
    idempotencyKey: "idem-c19-settle-0",
    reservationId: reserved[0].reservationId,
    receiptRef: MODEL_RECEIPT,
    traceparent:
      "00-bbf92f3577b34da6a3ce929d0e0e4736-70f067aa0ba902b7-01",
    tracestate: "retry=new-hop",
  });
  assert.deepEqual(duplicate, settled[0]);

  const report = await service.costVarianceReport(SERVER_CONTEXT, {
    fromOccurredAt: "2026-07-26T00:00:00.000Z",
    toOccurredAt: "2026-07-27T00:00:00.000Z",
  });
  assert.deepEqual(report.totals, {
    bookedCostMicros: 5380,
    supplierCostMicros: 4825,
    varianceMicros: -555,
  });
  assert.deepEqual(
    [
      ...report.byModel,
      ...report.byTool,
      ...report.bySandbox,
    ].map((row) => row.dimensionType),
    ["MODEL", "TOOL", "SANDBOX"],
  );
  assert.deepEqual(report.byTask, [
    {
      taskRef: TASK,
      bookedCostMicros: 5380,
      supplierCostMicros: 4825,
      varianceMicros: -555,
    },
  ]);
  assert.deepEqual(report.byPrincipal, [
    {
      principalId: PRINCIPAL,
      bookedCostMicros: 5380,
      supplierCostMicros: 4825,
      varianceMicros: -555,
    },
  ]);
  assert.deepEqual(
    report.ledgerEvents.map((event) => event.eventType),
    [
      "QUOTA_RESERVED",
      "QUOTA_RESERVED",
      "QUOTA_RESERVED",
      "USAGE_SETTLED",
      "USAGE_SETTLED",
      "USAGE_SETTLED",
    ],
  );
  const settledLedgerEvents = report.ledgerEvents.filter(
    (event) => event.eventType === "USAGE_SETTLED",
  );
  assert.deepEqual(
    settledLedgerEvents.map((event) => event.meterType),
    ["MODEL_TOKEN", "TOOL_CALL", "SANDBOX_VCPU_MILLISECOND"],
  );
  assert.equal(
    settledLedgerEvents.every(
      (event) =>
        typeof event.meterKey === "string" &&
        Number.isSafeInteger(event.supplierCostMicros) &&
        event.varianceMicros ===
          event.supplierCostMicros - event.costMicros,
    ),
    true,
  );
  const reconciledQuota = await service.quotaStatus(SERVER_CONTEXT);
  assert.deepEqual(
    reconciledQuota.accounts.map((account) => ({
      quotaScope: account.quotaScope,
      reservedMicros: account.reservedMicros,
      consumedMicros: account.consumedMicros,
    })),
    [
      {
        quotaScope: "PRINCIPAL",
        reservedMicros: 0,
        consumedMicros: 5380,
      },
      {
        quotaScope: "TENANT",
        reservedMicros: 0,
        consumedMicros: 5380,
      },
    ],
  );
});

test("quota release is idempotent and reconciles Tenant and Principal reservations", async () => {
  const { service, mutable } = createHarness();
  const reserved = await service.reserve(SERVER_CONTEXT, {
    idempotencyKey: "idem-c19-release-reserve",
    planRef: MODEL_PLAN,
    traceparent:
      "00-6bf92f3577b34da6a3ce929d0e0e4736-10f067aa0ba902b7-01",
    tracestate: null,
  });
  const request = {
    idempotencyKey: "idem-c19-release",
    reservationId: reserved.reservation.reservationId,
    traceparent: reserved.traceContext.traceparent,
    tracestate: null,
  };
  const released = await service.release(SERVER_CONTEXT, request);
  assert.equal(released.release.state, "RELEASED");
  assert.deepEqual(
    await service.release(SERVER_CONTEXT, {
      ...request,
      traceparent:
        "00-abf92f3577b34da6a3ce929d0e0e4736-60f067aa0ba902b7-01",
      tracestate: "retry=new-hop",
    }),
    released,
  );

  const quota = await service.quotaStatus(SERVER_CONTEXT);
  assert.deepEqual(
    quota.accounts.map((account) => [
      account.quotaScope,
      account.reservedMicros,
      account.consumedMicros,
    ]),
    [
      ["PRINCIPAL", 0, 0],
      ["TENANT", 0, 0],
    ],
  );
  const report = await service.costVarianceReport(SERVER_CONTEXT, {
    fromOccurredAt: "2026-07-26T00:00:00.000Z",
    toOccurredAt: "2026-07-27T00:00:00.000Z",
  });
  assert.deepEqual(
    report.ledgerEvents.map((event) => event.eventType),
    ["QUOTA_RESERVED", "QUOTA_RELEASED"],
  );
  mutable.now = "2026-07-26T13:00:00.000Z";
  await assert.rejects(
    service.settle(SERVER_CONTEXT, {
      idempotencyKey: "idem-c19-release-settle",
      reservationId: reserved.reservation.reservationId,
      receiptRef: MODEL_RECEIPT,
      traceparent: released.traceContext.traceparent,
      tracestate: null,
    }),
    (error) =>
      error instanceof ObservabilityError &&
      error.code === "RESERVATION_NOT_SETTLEABLE",
  );
});

test("concurrent reservations cannot oversell quota and idempotency conflicts fail closed", async () => {
  const { service } = createHarness();
  const request = (index) => ({
    idempotencyKey: `idem-c19-concurrent-${index}`,
    planRef: SANDBOX_PLAN,
    traceparent:
      "00-7bf92f3577b34da6a3ce929d0e0e4736-20f067aa0ba902b7-01",
    tracestate: null,
  });
  const results = await Promise.allSettled([
    service.reserve(SERVER_CONTEXT, request(1)),
    service.reserve(SERVER_CONTEXT, request(2)),
    service.reserve(SERVER_CONTEXT, request(3)),
  ]);
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
  const status = await service.quotaStatus(SERVER_CONTEXT);
  assert.equal(
    status.accounts.find(
      (account) => account.quotaScope === "PRINCIPAL",
    ).deniedCount,
    1,
  );
  assert.equal(
    status.accounts.find(
      (account) => account.quotaScope === "TENANT",
    ).deniedCount,
    0,
  );
  assert.equal(
    status.alerts.some(
      (alert) =>
        alert.code === "C19_QUOTA_DENIAL" &&
        alert.quotaScope === "PRINCIPAL",
    ),
    true,
  );

  await assert.rejects(
    service.reserve(SERVER_CONTEXT, {
      ...request(1),
      planRef: MODEL_PLAN,
    }),
    (error) =>
      error instanceof ObservabilityError &&
      error.code === "IDEMPOTENCY_CONFLICT",
  );
});

test("catalog is frozen to exactly three Synthetic Tenants and rejects duplicate metering evidence", async () => {
  assert.equal(CATALOG.tenantIds().length, 3);
  const { service, mutable } = createHarness();
  const first = await service.reserve(SERVER_CONTEXT, {
    idempotencyKey: "idem-c19-meter-reserve-1",
    planRef: MODEL_PLAN,
    traceparent:
      "00-8bf92f3577b34da6a3ce929d0e0e4736-30f067aa0ba902b7-01",
    tracestate: null,
  });
  const second = await service.reserve(SERVER_CONTEXT, {
    idempotencyKey: "idem-c19-meter-reserve-2",
    planRef: MODEL_PLAN,
    traceparent:
      "00-8bf92f3577b34da6a3ce929d0e0e4736-40f067aa0ba902b7-01",
    tracestate: null,
  });
  mutable.now = "2026-07-26T13:00:00.000Z";
  await service.settle(SERVER_CONTEXT, {
    idempotencyKey: "idem-c19-meter-settle-1",
    reservationId: first.reservation.reservationId,
    receiptRef: MODEL_RECEIPT,
    traceparent: first.traceContext.traceparent,
    tracestate: null,
  });
  await assert.rejects(
    service.settle(SERVER_CONTEXT, {
      idempotencyKey: "idem-c19-meter-settle-2",
      reservationId: second.reservation.reservationId,
      receiptRef: MODEL_RECEIPT,
      traceparent: second.traceContext.traceparent,
      tracestate: null,
    }),
    (error) =>
      error instanceof ObservabilityError &&
      error.code === "DUPLICATE_METER",
  );
});

test("caller cannot inject a Principal outside the C05 identity seam", async () => {
  const { service } = createHarness();
  await assert.rejects(
    service.reserve(
      {
        ...SERVER_CONTEXT,
        principalId:
          "prn_018f0000-0000-7000-8000-000000000299",
      },
      {
        idempotencyKey: "idem-c19-principal-injection",
        planRef: MODEL_PLAN,
        traceparent:
          "00-8bf92f3577b34da6a3ce929d0e0e4736-30f067aa0ba902b7-01",
        tracestate: null,
      },
    ),
    (error) =>
      error instanceof ObservabilityError &&
      error.code === "INVALID_INPUT",
  );
});

test("catalog substitution fails even when the changed document remains structurally valid", () => {
  const changed = structuredClone(catalogDocument);
  changed.rateCards[0].meters[0].unitRateMicros += 1;
  assert.throws(
    () => createSyntheticObservabilityCatalog(changed),
    (error) =>
      error instanceof ObservabilityError &&
      error.code === "INVALID_CATALOG",
  );
});
