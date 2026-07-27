import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import {
  CostReconciliationError,
  reconcileSyntheticCostBill,
} from "../lib/c19-cost-reconciliation.mjs";
import {
  createMemoryObservabilityStore,
  createObservabilityService,
  createSyntheticObservabilityCatalog,
} from "../lib/c19-observability.mjs";

async function json(path) {
  return JSON.parse(
    await readFile(new URL(path, import.meta.url), "utf8"),
  );
}

const bill = await json(
  "../implementation/p1/c19/synthetic-bill-set.v1.json",
);
const expectedReport = await json(
  "../implementation/p1/c19/synthetic-cost-reconciliation-report.v1.json",
);
const catalog = createSyntheticObservabilityCatalog(
  await json(
    "../implementation/p1/c19/synthetic-observability-catalog.v1.json",
  ),
);
const TENANT =
  "stn_018f0000-0000-7000-8000-000000000010";
const PRINCIPAL =
  "prn_018f0000-0000-7000-8000-000000000001";
const CONTEXT = {
  synthetic: true,
  routeTrustSource: "VERIFIED_ROUTE_DESCRIPTOR",
  tenantId: TENANT,
  identityContextRef:
    "fixture://c19/northstar/identity-context/ava",
};
const TRACEPARENT =
  "00-7bf92f3577b34da6a3ce929d0e0e4736-20f067aa0ba902b7-01";

function createService() {
  let nextId = 100;
  let nextSpan = 0x2000000000000000n;
  const mutable = {
    now: "2026-07-26T11:00:00.000Z",
  };
  const service = createObservabilityService({
    catalog,
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
      async resolveActionIdentity() {
        return {
          tenantId: TENANT,
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
      nextId += 1;
      return `018f0000-0000-7000-8000-${String(nextId).padStart(12, "0")}`;
    },
    spanIdFactory: () => {
      nextSpan += 1n;
      return nextSpan.toString(16);
    },
  });
  return { service, mutable };
}

async function internalCostReport() {
  const { service, mutable } = createService();
  const reservations = [];
  for (const [index, dimension] of [
    "model",
    "tool",
    "sandbox",
  ].entries()) {
    reservations.push(
      await service.reserve(CONTEXT, {
        idempotencyKey: `idem-c19-bill-reserve-${index}`,
        planRef: `fixture://c19/northstar/plans/${dimension}`,
        traceparent: TRACEPARENT,
        tracestate: null,
      }),
    );
  }
  mutable.now = "2026-07-26T13:00:00.000Z";
  for (const [index, dimension] of [
    "model",
    "tool",
    "sandbox",
  ].entries()) {
    await service.settle(CONTEXT, {
      idempotencyKey: `idem-c19-bill-settle-${index}`,
      reservationId:
        reservations[index].reservation.reservationId,
      receiptRef:
        `fixture://c19/northstar/receipts/${dimension}`,
      traceparent: TRACEPARENT,
      tracestate: null,
    });
  }
  return service.costVarianceReport(CONTEXT, {
    fromOccurredAt: "2026-07-26T00:00:00.000Z",
    toOccurredAt: "2026-07-27T00:00:00.000Z",
  });
}

test("independent Provider and infrastructure bills reconcile every settled meter within threshold", async () => {
  const result = reconcileSyntheticCostBill(
    await internalCostReport(),
    bill,
  );

  assert.deepEqual(result, expectedReport);
  assert.equal(result.acceptanceId, "C19-AC08");
  assert.equal(result.status, "WITHIN_THRESHOLD");
  assert.deepEqual(result.counts, {
    providerBillCount: 2,
    infrastructureBillCount: 1,
    billLineCount: 3,
    settledLedgerLineCount: 3,
    matchedLineCount: 3,
    unmatchedBillLineCount: 0,
    unmatchedLedgerLineCount: 0,
  });
  assert.deepEqual(result.totals, {
    internalBookedCostMicros: 5380,
    internalSupplierCostMicros: 4825,
    externalBilledCostMicros: 4825,
    externalToSupplierVarianceMicros: 0,
    externalToBookedVarianceMicros: -555,
    externalToBookedAbsoluteVarianceBasisPoints: 1032,
  });
  assert.deepEqual(
    result.lineMappings.map((line) => [
      line.billClass,
      line.dimensionType,
      line.meterKey,
      line.quantity,
      line.internalBookedCostMicros,
      line.internalSupplierCostMicros,
      line.externalBilledCostMicros,
    ]),
    [
      [
        "PROVIDER",
        "MODEL",
        "meter-northstar-model-2026-07-26",
        65,
        130,
        25,
        25,
      ],
      [
        "INFRASTRUCTURE",
        "SANDBOX",
        "meter-northstar-sandbox-2026-07-26",
        5000,
        5000,
        4800,
        4800,
      ],
      [
        "PROVIDER",
        "TOOL",
        "meter-northstar-tool-2026-07-26",
        1,
        250,
        0,
        0,
      ],
    ],
  );
});

test("unmatched, dimension-drifted and out-of-threshold bills fail closed", async (t) => {
  const internal = await internalCostReport();
  function setModelBookedCost(report, costMicros) {
    const event = report.ledgerEvents.find(
      ({ meterKey }) =>
        meterKey === "meter-northstar-model-2026-07-26",
    );
    const delta = costMicros - event.costMicros;
    event.costMicros = costMicros;
    event.varianceMicros = event.supplierCostMicros - costMicros;
    report.totals.bookedCostMicros += delta;
    report.totals.varianceMicros =
      report.totals.supplierCostMicros -
      report.totals.bookedCostMicros;
  }
  const cases = [
    {
      name: "unmatched external meter",
      code: "BILL_LINE_UNMATCHED",
      mutate(candidate) {
        candidate.bills[0].lines[0].meterKey =
          "meter-northstar-unknown-2026-07-26";
      },
    },
    {
      name: "missing external line",
      code: "LEDGER_LINE_UNMATCHED",
      mutate(candidate) {
        candidate.bills[2].lines = [];
      },
    },
    {
      name: "dimension drift",
      code: "BILL_LINE_MISMATCH",
      mutate(candidate) {
        candidate.bills[0].lines[0].quantity = 66;
      },
    },
    {
      name: "supplier amount exceeds zero tolerance",
      code: "COST_VARIANCE_EXCEEDED",
      mutate(candidate) {
        candidate.bills[0].lines[0].billedCostMicros = 26;
      },
    },
    {
      name: "booked variance exceeds frozen threshold",
      code: "COST_VARIANCE_EXCEEDED",
      mutate(_candidate, internalCandidate) {
        setModelBookedCost(internalCandidate, 180);
      },
    },
    {
      name: "booked variance ratio exceeds frozen threshold",
      code: "COST_VARIANCE_EXCEEDED",
      mutate(_candidate, internalCandidate) {
        setModelBookedCost(internalCandidate, 175);
      },
    },
    {
      name: "caller cannot raise a frozen threshold",
      code: "INVALID_BILL",
      mutate(candidate) {
        candidate.thresholds
          .maxExternalToBookedAbsoluteVarianceMicros = 601;
      },
    },
    {
      name: "bill class and source disagree",
      code: "INVALID_BILL",
      mutate(candidate) {
        candidate.bills[0].sourceRef =
          "fixture://c19/infrastructure/model-local-secure";
      },
    },
    {
      name: "billing period drift",
      code: "BILL_SCOPE_MISMATCH",
      mutate(candidate) {
        candidate.billingPeriod.toOccurredAt =
          "2026-07-28T00:00:00.000Z";
      },
    },
    {
      name: "arbitrary metadata",
      code: "INVALID_BILL",
      mutate(candidate) {
        candidate.metadata = {
          untrusted: "synthetic extension",
        };
      },
    },
  ];

  for (const current of cases) {
    await t.test(current.name, () => {
      const candidate = structuredClone(bill);
      const internalCandidate = structuredClone(internal);
      current.mutate(candidate, internalCandidate);
      assert.throws(
        () =>
          reconcileSyntheticCostBill(
            internalCandidate,
            candidate,
          ),
        (error) =>
          error instanceof CostReconciliationError &&
          error.code === current.code,
      );
    });
  }
});
