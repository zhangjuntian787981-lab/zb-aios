const TENANT_ID =
  /^stn_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const METER_KEY = /^[a-z0-9][a-z0-9._:-]{7,127}$/;
const FIXTURE_REF =
  /^fixture:\/\/c19\/(?:provider|infrastructure)\/[a-z0-9][a-z0-9./_-]{2,255}$/;
const DIMENSIONS = new Set(["MODEL", "TOOL", "SANDBOX"]);
const FROZEN_THRESHOLDS = Object.freeze({
  maxExternalToSupplierAbsoluteVarianceMicros: 0,
  maxExternalToBookedAbsoluteVarianceMicros: 600,
  maxExternalToBookedAbsoluteVarianceBasisPoints: 1100,
});

export class CostReconciliationError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "CostReconciliationError";
    this.code = code;
  }
}

function fail(code, message) {
  throw new CostReconciliationError(code, message);
}

function isPlainObject(value) {
  return (
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    Object.getPrototypeOf(value) === Object.prototype
  );
}

function exactKeys(value, expected, code, label) {
  if (
    !isPlainObject(value) ||
    Object.keys(value).length !== expected.length ||
    expected.some((key) => !Object.hasOwn(value, key))
  ) {
    fail(code, `${label} fields are invalid.`);
  }
}

function canonicalInstant(value, code, label) {
  if (
    typeof value !== "string" ||
    !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value) ||
    Number.isNaN(Date.parse(value)) ||
    new Date(value).toISOString() !== value
  ) {
    fail(code, `${label} is invalid.`);
  }
  return value;
}

function safeNonNegativeInteger(value, code, label) {
  if (!Number.isSafeInteger(value) || value < 0) {
    fail(code, `${label} is invalid.`);
  }
  return value;
}

function validateInternalReport(report) {
  if (
    !isPlainObject(report) ||
    !TENANT_ID.test(report.tenantId ?? "") ||
    !Array.isArray(report.ledgerEvents)
  ) {
    fail("INVALID_LEDGER_REPORT", "Internal C19 cost report is invalid.");
  }
  const fromOccurredAt = canonicalInstant(
    report.fromOccurredAt,
    "INVALID_LEDGER_REPORT",
    "Internal report start",
  );
  const toOccurredAt = canonicalInstant(
    report.toOccurredAt,
    "INVALID_LEDGER_REPORT",
    "Internal report end",
  );
  if (fromOccurredAt >= toOccurredAt) {
    fail("INVALID_LEDGER_REPORT", "Internal report period is invalid.");
  }
  exactKeys(
    report.totals,
    [
      "bookedCostMicros",
      "supplierCostMicros",
      "varianceMicros",
    ],
    "INVALID_LEDGER_REPORT",
    "Internal totals",
  );
  const settlements = report.ledgerEvents.filter(
    (event) => event?.eventType === "USAGE_SETTLED",
  );
  const byMeter = new Map();
  let bookedCostMicros = 0;
  let supplierCostMicros = 0;
  for (const event of settlements) {
    exactKeys(
      event,
      [
        "eventId",
        "tenantId",
        "principalId",
        "eventType",
        "reservationId",
        "taskRef",
        "dimensionType",
        "resourceRef",
        "meterType",
        "unit",
        "quantity",
        "costMicros",
        "rateVersion",
        "receiptRef",
        "meterKey",
        "supplierCostMicros",
        "varianceMicros",
        "traceId",
        "spanId",
        "occurredAt",
      ],
      "INVALID_LEDGER_REPORT",
      "Settled ledger event",
    );
    if (
      event.tenantId !== report.tenantId ||
      !METER_KEY.test(event.meterKey ?? "") ||
      !DIMENSIONS.has(event.dimensionType) ||
      typeof event.resourceRef !== "string" ||
      typeof event.meterType !== "string" ||
      typeof event.unit !== "string" ||
      typeof event.rateVersion !== "string" ||
      !Number.isSafeInteger(event.quantity) ||
      event.quantity < 0 ||
      !Number.isSafeInteger(event.costMicros) ||
      event.costMicros < 0 ||
      !Number.isSafeInteger(event.supplierCostMicros) ||
      event.supplierCostMicros < 0 ||
      event.varianceMicros !==
        event.supplierCostMicros - event.costMicros ||
      canonicalInstant(
        event.occurredAt,
        "INVALID_LEDGER_REPORT",
        "Ledger occurrence",
      ) < fromOccurredAt ||
      event.occurredAt >= toOccurredAt ||
      byMeter.has(event.meterKey)
    ) {
      fail("INVALID_LEDGER_REPORT", "Settled ledger event is invalid.");
    }
    byMeter.set(event.meterKey, event);
    bookedCostMicros += event.costMicros;
    supplierCostMicros += event.supplierCostMicros;
  }
  if (
    settlements.length === 0 ||
    report.totals.bookedCostMicros !== bookedCostMicros ||
    report.totals.supplierCostMicros !== supplierCostMicros ||
    report.totals.varianceMicros !==
      supplierCostMicros - bookedCostMicros
  ) {
    fail("INVALID_LEDGER_REPORT", "Internal totals do not reconcile.");
  }
  return {
    tenantId: report.tenantId,
    fromOccurredAt,
    toOccurredAt,
    settlements,
    byMeter,
    bookedCostMicros,
    supplierCostMicros,
  };
}

function validateBillSet(document) {
  exactKeys(
    document,
    [
      "schemaVersion",
      "phase",
      "dataClassification",
      "billSetId",
      "tenantId",
      "currency",
      "billingPeriod",
      "thresholds",
      "bills",
    ],
    "INVALID_BILL",
    "Synthetic bill set",
  );
  if (
    document.schemaVersion !== "1.0.0" ||
    document.phase !== "P1_SYNTHETIC_ONLY" ||
    document.dataClassification !== "SYNTHETIC" ||
    typeof document.billSetId !== "string" ||
    document.billSetId.length < 8 ||
    document.billSetId.length > 128 ||
    !TENANT_ID.test(document.tenantId ?? "") ||
    document.currency !== "USD_MICROS" ||
    !Array.isArray(document.bills)
  ) {
    fail("INVALID_BILL", "Synthetic bill set is invalid.");
  }
  exactKeys(
    document.billingPeriod,
    ["fromOccurredAt", "toOccurredAt"],
    "INVALID_BILL",
    "Billing period",
  );
  const fromOccurredAt = canonicalInstant(
    document.billingPeriod.fromOccurredAt,
    "INVALID_BILL",
    "Billing period start",
  );
  const toOccurredAt = canonicalInstant(
    document.billingPeriod.toOccurredAt,
    "INVALID_BILL",
    "Billing period end",
  );
  if (fromOccurredAt >= toOccurredAt) {
    fail("INVALID_BILL", "Billing period is invalid.");
  }
  exactKeys(
    document.thresholds,
    [
      "maxExternalToSupplierAbsoluteVarianceMicros",
      "maxExternalToBookedAbsoluteVarianceMicros",
      "maxExternalToBookedAbsoluteVarianceBasisPoints",
    ],
    "INVALID_BILL",
    "Cost thresholds",
  );
  for (const [name, value] of Object.entries(document.thresholds)) {
    safeNonNegativeInteger(value, "INVALID_BILL", name);
  }
  if (
    Object.entries(FROZEN_THRESHOLDS).some(
      ([name, value]) => document.thresholds[name] !== value,
    )
  ) {
    fail("INVALID_BILL", "Cost thresholds are not frozen.");
  }

  const billIds = new Set();
  const lineIds = new Set();
  const meterKeys = new Set();
  const lines = [];
  for (const bill of document.bills) {
    exactKeys(
      bill,
      ["billId", "billClass", "sourceRef", "lines"],
      "INVALID_BILL",
      "Synthetic bill",
    );
    if (
      typeof bill.billId !== "string" ||
      bill.billId.length < 8 ||
      bill.billId.length > 128 ||
      billIds.has(bill.billId) ||
      !["PROVIDER", "INFRASTRUCTURE"].includes(bill.billClass) ||
      !FIXTURE_REF.test(bill.sourceRef ?? "") ||
      !bill.sourceRef.startsWith(
        `fixture://c19/${bill.billClass.toLowerCase()}/`,
      ) ||
      !Array.isArray(bill.lines)
    ) {
      fail("INVALID_BILL", "Synthetic bill is invalid.");
    }
    billIds.add(bill.billId);
    for (const line of bill.lines) {
      exactKeys(
        line,
        [
          "billLineId",
          "meterKey",
          "dimensionType",
          "resourceRef",
          "meterType",
          "unit",
          "quantity",
          "rateVersion",
          "billedCostMicros",
        ],
        "INVALID_BILL",
        "Synthetic bill line",
      );
      const classMatchesDimension =
        (bill.billClass === "PROVIDER" &&
          ["MODEL", "TOOL"].includes(line.dimensionType)) ||
        (bill.billClass === "INFRASTRUCTURE" &&
          line.dimensionType === "SANDBOX");
      if (
        typeof line.billLineId !== "string" ||
        line.billLineId.length < 8 ||
        line.billLineId.length > 128 ||
        lineIds.has(line.billLineId) ||
        !METER_KEY.test(line.meterKey ?? "") ||
        meterKeys.has(line.meterKey) ||
        !classMatchesDimension ||
        typeof line.resourceRef !== "string" ||
        typeof line.meterType !== "string" ||
        typeof line.unit !== "string" ||
        typeof line.rateVersion !== "string"
      ) {
        fail("INVALID_BILL", "Synthetic bill line is invalid.");
      }
      safeNonNegativeInteger(
        line.quantity,
        "INVALID_BILL",
        "Bill quantity",
      );
      safeNonNegativeInteger(
        line.billedCostMicros,
        "INVALID_BILL",
        "Billed cost",
      );
      lineIds.add(line.billLineId);
      meterKeys.add(line.meterKey);
      lines.push({
        billId: bill.billId,
        billClass: bill.billClass,
        sourceRef: bill.sourceRef,
        ...line,
      });
    }
  }
  return {
    document,
    fromOccurredAt,
    toOccurredAt,
    lines,
    providerBillCount: document.bills.filter(
      (bill) => bill.billClass === "PROVIDER",
    ).length,
    infrastructureBillCount: document.bills.filter(
      (bill) => bill.billClass === "INFRASTRUCTURE",
    ).length,
  };
}

function aggregateByBillClass(lineMappings) {
  const groups = new Map();
  for (const line of lineMappings) {
    const prior = groups.get(line.billClass) ?? {
      billClass: line.billClass,
      internalBookedCostMicros: 0,
      internalSupplierCostMicros: 0,
      externalBilledCostMicros: 0,
      externalToSupplierVarianceMicros: 0,
      externalToBookedVarianceMicros: 0,
    };
    prior.internalBookedCostMicros += line.internalBookedCostMicros;
    prior.internalSupplierCostMicros +=
      line.internalSupplierCostMicros;
    prior.externalBilledCostMicros += line.externalBilledCostMicros;
    prior.externalToSupplierVarianceMicros +=
      line.externalToSupplierVarianceMicros;
    prior.externalToBookedVarianceMicros +=
      line.externalToBookedVarianceMicros;
    groups.set(line.billClass, prior);
  }
  return [...groups.values()].sort((left, right) =>
    left.billClass.localeCompare(right.billClass),
  );
}

export function reconcileSyntheticCostBill(costReport, billDocument) {
  const internal = validateInternalReport(costReport);
  const external = validateBillSet(billDocument);
  if (
    external.document.tenantId !== internal.tenantId ||
    external.fromOccurredAt !== internal.fromOccurredAt ||
    external.toOccurredAt !== internal.toOccurredAt
  ) {
    fail("BILL_SCOPE_MISMATCH", "Bill scope does not match the ledger.");
  }

  const matchedMeters = new Set();
  const lineMappings = [];
  for (const line of external.lines) {
    const ledger = internal.byMeter.get(line.meterKey);
    if (!ledger) {
      fail("BILL_LINE_UNMATCHED", "Bill line has no settled ledger row.");
    }
    for (const key of [
      "dimensionType",
      "resourceRef",
      "meterType",
      "unit",
      "quantity",
      "rateVersion",
    ]) {
      if (line[key] !== ledger[key]) {
        fail(
          "BILL_LINE_MISMATCH",
          "Bill line dimensions do not match the ledger.",
        );
      }
    }
    matchedMeters.add(line.meterKey);
    lineMappings.push({
      billId: line.billId,
      billLineId: line.billLineId,
      billClass: line.billClass,
      sourceRef: line.sourceRef,
      tenantId: ledger.tenantId,
      principalId: ledger.principalId,
      taskRef: ledger.taskRef,
      meterKey: ledger.meterKey,
      dimensionType: ledger.dimensionType,
      resourceRef: ledger.resourceRef,
      meterType: ledger.meterType,
      unit: ledger.unit,
      quantity: ledger.quantity,
      rateVersion: ledger.rateVersion,
      internalBookedCostMicros: ledger.costMicros,
      internalSupplierCostMicros: ledger.supplierCostMicros,
      externalBilledCostMicros: line.billedCostMicros,
      externalToSupplierVarianceMicros:
        line.billedCostMicros - ledger.supplierCostMicros,
      externalToBookedVarianceMicros:
        line.billedCostMicros - ledger.costMicros,
    });
  }
  if (
    internal.settlements.some(
      (event) => !matchedMeters.has(event.meterKey),
    )
  ) {
    fail(
      "LEDGER_LINE_UNMATCHED",
      "Settled ledger row has no bill line.",
    );
  }

  lineMappings.sort((left, right) =>
    left.meterKey.localeCompare(right.meterKey),
  );
  const externalBilledCostMicros = lineMappings.reduce(
    (sum, line) => sum + line.externalBilledCostMicros,
    0,
  );
  const externalToSupplierVarianceMicros =
    externalBilledCostMicros - internal.supplierCostMicros;
  const externalToBookedVarianceMicros =
    externalBilledCostMicros - internal.bookedCostMicros;
  const externalToBookedAbsoluteVarianceBasisPoints =
    internal.bookedCostMicros === 0
      ? externalBilledCostMicros === 0
        ? 0
        : Number.POSITIVE_INFINITY
      : Math.round(
          (Math.abs(externalToBookedVarianceMicros) * 10000) /
            internal.bookedCostMicros,
        );
  const thresholds = external.document.thresholds;
  const exceedsSupplier =
    Math.abs(externalToSupplierVarianceMicros) >
    thresholds.maxExternalToSupplierAbsoluteVarianceMicros;
  const exceedsBookedAbsolute =
    Math.abs(externalToBookedVarianceMicros) >
    thresholds.maxExternalToBookedAbsoluteVarianceMicros;
  const exceedsBookedRatio =
    internal.bookedCostMicros === 0
      ? externalBilledCostMicros !== 0
      : Math.abs(externalToBookedVarianceMicros) * 10000 >
        internal.bookedCostMicros *
          thresholds.maxExternalToBookedAbsoluteVarianceBasisPoints;
  if (
    exceedsSupplier ||
    exceedsBookedAbsolute ||
    exceedsBookedRatio
  ) {
    fail(
      "COST_VARIANCE_EXCEEDED",
      "Synthetic bill variance exceeds the frozen threshold.",
    );
  }

  return Object.freeze({
    schemaVersion: "1.0.0",
    acceptanceId: "C19-AC08",
    phase: "P1_SYNTHETIC_ONLY",
    status: "WITHIN_THRESHOLD",
    tenantId: internal.tenantId,
    billSetId: external.document.billSetId,
    currency: external.document.currency,
    billingPeriod: Object.freeze({
      fromOccurredAt: internal.fromOccurredAt,
      toOccurredAt: internal.toOccurredAt,
    }),
    thresholds: Object.freeze({ ...thresholds }),
    counts: Object.freeze({
      providerBillCount: external.providerBillCount,
      infrastructureBillCount: external.infrastructureBillCount,
      billLineCount: external.lines.length,
      settledLedgerLineCount: internal.settlements.length,
      matchedLineCount: matchedMeters.size,
      unmatchedBillLineCount: 0,
      unmatchedLedgerLineCount: 0,
    }),
    totals: Object.freeze({
      internalBookedCostMicros: internal.bookedCostMicros,
      internalSupplierCostMicros: internal.supplierCostMicros,
      externalBilledCostMicros,
      externalToSupplierVarianceMicros,
      externalToBookedVarianceMicros,
      externalToBookedAbsoluteVarianceBasisPoints,
    }),
    byBillClass: aggregateByBillClass(lineMappings).map((row) =>
      Object.freeze(row),
    ),
    lineMappings: lineMappings.map((row) => Object.freeze(row)),
  });
}
