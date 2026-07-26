import { createHash } from "node:crypto";

const TRACEPARENT =
  /^00-([0-9a-f]{32})-([0-9a-f]{16})-(00|01)$/;
const TRACE_ID_ZERO = "00000000000000000000000000000000";
const SPAN_ID_ZERO = "0000000000000000";
const SIMPLE_STATE_KEY = /^[a-z][_0-9a-z\-*/]{0,255}$/;
const TENANT_STATE_KEY =
  /^[a-z0-9][_0-9a-z\-*/]{0,240}@[a-z][_0-9a-z\-*/]{0,13}$/;
const TENANT_ID =
  /^stn_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const PRINCIPAL_ID =
  /^prn_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const TASK_REF =
  /^tsk_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const IDEMPOTENCY_KEY = /^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$/;
const OPERATION = /^c(?:14|16|18|19)\.[a-z][a-z0-9.]{1,63}$/;
const ERROR_CODE_BY_OPERATION = Object.freeze({
  "c14.model.route": "MODEL_ROUTE_REJECTED",
  "c16.tool.execute": "TOOL_EXECUTION_REJECTED",
  "c18.audit.append": "AUDIT_REJECTED",
  "c19.usage.settle": "USAGE_SETTLEMENT_REJECTED",
});
const SHA256 = /^sha256:[0-9a-f]{64}$/;
const REFERENCE = /^(?:fixture|model|tool|sandbox):\/\/[a-z0-9][a-z0-9./_-]{2,255}$/;
const SYNTHETIC_CATALOG_SHA256 =
  "sha256:0de84e3f5c3e5bc1a8c22714ba22d274a017d0c8f477236494451015fcd0403d";
const SECRET_LIKE =
  /(?:\b(?:basic|bearer)\s+[a-z0-9._~+/-]{4,}|(?:api[_-]?key|access[_-]?key|client[_-]?secret|password|secret|token)\s*[:=]|sk-[a-z0-9_-]{8,}|gh[pousr]_[a-z0-9]{8,}|-----BEGIN [A-Z ]+PRIVATE KEY-----)/i;
const PROHIBITED_TELEMETRY_FIELDS = new Set([
  "body",
  "content",
  "text",
  "message",
  "raw",
  "prompt",
  "input",
  "output",
  "toolArguments",
  "fileBytes",
  "bytes",
  "secret",
  "token",
  "credential",
  "password",
  "cookie",
  "authorizationHeader",
  "apiKey",
  "accessKey",
  "clientSecret",
  "privateKey",
  "labels",
  "attributes",
  "metadata",
]);

export class ObservabilityError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "ObservabilityError";
    this.code = code;
  }
}

function fail(code, message) {
  throw new ObservabilityError(code, message);
}

function isPlainObject(value) {
  return (
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    Object.getPrototypeOf(value) === Object.prototype
  );
}

function exactKeys(value, expected, label, prohibited = false) {
  if (!isPlainObject(value)) {
    fail("INVALID_INPUT", `${label} must be an object.`);
  }
  const actual = Object.keys(value);
  const unknown = actual.filter((key) => !expected.includes(key));
  if (unknown.length > 0) {
    if (
      prohibited &&
      unknown.some((key) => PROHIBITED_TELEMETRY_FIELDS.has(key))
    ) {
      fail(
        "PROHIBITED_TELEMETRY_FIELD",
        `${label} contains a prohibited telemetry field.`,
      );
    }
    fail("INVALID_INPUT", `${label} has unexpected fields.`);
  }
  if (
    actual.length !== expected.length ||
    expected.some((key) => !Object.hasOwn(value, key))
  ) {
    fail("INVALID_INPUT", `${label} is missing required fields.`);
  }
}

function canonicalInstant(value, label) {
  if (
    typeof value !== "string" ||
    !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value) ||
    Number.isNaN(Date.parse(value)) ||
    new Date(value).toISOString() !== value
  ) {
    fail("INVALID_INPUT", `${label} must be a canonical UTC instant.`);
  }
  return value;
}

function canonicalize(value) {
  if (Array.isArray(value)) {
    return `[${value.map(canonicalize).join(",")}]`;
  }
  if (isPlainObject(value)) {
    return `{${Object.keys(value)
      .sort()
      .map(
        (key) =>
          `${JSON.stringify(key)}:${canonicalize(value[key])}`,
      )
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

function validIdempotencyKey(value) {
  return (
    typeof value === "string" &&
    IDEMPOTENCY_KEY.test(value) &&
    !SECRET_LIKE.test(value)
  );
}

export function observabilitySha256(value) {
  return `sha256:${createHash("sha256")
    .update(canonicalize(value))
    .digest("hex")}`;
}

function clone(value) {
  return structuredClone(value);
}

function parseTracestate(value) {
  if (value === undefined || value === null) return null;
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > 512
  ) {
    fail("INVALID_TRACE_CONTEXT", "tracestate is invalid.");
  }
  const members = value.split(",");
  if (members.length > 32) {
    fail("INVALID_TRACE_CONTEXT", "tracestate is invalid.");
  }
  const keys = new Set();
  const canonical = [];
  for (const rawMember of members) {
    const member = rawMember.replace(/^[\t ]+|[\t ]+$/g, "");
    const separator = member.indexOf("=");
    if (separator < 1 || separator !== member.lastIndexOf("=")) {
      fail("INVALID_TRACE_CONTEXT", "tracestate is invalid.");
    }
    const key = member
      .slice(0, separator)
      .replace(/^[\t ]+|[\t ]+$/g, "");
    const stateValue = member
      .slice(separator + 1)
      .replace(/^[\t ]+|[\t ]+$/g, "");
    if (
      (!SIMPLE_STATE_KEY.test(key) && !TENANT_STATE_KEY.test(key)) ||
      keys.has(key) ||
      stateValue.length === 0 ||
      stateValue.length > 256 ||
      stateValue.endsWith(" ") ||
      SECRET_LIKE.test(stateValue) ||
      !/^[\x20-\x2b\x2d-\x3c\x3e-\x7e]+$/.test(stateValue)
    ) {
      fail("INVALID_TRACE_CONTEXT", "tracestate is invalid.");
    }
    keys.add(key);
    canonical.push(`${key}=${stateValue}`);
  }
  return canonical.join(",");
}

export function parseTraceContext(headers) {
  if (
    !headers ||
    typeof headers !== "object" ||
    Array.isArray(headers) ||
    Object.keys(headers).some(
      (key) => !["traceparent", "tracestate"].includes(key),
    )
  ) {
    fail("INVALID_TRACE_CONTEXT", "Trace Context headers are invalid.");
  }
  const match =
    typeof headers.traceparent === "string"
      ? TRACEPARENT.exec(headers.traceparent)
      : null;
  if (
    !match ||
    match[1] === TRACE_ID_ZERO ||
    match[2] === SPAN_ID_ZERO
  ) {
    fail("INVALID_TRACE_CONTEXT", "traceparent is invalid.");
  }
  const tracestate = parseTracestate(headers.tracestate);
  return Object.freeze({
    version: "00",
    traceId: match[1],
    parentId: match[2],
    traceFlags: match[3],
    sampled: match[3] === "01",
    traceparent: headers.traceparent,
    tracestate,
  });
}

export function propagateTraceContext(parent, childSpanId) {
  const verified = parseTraceContext({
    traceparent: parent?.traceparent,
    ...(parent?.tracestate === null ||
    parent?.tracestate === undefined
      ? {}
      : { tracestate: parent.tracestate }),
  });
  if (
    typeof childSpanId !== "string" ||
    !/^[0-9a-f]{16}$/.test(childSpanId) ||
    childSpanId === SPAN_ID_ZERO
  ) {
    fail("INVALID_TRACE_CONTEXT", "Child span ID is invalid.");
  }
  return Object.freeze({
    traceparent:
      `00-${verified.traceId}-${childSpanId}-${verified.traceFlags}`,
    tracestate: verified.tracestate,
  });
}

function validateCatalogDocument(document) {
  exactKeys(
    document,
    [
      "schemaVersion",
      "catalogVersion",
      "phase",
      "dataClassification",
      "telemetryOperations",
      "rateCards",
      "tenants",
    ],
    "observability catalog",
  );
  if (
    document.schemaVersion !== "1.0.0" ||
    document.catalogVersion !== "c19-synthetic-observability-v1" ||
    document.phase !== "P1_SYNTHETIC_ONLY" ||
    document.dataClassification !== "SYNTHETIC_ONLY" ||
    !Array.isArray(document.telemetryOperations) ||
    !Array.isArray(document.rateCards) ||
    !Array.isArray(document.tenants) ||
    document.tenants.length !== 3
  ) {
    fail("INVALID_CATALOG", "C19 catalog boundary is invalid.");
  }
}

function validateScopeEvidence(value) {
  exactKeys(
    value,
    ["decisionId", "evidenceRef", "policyVersion"],
    "scopeEvidence",
  );
  if (
    typeof value.decisionId !== "string" ||
    value.decisionId.length < 4 ||
    !REFERENCE.test(value.evidenceRef ?? "") ||
    typeof value.policyVersion !== "string" ||
    value.policyVersion.length < 4
  ) {
    fail("INVALID_CATALOG", "Scope evidence is invalid.");
  }
}

export function createSyntheticObservabilityCatalog(document) {
  validateCatalogDocument(document);
  if (observabilitySha256(document) !== SYNTHETIC_CATALOG_SHA256) {
    fail("INVALID_CATALOG", "C19 catalog digest is not frozen.");
  }
  const operations = new Map();
  for (const row of document.telemetryOperations) {
    exactKeys(row, ["operation", "module"], "telemetry operation");
    if (
      !OPERATION.test(row.operation ?? "") ||
      !["C14", "C16", "C18", "C19"].includes(row.module) ||
      operations.has(row.operation)
    ) {
      fail("INVALID_CATALOG", "Telemetry operation is invalid.");
    }
    operations.set(row.operation, Object.freeze(clone(row)));
  }
  if (
    operations.size !== 4 ||
    ![
      "c14.model.route",
      "c16.tool.execute",
      "c18.audit.append",
      "c19.usage.settle",
    ].every((operation) => operations.has(operation))
  ) {
    fail("INVALID_CATALOG", "Telemetry operations are incomplete.");
  }
  const rateCards = new Map();
  for (const rateCard of document.rateCards) {
    exactKeys(
      rateCard,
      ["rateVersion", "effectiveAt", "meters"],
      "rate card",
    );
    canonicalInstant(rateCard.effectiveAt, "rateCard.effectiveAt");
    if (
      typeof rateCard.rateVersion !== "string" ||
      !/^rates-[0-9]{4}-[0-9]{2}-v[1-9][0-9]*$/.test(
        rateCard.rateVersion,
      ) ||
      !Array.isArray(rateCard.meters) ||
      rateCard.meters.length !== 3 ||
      rateCards.has(rateCard.rateVersion)
    ) {
      fail("INVALID_CATALOG", "Rate card is invalid.");
    }
    const meters = new Map();
    for (const meter of rateCard.meters) {
      exactKeys(
        meter,
        ["meterType", "unit", "unitRateMicros"],
        "rate meter",
      );
      if (
        ![
          "MODEL_TOKEN",
          "TOOL_CALL",
          "SANDBOX_VCPU_MILLISECOND",
        ].includes(meter.meterType) ||
        !["TOKEN", "CALL", "VCPU_MILLISECOND"].includes(meter.unit) ||
        !Number.isSafeInteger(meter.unitRateMicros) ||
        meter.unitRateMicros < 0 ||
        meters.has(meter.meterType)
      ) {
        fail("INVALID_CATALOG", "Rate meter is invalid.");
      }
      meters.set(meter.meterType, Object.freeze(clone(meter)));
    }
    const expectedUnits = {
      MODEL_TOKEN: "TOKEN",
      TOOL_CALL: "CALL",
      SANDBOX_VCPU_MILLISECOND: "VCPU_MILLISECOND",
    };
    if (
      Object.entries(expectedUnits).some(
        ([meterType, unit]) => meters.get(meterType)?.unit !== unit,
      )
    ) {
      fail("INVALID_CATALOG", "Rate meter unit is invalid.");
    }
    rateCards.set(
      rateCard.rateVersion,
      Object.freeze({
        rateVersion: rateCard.rateVersion,
        effectiveAt: rateCard.effectiveAt,
        meters,
      }),
    );
  }
  if (rateCards.size === 0) {
    fail("INVALID_CATALOG", "At least one rate card is required.");
  }
  const tenants = new Map();
  const meterKeys = new Set();
  for (const tenant of document.tenants) {
    exactKeys(
      tenant,
      [
        "tenantId",
        "fixtureId",
        "quotaPeriod",
        "quotaLimitMicros",
        "quotaThresholdBasisPoints",
        "principalQuotas",
        "scopeEvidence",
        "plans",
        "receipts",
      ],
      "catalog tenant",
    );
    validateScopeEvidence(tenant.scopeEvidence);
    if (
      !TENANT_ID.test(tenant.tenantId ?? "") ||
      typeof tenant.fixtureId !== "string" ||
      tenant.fixtureId.length < 3 ||
      !/^[0-9]{4}-(?:0[1-9]|1[0-2])$/.test(tenant.quotaPeriod ?? "") ||
      !Number.isSafeInteger(tenant.quotaLimitMicros) ||
      tenant.quotaLimitMicros < 1 ||
      !Number.isSafeInteger(tenant.quotaThresholdBasisPoints) ||
      tenant.quotaThresholdBasisPoints < 1 ||
      tenant.quotaThresholdBasisPoints > 10000 ||
      !Array.isArray(tenant.principalQuotas) ||
      tenant.principalQuotas.length !== 2 ||
      !Array.isArray(tenant.plans) ||
      tenant.plans.length !== 3 ||
      !Array.isArray(tenant.receipts) ||
      tenant.receipts.length !== 3 ||
      tenants.has(tenant.tenantId)
    ) {
      fail("INVALID_CATALOG", "Synthetic Tenant is invalid.");
    }
    const principalQuotas = new Map();
    for (const quota of tenant.principalQuotas) {
      exactKeys(
        quota,
        [
          "principalId",
          "quotaLimitMicros",
          "quotaThresholdBasisPoints",
        ],
        "principal quota",
      );
      if (
        !PRINCIPAL_ID.test(quota.principalId ?? "") ||
        !Number.isSafeInteger(quota.quotaLimitMicros) ||
        quota.quotaLimitMicros < 1 ||
        !Number.isSafeInteger(quota.quotaThresholdBasisPoints) ||
        quota.quotaThresholdBasisPoints < 1 ||
        quota.quotaThresholdBasisPoints > 10000 ||
        principalQuotas.has(quota.principalId)
      ) {
        fail("INVALID_CATALOG", "Principal quota is invalid.");
      }
      principalQuotas.set(
        quota.principalId,
        Object.freeze(clone(quota)),
      );
    }
    const plans = new Map();
    for (const plan of tenant.plans) {
      exactKeys(
        plan,
        [
          "planRef",
          "taskRef",
          "dimensionType",
          "resourceRef",
          "meterType",
          "maxQuantity",
          "rateVersion",
          "sourceModule",
          "sourceEvidenceRef",
          "sourceEvidenceSha256",
          "auditEvidenceRef",
          "auditEvidenceSha256",
        ],
        "usage plan",
      );
      const expected = {
        MODEL: {
          meterType: "MODEL_TOKEN",
          sourceModule: "C14",
          resourcePrefix: "model://",
        },
        TOOL: {
          meterType: "TOOL_CALL",
          sourceModule: "C16",
          resourcePrefix: "tool://",
        },
        SANDBOX: {
          meterType: "SANDBOX_VCPU_MILLISECOND",
          sourceModule: "C19",
          resourcePrefix: "sandbox://",
        },
      }[plan.dimensionType];
      const rate = rateCards
        .get(plan.rateVersion)
        ?.meters.get(plan.meterType);
      if (
        !REFERENCE.test(plan.planRef ?? "") ||
        !TASK_REF.test(plan.taskRef ?? "") ||
        !expected ||
        plan.meterType !== expected.meterType ||
        plan.sourceModule !== expected.sourceModule ||
        !plan.resourceRef?.startsWith(expected.resourcePrefix) ||
        !REFERENCE.test(plan.resourceRef ?? "") ||
        !Number.isSafeInteger(plan.maxQuantity) ||
        plan.maxQuantity < 1 ||
        !rate ||
        !REFERENCE.test(plan.sourceEvidenceRef ?? "") ||
        !SHA256.test(plan.sourceEvidenceSha256 ?? "") ||
        !REFERENCE.test(plan.auditEvidenceRef ?? "") ||
        !SHA256.test(plan.auditEvidenceSha256 ?? "") ||
        plans.has(plan.planRef)
      ) {
        fail("INVALID_CATALOG", "Usage plan is invalid.");
      }
      const reservedCostMicros =
        plan.maxQuantity * rate.unitRateMicros;
      if (!Number.isSafeInteger(reservedCostMicros)) {
        fail("INVALID_CATALOG", "Usage plan cost is unsafe.");
      }
      plans.set(
        plan.planRef,
        Object.freeze({
          ...clone(plan),
          unit: rate.unit,
          unitRateMicros: rate.unitRateMicros,
          reservedCostMicros,
        }),
      );
    }
    if (
      !["MODEL", "TOOL", "SANDBOX"].every((dimensionType) =>
        [...plans.values()].some(
          (plan) => plan.dimensionType === dimensionType,
        ),
      )
    ) {
      fail("INVALID_CATALOG", "Usage plan dimensions are incomplete.");
    }
    const receipts = new Map();
    for (const receipt of tenant.receipts) {
      exactKeys(
        receipt,
        [
          "receiptRef",
          "planRef",
          "meterKey",
          "quantity",
          "supplierCostMicros",
          "occurredAt",
        ],
        "usage receipt",
      );
      const plan = plans.get(receipt.planRef);
      canonicalInstant(receipt.occurredAt, "receipt.occurredAt");
      if (
        !REFERENCE.test(receipt.receiptRef ?? "") ||
        typeof receipt.meterKey !== "string" ||
        !/^[a-z0-9][a-z0-9-]{7,127}$/.test(receipt.meterKey) ||
        !Number.isSafeInteger(receipt.quantity) ||
        receipt.quantity < 0 ||
        !Number.isSafeInteger(receipt.supplierCostMicros) ||
        receipt.supplierCostMicros < 0 ||
        !plan ||
        receipt.quantity > plan.maxQuantity ||
        receipts.has(receipt.receiptRef) ||
        meterKeys.has(receipt.meterKey)
      ) {
        fail("INVALID_CATALOG", "Usage receipt is invalid.");
      }
      const bookedCostMicros =
        receipt.quantity * plan.unitRateMicros;
      if (!Number.isSafeInteger(bookedCostMicros)) {
        fail("INVALID_CATALOG", "Usage receipt cost is unsafe.");
      }
      meterKeys.add(receipt.meterKey);
      receipts.set(
        receipt.receiptRef,
        Object.freeze({
          ...clone(receipt),
          bookedCostMicros,
        }),
      );
    }
    for (const plan of plans.values()) {
      if (plan.sourceEvidenceRef.includes("/upstream/")) continue;
      const receipt = tenant.receipts.find(
        (candidate) => candidate.planRef === plan.planRef,
      );
      const sourceEvidenceSha256 = observabilitySha256({
        schemaVersion: "c19-synthetic-usage-source.v1",
        tenantId: tenant.tenantId,
        planRef: plan.planRef,
        sourceModule: plan.sourceModule,
        sourceEvidenceRef: plan.sourceEvidenceRef,
        resourceRef: plan.resourceRef,
        meterType: plan.meterType,
        receipt,
      });
      const auditEvidenceSha256 = observabilitySha256({
        schemaVersion: "c19-synthetic-usage-audit.v1",
        tenantId: tenant.tenantId,
        planRef: plan.planRef,
        auditEvidenceRef: plan.auditEvidenceRef,
        sourceEvidenceSha256,
      });
      if (
        plan.sourceEvidenceSha256 !== sourceEvidenceSha256 ||
        plan.auditEvidenceSha256 !== auditEvidenceSha256
      ) {
        fail(
          "INVALID_CATALOG",
          "Synthetic usage evidence digest is invalid.",
        );
      }
    }
    tenants.set(
      tenant.tenantId,
      Object.freeze({
        fixtureId: tenant.fixtureId,
        quotaPeriod: tenant.quotaPeriod,
        quotaLimitMicros: tenant.quotaLimitMicros,
        quotaThresholdBasisPoints:
          tenant.quotaThresholdBasisPoints,
        principalQuotas,
        scopeEvidence: Object.freeze(clone(tenant.scopeEvidence)),
        plans,
        receipts,
      }),
    );
  }
  const catalogSha256 = observabilitySha256(document);
  if (!SHA256.test(catalogSha256)) {
    fail("INVALID_CATALOG", "Catalog digest is invalid.");
  }
  return Object.freeze({
    catalogVersion: document.catalogVersion,
    catalogSha256,
    resolveTelemetryOperation(operation) {
      if (!OPERATION.test(operation ?? "")) {
        fail("INVALID_INPUT", "operation is invalid.");
      }
      const row = operations.get(operation);
      if (!row) {
        fail("SYNTHETIC_FIXTURE_MISMATCH", "Operation is not frozen.");
      }
      return clone(row);
    },
    resolveTenant(tenantId) {
      if (!TENANT_ID.test(tenantId ?? "")) {
        fail("INVALID_INPUT", "tenantId is invalid.");
      }
      const tenant = tenants.get(tenantId);
      if (!tenant) {
        fail(
          "SYNTHETIC_FIXTURE_MISMATCH",
          "Synthetic Tenant is not frozen.",
        );
      }
      return {
        fixtureId: tenant.fixtureId,
        quotaPeriod: tenant.quotaPeriod,
        quotaLimitMicros: tenant.quotaLimitMicros,
        quotaThresholdBasisPoints:
          tenant.quotaThresholdBasisPoints,
        scopeEvidence: clone(tenant.scopeEvidence),
      };
    },
    resolvePrincipalQuota(tenantId, principalId) {
      const quota = tenants
        .get(tenantId)
        ?.principalQuotas.get(principalId);
      if (!quota) {
        fail(
          "SYNTHETIC_FIXTURE_MISMATCH",
          "Principal quota is not frozen for this Synthetic Tenant.",
        );
      }
      return clone(quota);
    },
    resolvePlan(tenantId, planRef) {
      const tenant = tenants.get(tenantId);
      const plan = tenant?.plans.get(planRef);
      if (!plan) {
        fail(
          "SYNTHETIC_FIXTURE_MISMATCH",
          "Usage plan is not frozen for this Synthetic Tenant.",
        );
      }
      return clone(plan);
    },
    resolveReceipt(tenantId, receiptRef) {
      const tenant = tenants.get(tenantId);
      const receipt = tenant?.receipts.get(receiptRef);
      if (!receipt) {
        fail(
          "SYNTHETIC_FIXTURE_MISMATCH",
          "Usage receipt is not frozen for this Synthetic Tenant.",
        );
      }
      return clone(receipt);
    },
    tenantIds() {
      return [...tenants.keys()];
    },
  });
}

function validateServerContext(context) {
  exactKeys(
    context,
    [
      "synthetic",
      "routeTrustSource",
      "tenantId",
      "identityContextRef",
    ],
    "trusted server context",
  );
  if (
    context.synthetic !== true ||
    context.routeTrustSource !== "VERIFIED_ROUTE_DESCRIPTOR" ||
    !TENANT_ID.test(context.tenantId ?? "") ||
    !REFERENCE.test(context.identityContextRef ?? "")
  ) {
    fail("UNTRUSTED_ROUTE", "C19 route context is untrusted.");
  }
}

function validateActionIdentity(value, tenantId) {
  const human = value?.humanSubject;
  if (
    !isPlainObject(value) ||
    value.tenantId !== tenantId ||
    value.tenantKind !== "SYNTHETIC" ||
    value.trustSource !==
      "VERIFIED_SESSION_IDENTITY_LINK_AND_WORKLOAD_CONTEXT" ||
    !isPlainObject(human) ||
    !PRINCIPAL_ID.test(human.principalId ?? "") ||
    human.principalType !== "HUMAN" ||
    !Number.isSafeInteger(human.lifecycleVersion) ||
    human.lifecycleVersion < 1 ||
    !Number.isSafeInteger(human.securityEpoch) ||
    human.securityEpoch < 1
  ) {
    fail(
      "PRINCIPAL_SCOPE_VIOLATION",
      "C05 action identity is invalid.",
    );
  }
  return human.principalId;
}

function validateSignalRequest(request) {
  exactKeys(
    request,
    [
      "idempotencyKey",
      "traceparent",
      "tracestate",
      "signalType",
      "operation",
      "taskRef",
      "status",
      "durationMs",
      "errorCode",
    ],
    "telemetry request",
    true,
  );
  if (
    !validIdempotencyKey(request.idempotencyKey) ||
    !TASK_REF.test(request.taskRef ?? "") ||
    !["TRACE", "SPAN", "LOG"].includes(request.signalType) ||
    !["OK", "ERROR"].includes(request.status) ||
    (request.signalType === "LOG"
      ? request.durationMs !== null
      : !Number.isSafeInteger(request.durationMs) ||
        request.durationMs < 0) ||
    (request.status === "OK"
      ? request.errorCode !== null
      : request.errorCode !==
        ERROR_CODE_BY_OPERATION[request.operation])
  ) {
    fail("INVALID_INPUT", "Telemetry request is invalid.");
  }
}

function validateScope(scope, tenant, evidence) {
  exactKeys(
    scope,
    [
      "trustSource",
      "tenantId",
      "tenantKind",
      "lifecycleVersion",
      "correlationId",
      "decisionId",
      "evidenceRef",
      "policyVersion",
    ],
    "verified tenant scope",
  );
  if (
    scope.trustSource !== "C07_VERIFIED_TENANT_SCOPE" ||
    scope.tenantId !== tenant.tenantId ||
    scope.tenantKind !== "SYNTHETIC" ||
    !Number.isSafeInteger(scope.lifecycleVersion) ||
    scope.lifecycleVersion < 1 ||
    typeof scope.correlationId !== "string" ||
    scope.correlationId.length < 1 ||
    scope.correlationId.length > 128 ||
    scope.decisionId !== evidence.decisionId ||
    scope.evidenceRef !== evidence.evidenceRef ||
    scope.policyVersion !== evidence.policyVersion
  ) {
    fail("TENANT_SCOPE_VIOLATION", "C07 Tenant Scope is invalid.");
  }
  return scope;
}

function validateTenantAdmission(tenant, tenantId) {
  if (
    !isPlainObject(tenant) ||
    tenant.tenantId !== tenantId ||
    tenant.tenantKind !== "SYNTHETIC" ||
    !Number.isSafeInteger(tenant.lifecycleVersion) ||
    tenant.lifecycleVersion < 1
  ) {
    fail("TENANT_SCOPE_VIOLATION", "C03 Tenant admission is invalid.");
  }
  return tenant;
}

function generatedReference(prefix, idFactory) {
  const value = idFactory();
  if (
    typeof value !== "string" ||
    !/^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(
      value,
    )
  ) {
    fail("INVALID_CONFIGURATION", "Generated identifier is invalid.");
  }
  return `${prefix}_${value}`;
}

export function createMemoryObservabilityStore() {
  const signalsByTenant = new Map();
  const signalIdempotency = new Map();
  const quotaAccounts = new Map();
  const reservationsByTenant = new Map();
  const quotaIdempotency = new Map();
  const meterKeysByTenant = new Map();
  const usageLedgerByTenant = new Map();
  let serial = Promise.resolve();

  function transaction(work) {
    const result = serial.then(work, work);
    serial = result.catch(() => undefined);
    return result;
  }

  async function appendSignal(scope, command) {
    if (scope.tenantId !== command.signal.tenantId) {
      fail("TENANT_SCOPE_VIOLATION", "Signal scope is invalid.");
    }
    const key = `${scope.tenantId}\u0000${command.idempotencyKey}`;
    const prior = signalIdempotency.get(key);
    if (prior) {
      if (prior.requestHash !== command.requestHash) {
        fail(
          "IDEMPOTENCY_CONFLICT",
          "Idempotency key was reused with another request.",
        );
      }
      return { ...clone(prior.result), duplicate: true };
    }
    const rows = signalsByTenant.get(scope.tenantId) ?? [];
    const signal = Object.freeze(clone(command.signal));
    rows.push(signal);
    signalsByTenant.set(scope.tenantId, rows);
    const result = Object.freeze({
      signal: clone(signal),
      traceContext: clone(command.traceContext),
      metricLabels: clone(command.metricLabels),
      duplicate: false,
    });
    signalIdempotency.set(key, {
      requestHash: command.requestHash,
      result,
    });
    return clone(result);
  }

  async function querySignals(scope, range) {
    return (signalsByTenant.get(scope.tenantId) ?? [])
      .filter(
        (row) =>
          row.occurredAt >= range.fromOccurredAt &&
          row.occurredAt < range.toOccurredAt,
      )
      .map(clone);
  }

  async function reserve(scope, command) {
    return transaction(() => {
      const key =
        `${scope.tenantId}\u0000RESERVE\u0000${command.idempotencyKey}`;
      const prior = quotaIdempotency.get(key);
      if (prior) {
        if (prior.requestHash !== command.requestHash) {
          fail(
            "IDEMPOTENCY_CONFLICT",
            "Idempotency key was reused with another request.",
          );
        }
        return { ...clone(prior.result), duplicate: true };
      }
      const accounts = command.quotaAccounts.map((definition) => {
        const accountKey =
          `${scope.tenantId}\u0000${definition.quotaScope}` +
          `\u0000${definition.quotaSubjectId}` +
          `\u0000${command.quotaPeriod}`;
        let account = quotaAccounts.get(accountKey);
        if (!account) {
          account = {
            tenantId: scope.tenantId,
            principalId: definition.principalId,
            quotaScope: definition.quotaScope,
            quotaSubjectId: definition.quotaSubjectId,
            quotaPeriod: command.quotaPeriod,
            quotaLimitMicros: definition.quotaLimitMicros,
            quotaThresholdBasisPoints:
              definition.quotaThresholdBasisPoints,
            reservedMicros: 0,
            consumedMicros: 0,
            deniedCount: 0,
          };
          quotaAccounts.set(accountKey, account);
        }
        if (
          account.quotaLimitMicros !== definition.quotaLimitMicros ||
          account.quotaThresholdBasisPoints !==
            definition.quotaThresholdBasisPoints
        ) {
          fail("QUOTA_CONFIGURATION_MISMATCH", "Quota configuration changed.");
        }
        return account;
      });
      const denied = accounts.filter(
        (account) =>
          account.reservedMicros +
            account.consumedMicros +
            command.reservation.reservedCostMicros >
          account.quotaLimitMicros,
      );
      if (denied.length > 0) {
        for (const account of denied) account.deniedCount += 1;
        return {
          denied: true,
          deniedScopes: denied.map((account) => account.quotaScope),
          duplicate: false,
        };
      }
      const tenantReservations =
        reservationsByTenant.get(scope.tenantId) ?? new Map();
      if (tenantReservations.has(command.reservation.reservationId)) {
        fail("IDEMPOTENCY_CONFLICT", "Reservation identifier exists.");
      }
      for (const account of accounts) {
        account.reservedMicros +=
          command.reservation.reservedCostMicros;
      }
      tenantReservations.set(
        command.reservation.reservationId,
        clone(command.reservation),
      );
      reservationsByTenant.set(scope.tenantId, tenantReservations);
      const ledger = usageLedgerByTenant.get(scope.tenantId) ?? [];
      ledger.push(Object.freeze(clone(command.ledgerEvent)));
      usageLedgerByTenant.set(scope.tenantId, ledger);
      const result = Object.freeze({
        reservation: clone(command.reservation),
        traceContext: clone(command.traceContext),
        duplicate: false,
      });
      quotaIdempotency.set(key, {
        requestHash: command.requestHash,
        result,
      });
      return clone(result);
    });
  }

  async function release(scope, command) {
    return transaction(() => {
      const key =
        `${scope.tenantId}\u0000RELEASE\u0000${command.idempotencyKey}`;
      const prior = quotaIdempotency.get(key);
      if (prior) {
        if (prior.requestHash !== command.requestHash) {
          fail(
            "IDEMPOTENCY_CONFLICT",
            "Idempotency key was reused with another request.",
          );
        }
        return clone(prior.result);
      }
      const reservations = reservationsByTenant.get(scope.tenantId);
      const reservation = reservations?.get(
        command.release.reservationId,
      );
      if (!reservation || reservation.state !== "RESERVED") {
        fail(
          "RESERVATION_NOT_RELEASABLE",
          "Reservation is not releasable.",
        );
      }
      if (
        reservation.principalId !== command.release.principalId ||
        command.release.releasedAt < reservation.createdAt
      ) {
        fail(
          "SYNTHETIC_FIXTURE_MISMATCH",
          "Release does not match its reservation.",
        );
      }
      const accounts = [
        ["TENANT", scope.tenantId],
        ["PRINCIPAL", reservation.principalId],
      ].map(([quotaScope, quotaSubjectId]) =>
        quotaAccounts.get(
          `${scope.tenantId}\u0000${quotaScope}` +
            `\u0000${quotaSubjectId}` +
            `\u0000${reservation.quotaPeriod}`,
        ),
      );
      if (accounts.some((account) => !account)) {
        fail(
          "RESERVATION_NOT_RELEASABLE",
          "Quota account is missing.",
        );
      }
      for (const account of accounts) {
        account.reservedMicros -= reservation.reservedCostMicros;
      }
      const release = {
        ...clone(reservation),
        state: "RELEASED",
        releasedAt: command.release.releasedAt,
      };
      reservations.set(reservation.reservationId, release);
      const event = Object.freeze({
        eventId: command.release.eventId,
        tenantId: scope.tenantId,
        principalId: reservation.principalId,
        eventType: "QUOTA_RELEASED",
        reservationId: reservation.reservationId,
        taskRef: reservation.taskRef,
        dimensionType: reservation.dimensionType,
        resourceRef: reservation.resourceRef,
        meterType: reservation.meterType,
        unit: reservation.unit,
        quantity: reservation.maxQuantity,
        costMicros: reservation.reservedCostMicros,
        rateVersion: reservation.rateVersion,
        receiptRef: null,
        meterKey: null,
        supplierCostMicros: null,
        varianceMicros: null,
        traceId: command.release.traceId,
        spanId: command.release.spanId,
        occurredAt: command.release.releasedAt,
      });
      const ledger = usageLedgerByTenant.get(scope.tenantId) ?? [];
      ledger.push(event);
      usageLedgerByTenant.set(scope.tenantId, ledger);
      const result = Object.freeze({
        release: clone(release),
        traceContext: clone(command.traceContext),
      });
      quotaIdempotency.set(key, {
        requestHash: command.requestHash,
        result,
      });
      return clone(result);
    });
  }

  async function settle(scope, command) {
    return transaction(() => {
      const key =
        `${scope.tenantId}\u0000SETTLE\u0000${command.idempotencyKey}`;
      const prior = quotaIdempotency.get(key);
      if (prior) {
        if (prior.requestHash !== command.requestHash) {
          fail(
            "IDEMPOTENCY_CONFLICT",
            "Idempotency key was reused with another request.",
          );
        }
        return { ...clone(prior.result), duplicate: true };
      }
      const reservations = reservationsByTenant.get(scope.tenantId);
      const reservation = reservations?.get(
        command.settlement.reservationId,
      );
      if (!reservation || reservation.state !== "RESERVED") {
        fail(
          "RESERVATION_NOT_SETTLEABLE",
          "Reservation is not settleable.",
        );
      }
      if (
        reservation.principalId !== command.settlement.principalId ||
        reservation.planRef !== command.settlement.planRef ||
        command.settlement.quantity > reservation.maxQuantity ||
        command.settlement.bookedCostMicros >
          reservation.reservedCostMicros ||
        command.settlement.occurredAt < reservation.createdAt ||
        command.settlement.settledAt <
          command.settlement.occurredAt
      ) {
        fail(
          "SYNTHETIC_FIXTURE_MISMATCH",
          "Receipt does not match its reservation.",
        );
      }
      const meterKeys =
        meterKeysByTenant.get(scope.tenantId) ?? new Set();
      if (meterKeys.has(command.settlement.meterKey)) {
        fail("DUPLICATE_METER", "Meter evidence was already settled.");
      }
      const accounts = [
        ["TENANT", scope.tenantId],
        ["PRINCIPAL", reservation.principalId],
      ].map(([quotaScope, quotaSubjectId]) =>
        quotaAccounts.get(
          `${scope.tenantId}\u0000${quotaScope}` +
            `\u0000${quotaSubjectId}` +
            `\u0000${reservation.quotaPeriod}`,
        ),
      );
      if (accounts.some((account) => !account)) {
        fail(
          "RESERVATION_NOT_SETTLEABLE",
          "Quota account is missing.",
        );
      }
      for (const account of accounts) {
        account.reservedMicros -= reservation.reservedCostMicros;
        account.consumedMicros +=
          command.settlement.bookedCostMicros;
      }
      const settlement = {
        ...clone(reservation),
        ...clone(command.settlement),
        state: "SETTLED",
      };
      reservations.set(reservation.reservationId, settlement);
      meterKeys.add(command.settlement.meterKey);
      meterKeysByTenant.set(scope.tenantId, meterKeys);
      const ledger = usageLedgerByTenant.get(scope.tenantId) ?? [];
      ledger.push(Object.freeze(clone(command.ledgerEvent)));
      usageLedgerByTenant.set(scope.tenantId, ledger);
      const result = Object.freeze({
        settlement: clone(settlement),
        traceContext: clone(command.traceContext),
        duplicate: false,
      });
      quotaIdempotency.set(key, {
        requestHash: command.requestHash,
        result,
      });
      return clone(result);
    });
  }

  async function queryUsage(scope, range) {
    const ledgerEvents = (
      usageLedgerByTenant.get(scope.tenantId) ?? []
    ).filter(
      (event) =>
        event.occurredAt >= range.fromOccurredAt &&
        event.occurredAt < range.toOccurredAt,
    );
    const settlements = ledgerEvents
      .filter((event) => event.eventType === "USAGE_SETTLED")
      .map((event) => ({
        tenantId: event.tenantId,
        principalId: event.principalId,
        taskRef: event.taskRef,
        dimensionType: event.dimensionType,
        resourceRef: event.resourceRef,
        meterType: event.meterType,
        unit: event.unit,
        rateVersion: event.rateVersion,
        quantity: event.quantity,
        bookedCostMicros: event.costMicros,
        supplierCostMicros: event.supplierCostMicros,
        varianceMicros: event.varianceMicros,
      }));
    return {
      ledgerEvents: ledgerEvents.map(clone),
      settlements: settlements.map(clone),
    };
  }

  async function queryQuota(scope, query) {
    return [...quotaAccounts.values()]
      .filter(
        (account) =>
          account.tenantId === scope.tenantId &&
          account.quotaPeriod === query.quotaPeriod &&
          (account.quotaScope === "TENANT" ||
            account.principalId === query.principalId),
      )
      .map(clone);
  }

  return Object.freeze({
    appendSignal,
    querySignals,
    reserve,
    release,
    settle,
    queryUsage,
    queryQuota,
  });
}

function validateServiceDependencies(dependencies) {
  if (
    typeof dependencies?.tenantRegistry?.admitNewRequest !== "function" ||
    typeof dependencies?.catalog?.resolveTenant !== "function" ||
    typeof dependencies?.catalog?.resolvePrincipalQuota !== "function" ||
    typeof dependencies?.catalog?.resolveTelemetryOperation !== "function" ||
    typeof dependencies?.catalog?.resolvePlan !== "function" ||
    typeof dependencies?.catalog?.resolveReceipt !== "function" ||
    typeof dependencies?.store?.appendSignal !== "function" ||
    typeof dependencies?.store?.querySignals !== "function" ||
    typeof dependencies?.store?.reserve !== "function" ||
    typeof dependencies?.store?.release !== "function" ||
    typeof dependencies?.store?.settle !== "function" ||
    typeof dependencies?.store?.queryUsage !== "function" ||
    typeof dependencies?.store?.queryQuota !== "function" ||
    typeof dependencies?.principalResolver?.resolveActionIdentity !==
      "function" ||
    typeof dependencies?.tenantScopeFactory !== "function" ||
    typeof dependencies?.clock !== "function" ||
    typeof dependencies?.idFactory !== "function" ||
    typeof dependencies?.spanIdFactory !== "function"
  ) {
    fail("INVALID_CONFIGURATION", "C19 dependencies are incomplete.");
  }
}

function validateReserveRequest(request) {
  exactKeys(
    request,
    [
      "idempotencyKey",
      "planRef",
      "traceparent",
      "tracestate",
    ],
    "quota reservation request",
    true,
  );
  if (
    !validIdempotencyKey(request.idempotencyKey) ||
    !REFERENCE.test(request.planRef ?? "")
  ) {
    fail("INVALID_INPUT", "Quota reservation request is invalid.");
  }
}

function validateSettleRequest(request) {
  exactKeys(
    request,
    [
      "idempotencyKey",
      "reservationId",
      "receiptRef",
      "traceparent",
      "tracestate",
    ],
    "usage settlement request",
    true,
  );
  if (
    !validIdempotencyKey(request.idempotencyKey) ||
    !/^qrs_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(
      request.reservationId ?? "",
    ) ||
    !REFERENCE.test(request.receiptRef ?? "")
  ) {
    fail("INVALID_INPUT", "Usage settlement request is invalid.");
  }
}

function validateReleaseRequest(request) {
  exactKeys(
    request,
    [
      "idempotencyKey",
      "reservationId",
      "traceparent",
      "tracestate",
    ],
    "quota release request",
    true,
  );
  if (
    !validIdempotencyKey(request.idempotencyKey) ||
    !/^qrs_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(
      request.reservationId ?? "",
    )
  ) {
    fail("INVALID_INPUT", "Quota release request is invalid.");
  }
}

function childTraceContext(request, spanIdFactory) {
  const parent = parseTraceContext({
    traceparent: request.traceparent,
    ...(request.tracestate === null
      ? {}
      : { tracestate: request.tracestate }),
  });
  const spanId = spanIdFactory();
  return {
    parent,
    spanId,
    traceContext: propagateTraceContext(parent, spanId),
  };
}

function reportRange(request, label) {
  exactKeys(
    request,
    ["fromOccurredAt", "toOccurredAt"],
    `${label} request`,
  );
  const fromOccurredAt = canonicalInstant(
    request.fromOccurredAt,
    "fromOccurredAt",
  );
  const toOccurredAt = canonicalInstant(
    request.toOccurredAt,
    "toOccurredAt",
  );
  if (fromOccurredAt >= toOccurredAt) {
    fail("INVALID_INPUT", `${label} range is invalid.`);
  }
  return { fromOccurredAt, toOccurredAt };
}

function costSummary(rows, keyName) {
  const groups = new Map();
  for (const row of rows) {
    const key = row[keyName];
    const prior = groups.get(key) ?? {
      [keyName]: key,
      bookedCostMicros: 0,
      supplierCostMicros: 0,
      varianceMicros: 0,
    };
    prior.bookedCostMicros += row.bookedCostMicros;
    prior.supplierCostMicros += row.supplierCostMicros;
    prior.varianceMicros += row.varianceMicros;
    groups.set(key, prior);
  }
  return [...groups.values()].sort((left, right) =>
    left[keyName].localeCompare(right[keyName]),
  );
}

function dimensionSummary(rows, dimensionType) {
  const selected = rows.filter(
    (row) => row.dimensionType === dimensionType,
  );
  const groups = new Map();
  for (const row of selected) {
    const key = `${row.resourceRef}\u0000${row.rateVersion}`;
    const prior = groups.get(key) ?? {
      dimensionType,
      resourceRef: row.resourceRef,
      unit: row.unit,
      rateVersion: row.rateVersion,
      quantity: 0,
      bookedCostMicros: 0,
      supplierCostMicros: 0,
      varianceMicros: 0,
    };
    prior.quantity += row.quantity;
    prior.bookedCostMicros += row.bookedCostMicros;
    prior.supplierCostMicros += row.supplierCostMicros;
    prior.varianceMicros += row.varianceMicros;
    groups.set(key, prior);
  }
  return [...groups.values()].sort((left, right) =>
    `${left.resourceRef}\u0000${left.rateVersion}`.localeCompare(
      `${right.resourceRef}\u0000${right.rateVersion}`,
    ),
  );
}

export function createObservabilityService({
  tenantRegistry,
  catalog,
  store,
  tenantScopeFactory,
  principalResolver,
  clock = () => new Date().toISOString(),
  idFactory,
  spanIdFactory,
}) {
  const dependencies = {
    tenantRegistry,
    catalog,
    store,
    tenantScopeFactory,
    principalResolver,
    clock,
    idFactory,
    spanIdFactory,
  };
  validateServiceDependencies(dependencies);

  async function verifiedContext(serverContext, correlationId) {
    validateServerContext(serverContext);
    const frozenTenant = catalog.resolveTenant(serverContext.tenantId);
    const tenant = validateTenantAdmission(
      await tenantRegistry.admitNewRequest({
        tenantId: serverContext.tenantId,
        expectedTenantKind: "SYNTHETIC",
      }),
      serverContext.tenantId,
    );
    const scope = validateScope(
      tenantScopeFactory({
        tenant,
        scopeEvidence: frozenTenant.scopeEvidence,
        correlationId,
      }),
      tenant,
      frozenTenant.scopeEvidence,
    );
    const principalId = validateActionIdentity(
      await principalResolver.resolveActionIdentity({
        tenantId: serverContext.tenantId,
        identityContextRef: serverContext.identityContextRef,
      }),
      serverContext.tenantId,
    );
    catalog.resolvePrincipalQuota(serverContext.tenantId, principalId);
    return { scope, principalId };
  }

  async function recordSignal(serverContext, request) {
    validateServerContext(serverContext);
    validateSignalRequest(request);
    const operation = catalog.resolveTelemetryOperation(request.operation);
    const { parent, spanId, traceContext } = childTraceContext(
      request,
      spanIdFactory,
    );
    const occurredAt = canonicalInstant(clock(), "clock");
    const { scope, principalId } = await verifiedContext(
      serverContext,
      parent.traceId,
    );
    const signal = Object.freeze({
      signalId: generatedReference("sig", idFactory),
      tenantId: serverContext.tenantId,
      principalId,
      taskRef: request.taskRef,
      traceId: parent.traceId,
      spanId,
      parentSpanId: parent.parentId,
      module: operation.module,
      operation: operation.operation,
      signalType: request.signalType,
      status: request.status,
      durationMs: request.durationMs,
      errorCode: request.errorCode,
      occurredAt,
    });
    const metricLabels = Object.freeze({
      module: signal.module,
      operation: signal.operation,
      signal_type: signal.signalType,
      status: signal.status,
      error_code: signal.errorCode ?? "NONE",
    });
    return store.appendSignal(scope, {
      idempotencyKey: request.idempotencyKey,
      requestHash: observabilitySha256({
        tenantId: serverContext.tenantId,
        principalId,
        taskRef: request.taskRef,
        traceparent: request.traceparent,
        tracestate: request.tracestate,
        module: signal.module,
        operation: signal.operation,
        signalType: signal.signalType,
        status: signal.status,
        durationMs: signal.durationMs,
        errorCode: signal.errorCode,
      }),
      signal,
      traceContext,
      metricLabels,
    });
  }

  async function telemetryReport(serverContext, request) {
    const { fromOccurredAt, toOccurredAt } = reportRange(
      request,
      "telemetry report",
    );
    const { scope } = await verifiedContext(
      serverContext,
      "c19-telemetry-report",
    );
    const records = await store.querySignals(scope, {
      fromOccurredAt,
      toOccurredAt,
    });
    const durations = records
      .map((row) => row.durationMs)
      .filter((value) => value !== null);
    const errors = records.filter((row) => row.status === "ERROR").length;
    return Object.freeze({
      tenantId: serverContext.tenantId,
      fromOccurredAt,
      toOccurredAt,
      traceCount: new Set(records.map((row) => row.traceId)).size,
      sli: Object.freeze({
        totalSignals: records.length,
        errorSignals: errors,
        successRatio:
          records.length === 0 ? null : (records.length - errors) / records.length,
        durationCount: durations.length,
        totalDurationMs: durations.reduce((sum, value) => sum + value, 0),
        maxDurationMs: durations.length === 0 ? null : Math.max(...durations),
      }),
      records: records.map((row) => Object.freeze(clone(row))),
    });
  }

  async function reserve(serverContext, request) {
    validateServerContext(serverContext);
    validateReserveRequest(request);
    const tenantConfig = catalog.resolveTenant(serverContext.tenantId);
    const plan = catalog.resolvePlan(
      serverContext.tenantId,
      request.planRef,
    );
    const { parent, spanId, traceContext } = childTraceContext(
      request,
      spanIdFactory,
    );
    const createdAt = canonicalInstant(clock(), "clock");
    const { scope, principalId } = await verifiedContext(
      serverContext,
      parent.traceId,
    );
    const principalQuota = catalog.resolvePrincipalQuota(
      serverContext.tenantId,
      principalId,
    );
    const reservationId = generatedReference("qrs", idFactory);
    const reservation = Object.freeze({
      reservationId,
      tenantId: serverContext.tenantId,
      principalId,
      planRef: plan.planRef,
      taskRef: plan.taskRef,
      dimensionType: plan.dimensionType,
      resourceRef: plan.resourceRef,
      meterType: plan.meterType,
      unit: plan.unit,
      maxQuantity: plan.maxQuantity,
      rateVersion: plan.rateVersion,
      unitRateMicros: plan.unitRateMicros,
      reservedCostMicros: plan.reservedCostMicros,
      quotaPeriod: tenantConfig.quotaPeriod,
      catalogVersion: catalog.catalogVersion,
      catalogSha256: catalog.catalogSha256,
      traceId: parent.traceId,
      spanId,
      parentSpanId: parent.parentId,
      inputTraceparent: request.traceparent,
      state: "RESERVED",
      createdAt,
    });
    const ledgerEvent = Object.freeze({
      eventId: generatedReference("ule", idFactory),
      tenantId: serverContext.tenantId,
      principalId,
      eventType: "QUOTA_RESERVED",
      reservationId,
      taskRef: plan.taskRef,
      dimensionType: plan.dimensionType,
      resourceRef: plan.resourceRef,
      meterType: plan.meterType,
      unit: plan.unit,
      quantity: plan.maxQuantity,
      costMicros: plan.reservedCostMicros,
      rateVersion: plan.rateVersion,
      receiptRef: null,
      meterKey: null,
      supplierCostMicros: null,
      varianceMicros: null,
      traceId: parent.traceId,
      spanId,
      occurredAt: createdAt,
    });
    const result = await store.reserve(scope, {
      idempotencyKey: request.idempotencyKey,
      requestHash: observabilitySha256({
        tenantId: serverContext.tenantId,
        principalId,
        planRef: request.planRef,
      }),
      quotaPeriod: tenantConfig.quotaPeriod,
      quotaAccounts: [
        {
          quotaScope: "TENANT",
          quotaSubjectId: serverContext.tenantId,
          principalId: null,
          quotaLimitMicros: tenantConfig.quotaLimitMicros,
          quotaThresholdBasisPoints:
            tenantConfig.quotaThresholdBasisPoints,
        },
        {
          quotaScope: "PRINCIPAL",
          quotaSubjectId: principalId,
          principalId,
          quotaLimitMicros: principalQuota.quotaLimitMicros,
          quotaThresholdBasisPoints:
            principalQuota.quotaThresholdBasisPoints,
        },
      ],
      reservation,
      ledgerEvent,
      traceContext,
    });
    if (result.denied === true) {
      fail("QUOTA_EXCEEDED", "Synthetic quota is exceeded.");
    }
    return result;
  }

  async function settle(serverContext, request) {
    validateServerContext(serverContext);
    validateSettleRequest(request);
    const receipt = catalog.resolveReceipt(
      serverContext.tenantId,
      request.receiptRef,
    );
    const plan = catalog.resolvePlan(
      serverContext.tenantId,
      receipt.planRef,
    );
    const { parent, spanId, traceContext } = childTraceContext(
      request,
      spanIdFactory,
    );
    const createdAt = canonicalInstant(clock(), "clock");
    if (createdAt < receipt.occurredAt) {
      fail(
        "INVALID_CLOCK",
        "Settlement time precedes the frozen usage receipt.",
      );
    }
    const { scope, principalId } = await verifiedContext(
      serverContext,
      parent.traceId,
    );
    const settlement = Object.freeze({
      reservationId: request.reservationId,
      tenantId: serverContext.tenantId,
      principalId,
      planRef: plan.planRef,
      taskRef: plan.taskRef,
      dimensionType: plan.dimensionType,
      resourceRef: plan.resourceRef,
      meterType: plan.meterType,
      unit: plan.unit,
      rateVersion: plan.rateVersion,
      unitRateMicros: plan.unitRateMicros,
      receiptRef: receipt.receiptRef,
      meterKey: receipt.meterKey,
      quantity: receipt.quantity,
      bookedCostMicros: receipt.bookedCostMicros,
      supplierCostMicros: receipt.supplierCostMicros,
      varianceMicros:
        receipt.supplierCostMicros - receipt.bookedCostMicros,
      sourceModule: plan.sourceModule,
      sourceEvidenceRef: plan.sourceEvidenceRef,
      sourceEvidenceSha256: plan.sourceEvidenceSha256,
      auditEvidenceRef: plan.auditEvidenceRef,
      auditEvidenceSha256: plan.auditEvidenceSha256,
      traceId: parent.traceId,
      spanId,
      parentSpanId: parent.parentId,
      inputTraceparent: request.traceparent,
      occurredAt: receipt.occurredAt,
      settledAt: createdAt,
    });
    const ledgerEvent = Object.freeze({
      eventId: generatedReference("ule", idFactory),
      tenantId: serverContext.tenantId,
      principalId,
      eventType: "USAGE_SETTLED",
      reservationId: request.reservationId,
      taskRef: plan.taskRef,
      dimensionType: plan.dimensionType,
      resourceRef: plan.resourceRef,
      meterType: plan.meterType,
      unit: plan.unit,
      quantity: receipt.quantity,
      costMicros: receipt.bookedCostMicros,
      rateVersion: plan.rateVersion,
      receiptRef: receipt.receiptRef,
      meterKey: receipt.meterKey,
      supplierCostMicros: receipt.supplierCostMicros,
      varianceMicros:
        receipt.supplierCostMicros - receipt.bookedCostMicros,
      traceId: parent.traceId,
      spanId,
      occurredAt: receipt.occurredAt,
    });
    return store.settle(scope, {
      idempotencyKey: request.idempotencyKey,
      requestHash: observabilitySha256({
        tenantId: serverContext.tenantId,
        principalId,
        reservationId: request.reservationId,
        receiptRef: request.receiptRef,
      }),
      settlement,
      ledgerEvent,
      traceContext,
    });
  }

  async function release(serverContext, request) {
    validateServerContext(serverContext);
    validateReleaseRequest(request);
    const { parent, spanId, traceContext } = childTraceContext(
      request,
      spanIdFactory,
    );
    const releasedAt = canonicalInstant(clock(), "clock");
    const { scope, principalId } = await verifiedContext(
      serverContext,
      parent.traceId,
    );
    return store.release(scope, {
      idempotencyKey: request.idempotencyKey,
      requestHash: observabilitySha256({
        tenantId: serverContext.tenantId,
        principalId,
        reservationId: request.reservationId,
      }),
      release: {
        eventId: generatedReference("ule", idFactory),
        reservationId: request.reservationId,
        principalId,
        traceId: parent.traceId,
        spanId,
        releasedAt,
      },
      traceContext,
    });
  }

  async function costVarianceReport(serverContext, request) {
    const range = reportRange(request, "cost variance report");
    const { scope } = await verifiedContext(
      serverContext,
      "c19-cost-report",
    );
    const usage = await store.queryUsage(scope, range);
    const totals = costSummary(usage.settlements, "tenantId")[0] ?? {
      bookedCostMicros: 0,
      supplierCostMicros: 0,
      varianceMicros: 0,
    };
    delete totals.tenantId;
    return Object.freeze({
      tenantId: serverContext.tenantId,
      ...range,
      totals: Object.freeze(totals),
      byTask: costSummary(usage.settlements, "taskRef"),
      byPrincipal: costSummary(
        usage.settlements,
        "principalId",
      ),
      byModel: dimensionSummary(usage.settlements, "MODEL"),
      byTool: dimensionSummary(usage.settlements, "TOOL"),
      bySandbox: dimensionSummary(usage.settlements, "SANDBOX"),
      ledgerEvents: usage.ledgerEvents.map((event) =>
        Object.freeze(clone(event)),
      ),
    });
  }

  async function quotaStatus(serverContext) {
    validateServerContext(serverContext);
    const tenant = catalog.resolveTenant(serverContext.tenantId);
    const { scope, principalId } = await verifiedContext(
      serverContext,
      "c19-quota-status",
    );
    const accounts = await store.queryQuota(scope, {
      quotaPeriod: tenant.quotaPeriod,
      principalId,
    });
    const normalized = accounts
      .map((account) => {
        const usedMicros =
          account.reservedMicros + account.consumedMicros;
        return {
          ...clone(account),
          utilizationRatio:
            usedMicros / account.quotaLimitMicros,
        };
      })
      .sort((left, right) =>
        left.quotaScope.localeCompare(right.quotaScope),
      );
    const alerts = normalized.flatMap((account) => {
      const rows = [];
      if (
        account.utilizationRatio >=
        account.quotaThresholdBasisPoints / 10000
      ) {
        rows.push({
          code: "C19_QUOTA_THRESHOLD",
          quotaScope: account.quotaScope,
        });
      }
      if (account.deniedCount > 0) {
        rows.push({
          code: "C19_QUOTA_DENIAL",
          quotaScope: account.quotaScope,
        });
      }
      return rows;
    });
    return Object.freeze({
      tenantId: serverContext.tenantId,
      principalId,
      quotaPeriod: tenant.quotaPeriod,
      accounts: normalized.map((account) =>
        Object.freeze(account),
      ),
      metrics: normalized.flatMap((account) => [
        Object.freeze({
          name: "aios_c19_quota_utilization_ratio",
          labels: Object.freeze({
            quota_scope: account.quotaScope,
          }),
          value: account.utilizationRatio,
        }),
        Object.freeze({
          name: "aios_c19_quota_denial_total",
          labels: Object.freeze({
            quota_scope: account.quotaScope,
          }),
          value: account.deniedCount,
        }),
      ]),
      alerts: alerts.map((alert) => Object.freeze(alert)),
    });
  }

  return Object.freeze({
    recordSignal,
    telemetryReport,
    reserve,
    release,
    settle,
    costVarianceReport,
    quotaStatus,
  });
}
