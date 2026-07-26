import { toolGatewaySha256 } from "./tool-gateway.mjs";

const OPERATION_BINDINGS = Object.freeze({
  "synthetic.approval.status.get": Object.freeze({
    adapterVersion: "c0-approval-v1",
    audience: "c16-c0-approval",
  }),
  "synthetic.erp.order.get": Object.freeze({
    adapterVersion: "c0-erp-v1",
    audience: "c16-c0-erp",
  }),
  "synthetic.bi.metric.get": Object.freeze({
    adapterVersion: "c0-bi-v1",
    audience: "c16-c0-bi",
  }),
});
const SYNTHETIC_TENANT_ID =
  /^stn_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const SHA256 = /^sha256:[a-f0-9]{64}$/;

export class C16SyntheticToolAdapterError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "C16SyntheticToolAdapterError";
    this.code = code;
  }
}

function fail(code, message) {
  throw new C16SyntheticToolAdapterError(code, message);
}

function clone(value) {
  return value === undefined ? undefined : structuredClone(value);
}

function deepFreeze(value) {
  if (!value || typeof value !== "object" || Object.isFrozen(value)) {
    return value;
  }
  for (const nested of Object.values(value)) deepFreeze(nested);
  return Object.freeze(value);
}

function plainObject(value) {
  return (
    value &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    Object.getPrototypeOf(value) === Object.prototype
  );
}

function exactKeys(value, allowed) {
  return (
    plainObject(value) &&
    Object.keys(value).length === allowed.length &&
    Object.keys(value).every((key) => allowed.includes(key))
  );
}

function validateFixtureDocument(document) {
  if (
    !exactKeys(document, [
      "schemaVersion",
      "fixtureVersion",
      "phase",
      "dataClassification",
      "networkAccess",
      "records",
    ]) ||
    document.schemaVersion !== "1.0.0" ||
    document.phase !== "P1_SYNTHETIC_ONLY" ||
    document.dataClassification !== "SYNTHETIC_ONLY" ||
    document.networkAccess !== "DISABLED" ||
    !Array.isArray(document.records) ||
    document.records.length < 3
  ) {
    fail(
      "INVALID_CONFIGURATION",
      "C16 C0 fixture document is invalid.",
    );
  }
  const records = new Map();
  const representedOperations = new Set();
  for (const record of document.records) {
    if (
      !exactKeys(record, [
        "tenantId",
        "operationId",
        "lookup",
        "result",
      ]) ||
      !SYNTHETIC_TENANT_ID.test(record.tenantId ?? "") ||
      !OPERATION_BINDINGS[record.operationId] ||
      !plainObject(record.lookup) ||
      !plainObject(record.result)
    ) {
      fail("INVALID_CONFIGURATION", "C16 C0 fixture row is invalid.");
    }
    const key = toolGatewaySha256({
      tenantId: record.tenantId,
      operationId: record.operationId,
      lookup: record.lookup,
    });
    if (records.has(key)) {
      fail("INVALID_CONFIGURATION", "C16 C0 fixture is duplicated.");
    }
    representedOperations.add(record.operationId);
    records.set(key, deepFreeze(clone(record.result)));
  }
  if (representedOperations.size !== 3) {
    fail(
      "INVALID_CONFIGURATION",
      "C16 C0 fixtures must cover all three operations.",
    );
  }
  return records;
}

function validateCall(call) {
  const binding = OPERATION_BINDINGS[call?.operationId];
  if (
    !exactKeys(call, [
      "tenantId",
      "tenantKind",
      "operationId",
      "callId",
      "effectKey",
      "adapterVersion",
      "audience",
      "normalizedParams",
    ]) ||
    !SYNTHETIC_TENANT_ID.test(call.tenantId ?? "") ||
    call.tenantKind !== "SYNTHETIC" ||
    !binding ||
    call.adapterVersion !== binding.adapterVersion ||
    call.audience !== binding.audience ||
    !/^tcl_[0-9a-f-]{36}$/.test(call.callId ?? "") ||
    !SHA256.test(call.effectKey ?? "") ||
    !plainObject(call.normalizedParams)
  ) {
    fail(
      "SYNTHETIC_BOUNDARY_VIOLATION",
      "C16 Adapter accepts only a fixed C0 call.",
    );
  }
  return binding;
}

export function createC16SyntheticToolAdapter({
  credentialBroker,
  fixtureDocument,
  maxNewEffectsPerTenant = 100,
  failedEffectKeys = new Set(),
}) {
  if (
    typeof credentialBroker?.assertUsable !== "function" ||
    !Number.isSafeInteger(maxNewEffectsPerTenant) ||
    maxNewEffectsPerTenant < 1 ||
    maxNewEffectsPerTenant > 10_000 ||
    !(failedEffectKeys instanceof Set)
  ) {
    fail("INVALID_CONFIGURATION", "C16 C0 Adapter is invalid.");
  }
  const fixtures = validateFixtureDocument(fixtureDocument);
  const effects = new Map();
  const tenantCounts = new Map();
  let newExecutionCount = 0;

  return Object.freeze({
    async execute(call, capability) {
      const binding = validateCall(call);
      try {
        credentialBroker.assertUsable(capability, {
          tenantId: call.tenantId,
          operationId: call.operationId,
          callId: call.callId,
          audience: binding.audience,
        });
      } catch {
        fail("CREDENTIAL_REJECTED", "C16 private capability was rejected.");
      }
      const requestHash = toolGatewaySha256(call);
      const prior = effects.get(call.effectKey);
      if (prior) {
        if (prior.requestHash !== requestHash) {
          fail(
            "EFFECT_KEY_CONFLICT",
            "C16 effect key was reused for a different call.",
          );
        }
        return deepFreeze({
          result: clone(prior.result),
          receipt: { ...clone(prior.receipt), replayed: true },
        });
      }
      const tenantCount = tenantCounts.get(call.tenantId) ?? 0;
      if (tenantCount >= maxNewEffectsPerTenant) {
        fail("RATE_LIMITED", "C16 synthetic rate limit was reached.");
      }
      if (failedEffectKeys.has(call.effectKey)) {
        fail("ADAPTER_UNAVAILABLE", "C16 C0 Adapter failed closed.");
      }
      const fixtureKey = toolGatewaySha256({
        tenantId: call.tenantId,
        operationId: call.operationId,
        lookup: call.normalizedParams,
      });
      const result = fixtures.get(fixtureKey);
      if (!result) {
        fail(
          "SYNTHETIC_RECORD_NOT_FOUND",
          "C16 Synthetic record was not found.",
        );
      }
      const receiptBase = {
        schemaVersion: "c16-c0-tool-receipt.v1",
        tenantId: call.tenantId,
        tenantKind: "SYNTHETIC",
        callId: call.callId,
        operationId: call.operationId,
        effectKey: call.effectKey,
        adapterVersion: call.adapterVersion,
        resultSha256: toolGatewaySha256(result),
        networkRequestCount: 0,
        externalEffectCount: 0,
        replayed: false,
      };
      const receipt = deepFreeze({
        ...receiptBase,
        receiptSha256: toolGatewaySha256(receiptBase),
      });
      effects.set(call.effectKey, {
        requestHash,
        result: clone(result),
        receipt: clone(receipt),
      });
      tenantCounts.set(call.tenantId, tenantCount + 1);
      newExecutionCount += 1;
      return deepFreeze({ result: clone(result), receipt });
    },

    snapshot() {
      return deepFreeze({
        networkRequestCount: 0,
        enterpriseEndpointCount: 0,
        enterpriseCredentialCount: 0,
        externalEffectCount: 0,
        newExecutionCount,
        effectKeys: [...effects.keys()].sort(),
      });
    },
  });
}

