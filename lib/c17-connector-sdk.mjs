import { createHash } from "node:crypto";
import { types } from "node:util";
import {
  createC16EphemeralCredentialBroker,
} from "./c16-ephemeral-credential-broker.mjs";
import { isC17MockLab } from "./c17-mock-lab.mjs";
import { normalizeC17DateTime } from "./c17-time.mjs";

const OPERATION_ID =
  /^[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)+$/;
const EXPECTED_TEMPLATE_SET_SHA256 =
  "sha256:11032e8f41ba671f582ee905b1d865ef404d291eb7b8a7f653354ccb6ecbe459";
const MAX_JSON_DEPTH = 64;
const MAX_JSON_NODES = 10_000;
const C17_CREDENTIAL_BROKERS = new WeakSet();

export class C17ConnectorError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "C17ConnectorError";
    this.code = code;
  }
}

function fail(code, message) {
  throw new C17ConnectorError(code, message);
}

export function createC17CredentialBroker(observedAt) {
  let currentObservedAt = normalizeC17DateTime(observedAt);
  if (currentObservedAt === null) {
    fail(
      "INVALID_CONFIGURATION",
      "C17 capability Broker time is invalid.",
    );
  }
  let idValue = 500;
  const broker = createC16EphemeralCredentialBroker({
    clock: () => currentObservedAt,
    idFactory: () => {
      idValue += 1;
      return `018f0000-0000-7000-8000-${String(idValue).padStart(12, "0")}`;
    },
    ttlSeconds: 15,
  });
  const registered = Object.freeze({
    issue(scope) {
      if (!validJsonValue(scope)) {
        fail("INVALID_INPUT", "C17 capability scope is invalid.");
      }
      try {
        return broker.issue(scope);
      } catch {
        fail("INVALID_INPUT", "C17 capability scope is invalid.");
      }
    },
    assertUsable(capability, scope) {
      if (
        !validJsonValue(capability) ||
        !validJsonValue(scope)
      ) {
        fail("DENIED", "C17 capability authorization was denied.");
      }
      try {
        return broker.assertUsable(capability, scope);
      } catch {
        fail("DENIED", "C17 capability authorization was denied.");
      }
    },
    revoke(capability) {
      if (!validJsonValue(capability)) {
        fail("DENIED", "C17 capability revocation was denied.");
      }
      try {
        return broker.revoke(capability);
      } catch {
        fail("DENIED", "C17 capability revocation was denied.");
      }
    },
    snapshot: () => broker.snapshot(),
    setSyntheticObservedAt(value) {
      const normalized = normalizeC17DateTime(value);
      if (
        normalized === null ||
        Date.parse(normalized) < Date.parse(currentObservedAt)
      ) {
        fail(
          "INVALID_INPUT",
          "C17 capability Broker time cannot move backward.",
        );
      }
      currentObservedAt = normalized;
    },
  });
  C17_CREDENTIAL_BROKERS.add(registered);
  return registered;
}

function plainObject(value) {
  return (
    value &&
    typeof value === "object" &&
    !types.isProxy(value) &&
    !Array.isArray(value) &&
    Object.getPrototypeOf(value) === Object.prototype
  );
}

function dataDescriptors(value) {
  if (!plainObject(value)) return null;
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const keys = Reflect.ownKeys(descriptors);
  if (
    keys.some(
      (key) =>
        typeof key !== "string" ||
        !descriptors[key].enumerable ||
        !Object.hasOwn(descriptors[key], "value"),
    )
  ) {
    return null;
  }
  return descriptors;
}

function exactKeys(value, allowed) {
  const descriptors = dataDescriptors(value);
  return (
    descriptors !== null &&
    Reflect.ownKeys(descriptors).length === allowed.length &&
    Reflect.ownKeys(descriptors).every((key) =>
      allowed.includes(key),
    )
  );
}

function readClosedConfiguration(value, allowed, required = allowed) {
  const descriptors = dataDescriptors(value);
  if (descriptors === null) return null;
  const keys = Reflect.ownKeys(descriptors);
  if (
    keys.some((key) => !allowed.includes(key)) ||
    required.some((key) => !Object.hasOwn(descriptors, key))
  ) {
    return null;
  }
  return Object.fromEntries(
    keys.map((key) => [key, descriptors[key].value]),
  );
}

function validJsonValue(value) {
  const pending = [{ value, depth: 0 }];
  const seen = new WeakSet();
  let nodeCount = 0;

  while (pending.length > 0) {
    const current = pending.pop();
    nodeCount += 1;
    if (
      current.depth > MAX_JSON_DEPTH ||
      nodeCount > MAX_JSON_NODES
    ) {
      return false;
    }
    if (current.value === null) continue;
    if (["string", "boolean"].includes(typeof current.value)) {
      continue;
    }
    if (typeof current.value === "number") {
      if (!Number.isFinite(current.value)) return false;
      continue;
    }
    if (
      typeof current.value !== "object" ||
      types.isProxy(current.value) ||
      (!Array.isArray(current.value) && !plainObject(current.value)) ||
      seen.has(current.value)
    ) {
      return false;
    }
    seen.add(current.value);
    const descriptors = Object.getOwnPropertyDescriptors(
      current.value,
    );
    if (Array.isArray(current.value)) {
      const lengthDescriptor = descriptors.length;
      if (
        !lengthDescriptor ||
        !Object.hasOwn(lengthDescriptor, "value") ||
        !Number.isSafeInteger(lengthDescriptor.value) ||
        lengthDescriptor.value < 0 ||
        lengthDescriptor.value > MAX_JSON_NODES ||
        Reflect.ownKeys(descriptors).length !==
          lengthDescriptor.value + 1
      ) {
        return false;
      }
      for (
        let index = 0;
        index < lengthDescriptor.value;
        index += 1
      ) {
        const descriptor = descriptors[String(index)];
        if (
          !descriptor ||
          !descriptor.enumerable ||
          !Object.hasOwn(descriptor, "value")
        ) {
          return false;
        }
        pending.push({
          value: descriptor.value,
          depth: current.depth + 1,
        });
      }
      continue;
    }
    for (const key of Reflect.ownKeys(descriptors)) {
      const descriptor = descriptors[key];
      if (
        typeof key !== "string" ||
        !descriptor.enumerable ||
        !Object.hasOwn(descriptor, "value") ||
        ["__proto__", "constructor", "prototype"].includes(key)
      ) {
        return false;
      }
      pending.push({
        value: descriptor.value,
        depth: current.depth + 1,
      });
    }
  }
  return true;
}

function deepFreeze(value) {
  if (!value || typeof value !== "object" || Object.isFrozen(value)) {
    return value;
  }
  for (const nested of Object.values(value)) deepFreeze(nested);
  return Object.freeze(value);
}

function canonicalInstantOrNull(value) {
  return value === null || normalizeC17DateTime(value) !== null;
}

function canonicalize(value) {
  if (Array.isArray(value)) {
    return `[${value.map(canonicalize).join(",")}]`;
  }
  if (plainObject(value)) {
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

export function c17ConnectorSha256(value) {
  if (!validJsonValue(value)) {
    fail("INVALID_JSON", "C17 hash input is not bounded JSON.");
  }
  return `sha256:${createHash("sha256")
    .update(canonicalize(value))
    .digest("hex")}`;
}

function configurationSha256(value) {
  try {
    return c17ConnectorSha256(value);
  } catch {
    fail("INVALID_CONFIGURATION", "C17 configuration is invalid.");
  }
}

function validClosedSchema(schema) {
  if (
    !exactKeys(schema, [
      "type",
      "additionalProperties",
      "required",
      "properties",
    ]) ||
    schema.type !== "object" ||
    schema.additionalProperties !== false ||
    !Array.isArray(schema.required) ||
    !plainObject(schema.properties) ||
    schema.required.length !== Object.keys(schema.properties).length ||
    !schema.required.every((field) =>
      Object.hasOwn(schema.properties, field),
    )
  ) {
    return false;
  }
  return Object.values(schema.properties).every((property) => {
    if (!plainObject(property)) return false;
    const allowed = ["type", "pattern", "enum", "maxLength"];
    if (!Object.keys(property).every((key) => allowed.includes(key))) {
      return false;
    }
    if (!["string", "number"].includes(property.type)) return false;
    if (
      property.pattern !== undefined &&
      (typeof property.pattern !== "string" ||
        property.type !== "string")
    ) {
      return false;
    }
    if (
      property.maxLength !== undefined &&
      (property.type !== "string" ||
        !Number.isSafeInteger(property.maxLength) ||
        property.maxLength < 1)
    ) {
      return false;
    }
    return (
      property.enum === undefined ||
      (Array.isArray(property.enum) &&
        property.enum.length > 0 &&
        property.enum.every((value) => typeof value === property.type))
    );
  });
}

function validTemplate(template) {
  return (
    exactKeys(template, [
      "templateId",
      "category",
      "operationId",
      "mode",
      "adapterSpiVersion",
      "envelopeContractVersion",
      "audience",
      "parameterSchema",
      "resultSchema",
    ]) &&
    typeof template.templateId === "string" &&
    /^[a-z][a-z0-9-]+-v1$/.test(template.templateId) &&
    [
      "APPROVAL_COLLABORATION",
      "ERP_BUSINESS",
      "BI_ANALYTICS",
    ].includes(template.category) &&
    OPERATION_ID.test(template.operationId ?? "") &&
    template.mode === "READ_ONLY" &&
    template.adapterSpiVersion === "1.0.0" &&
    template.envelopeContractVersion === 1 &&
    typeof template.audience === "string" &&
    /^[a-z0-9][a-z0-9-]{0,63}$/.test(template.audience) &&
    validClosedSchema(template.parameterSchema) &&
    validClosedSchema(template.resultSchema)
  );
}

function valueMatchesSchema(value, schema) {
  if (
    !validJsonValue(value) ||
    !exactKeys(value, schema.required)
  ) {
    return false;
  }
  for (const [field, property] of Object.entries(schema.properties)) {
    const fieldValue = value[field];
    if (
      typeof fieldValue !== property.type ||
      (property.type === "number" && !Number.isFinite(fieldValue)) ||
      (property.pattern !== undefined &&
        !new RegExp(property.pattern).test(fieldValue)) ||
      (property.maxLength !== undefined &&
        fieldValue.length > property.maxLength) ||
      (property.enum !== undefined &&
        !property.enum.includes(fieldValue))
    ) {
      return false;
    }
  }
  return true;
}

export function createC17ConnectorTemplates(document) {
  if (
    !validJsonValue(document) ||
    !exactKeys(document, [
      "schemaVersion",
      "templateSetVersion",
      "phase",
      "dataClassification",
      "connectorStage",
      "networkAccess",
      "templates",
    ]) ||
    document.schemaVersion !== "1.0.0" ||
    document.templateSetVersion !== "c17-connector-templates-v1" ||
    document.phase !== "P1_SYNTHETIC_ONLY" ||
    document.dataClassification !== "SYNTHETIC_ONLY" ||
    document.connectorStage !== "C0_DISABLED" ||
    document.networkAccess !== "DISABLED" ||
    !Array.isArray(document.templates) ||
    document.templates.length !== 3 ||
    !document.templates.every(validTemplate) ||
    configurationSha256(document) !== EXPECTED_TEMPLATE_SET_SHA256
  ) {
    fail("INVALID_CONFIGURATION", "C17 Template catalog is invalid.");
  }
  const templates = deepFreeze(structuredClone(document.templates));
  const byOperation = new Map(
    templates.map((template) => [template.operationId, template]),
  );
  const categories = templates.map((template) => template.category);
  const operations = templates.map((template) => template.operationId);
  if (
    new Set(categories).size !== 3 ||
    new Set(operations).size !== 3
  ) {
    fail("INVALID_CONFIGURATION", "C17 Template catalog is incomplete.");
  }
  return Object.freeze({
    phase: document.phase,
    connectorStage: document.connectorStage,
    networkAccess: document.networkAccess,
    list() {
      return templates;
    },
    get(operationId) {
      return byOperation.get(operationId) ?? null;
    },
    validateParameters(operationId, parameters) {
      const template = byOperation.get(operationId);
      return Boolean(
        template &&
          valueMatchesSchema(parameters, template.parameterSchema),
      );
    },
    validateResult(operationId, result) {
      const template = byOperation.get(operationId);
      return Boolean(
        template && valueMatchesSchema(result, template.resultSchema),
      );
    },
  });
}

function validServerContext(context) {
  return (
    exactKeys(context, [
      "tenantId",
      "tenantKind",
      "principalId",
      "callId",
      "connectorStage",
    ]) &&
    /^stn_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(
      context.tenantId ?? "",
    ) &&
    context.tenantKind === "SYNTHETIC" &&
    /^prn_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(
      context.principalId ?? "",
    ) &&
    /^tcl_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(
      context.callId ?? "",
    ) &&
    context.connectorStage === "C0_DISABLED"
  );
}

function validMockResult(
  result,
  operationId,
  requestedParameters,
  templates,
) {
  return (
    exactKeys(result, ["status", "data", "provenance", "error"]) &&
    result.status === "OK" &&
    templates.validateResult(operationId, result.data) &&
    Object.entries(requestedParameters).every(
      ([field, value]) => result.data[field] === value,
    ) &&
    exactKeys(result.provenance, [
      "source_mode",
      "freshness_status",
      "as_of",
      "observed_at",
      "content_hash",
    ]) &&
    result.provenance.source_mode === "SYNTHETIC" &&
    result.provenance.freshness_status === "CURRENT" &&
    canonicalInstantOrNull(result.provenance.as_of) &&
    canonicalInstantOrNull(result.provenance.observed_at) &&
    /^sha256:[a-f0-9]{64}$/.test(
      result.provenance.content_hash ?? "",
    ) &&
    result.provenance.content_hash ===
      c17ConnectorSha256(result.data) &&
    result.error === null
  );
}

async function executeWithTimeout(adapter, call, timeoutMs) {
  let timer;
  try {
    return await Promise.race([
      Promise.resolve().then(() => adapter.execute(call)),
      new Promise((_, reject) => {
        timer = setTimeout(reject, timeoutMs);
      }),
    ]);
  } catch {
    fail("UNAVAILABLE", "C17 Adapter is unavailable.");
  } finally {
    clearTimeout(timer);
  }
}

export function createC17ConnectorSdk(configuration) {
  const parsedConfiguration = readClosedConfiguration(configuration, [
    "templateDocument",
    "credentialBroker",
    "adapter",
    "timeoutMs",
  ]);
  if (parsedConfiguration === null) {
    fail("INVALID_CONFIGURATION", "C17 SDK configuration is invalid.");
  }
  const {
    templateDocument,
    credentialBroker,
    adapter,
    timeoutMs,
  } = parsedConfiguration;
  if (
    !C17_CREDENTIAL_BROKERS.has(credentialBroker) ||
    !isC17MockLab(adapter) ||
    !Number.isSafeInteger(timeoutMs) ||
    timeoutMs < 1 ||
    timeoutMs > 30_000
  ) {
    fail("INVALID_CONFIGURATION", "C17 SDK configuration is invalid.");
  }
  const templates = createC17ConnectorTemplates(templateDocument);
  const consumedCapabilities = new Set();

  return Object.freeze({
    async execute(serverContext, envelope, capability) {
      if (
        !validJsonValue(serverContext) ||
        !validServerContext(serverContext)
      ) {
        fail(
          "SYNTHETIC_BOUNDARY_VIOLATION",
          "C17 requires a trusted C0 Synthetic Tenant context.",
        );
      }
      if (
        capability !== undefined &&
        !validJsonValue(capability)
      ) {
        fail("DENIED", "C17 connector authorization was denied.");
      }
      const request = validateConnectorEnvelope(envelope);
      const template = templates.get(request.operation_id);
      if (
        !template ||
        request.principal_id !== serverContext.principalId ||
        !templates.validateParameters(
          request.operation_id,
          request.request.parameters,
        )
      ) {
        fail("INVALID_REQUEST", "C17 connector request is invalid.");
      }
      const replayKey =
        typeof capability?.capabilityId === "string"
          ? c17ConnectorSha256(capability.capabilityId)
          : null;
      if (replayKey && consumedCapabilities.has(replayKey)) {
        fail("REPLAY_REJECTED", "C17 connector replay was rejected.");
      }
      try {
        credentialBroker.assertUsable(capability, {
          tenantId: serverContext.tenantId,
          operationId: request.operation_id,
          callId: serverContext.callId,
          audience: template.audience,
        });
        consumedCapabilities.add(replayKey);
        credentialBroker.revoke(capability);
      } catch {
        fail("DENIED", "C17 connector authorization was denied.");
      }
      const result = await executeWithTimeout(
        adapter,
        {
          tenantId: serverContext.tenantId,
          tenantKind: serverContext.tenantKind,
          operationId: request.operation_id,
          parameters: request.request.parameters,
          requestedAsOf: request.request.requested_as_of,
        },
        timeoutMs,
      );
      if (
        !validMockResult(
          result,
          request.operation_id,
          request.request.parameters,
          templates,
        )
      ) {
        fail(
          "INVALID_ADAPTER_RESULT",
          "C17 Adapter result is invalid.",
        );
      }
      return validateConnectorEnvelope({
        document_status: request.document_status,
        contract_version: request.contract_version,
        message_type: "RESULT",
        operation_id: request.operation_id,
        trace_id: request.trace_id,
        principal_id: request.principal_id,
        purpose: request.purpose,
        result: structuredClone(result),
      });
    },
  });
}

function validEnvelopeBase(envelope) {
  return (
    envelope.document_status === "GENERIC_PRODUCT_TEMPLATE" &&
    envelope.contract_version === 1 &&
    ["REQUEST", "RESULT"].includes(envelope.message_type) &&
    OPERATION_ID.test(envelope.operation_id ?? "") &&
    envelope.operation_id.length <= 160 &&
    !/\.v[0-9]+$/.test(envelope.operation_id) &&
    typeof envelope.trace_id === "string" &&
    envelope.trace_id.length >= 8 &&
    envelope.trace_id.length <= 160 &&
    typeof envelope.principal_id === "string" &&
    envelope.principal_id.length >= 8 &&
    envelope.principal_id.length <= 160 &&
    typeof envelope.purpose === "string" &&
    envelope.purpose.length >= 1 &&
    envelope.purpose.length <= 240
  );
}

function validResultPart(result) {
  const statuses = [
    "OK",
    "NOT_FOUND",
    "DENIED",
    "STALE",
    "UNAVAILABLE",
    "INVALID",
  ];
  if (
    !exactKeys(result, ["status", "data", "provenance", "error"]) ||
    !statuses.includes(result.status) ||
    !validJsonValue(result.data) ||
    !exactKeys(result.provenance, [
      "source_mode",
      "freshness_status",
      "as_of",
      "observed_at",
      "content_hash",
    ]) ||
    ![
      "SYNTHETIC",
      "PUBLIC_EXTERNAL_CONTEXT",
      "APPROVED_SNAPSHOT",
      "REAL_READ",
    ].includes(result.provenance.source_mode) ||
    !["CURRENT", "STALE", "UNKNOWN", "NOT_APPLICABLE"].includes(
      result.provenance.freshness_status,
    ) ||
    !canonicalInstantOrNull(result.provenance.as_of) ||
    !canonicalInstantOrNull(result.provenance.observed_at) ||
    !(
      result.provenance.content_hash === null ||
      /^sha256:[a-f0-9]{64}$/.test(
        result.provenance.content_hash ?? "",
      )
    )
  ) {
    return false;
  }
  if (result.status === "OK") return result.error === null;
  return (
    exactKeys(result.error, ["code", "message", "retryable"]) &&
    result.error.code === result.status &&
    typeof result.error.message === "string" &&
    result.error.message.length >= 1 &&
    result.error.message.length <= 500 &&
    typeof result.error.retryable === "boolean"
  );
}

export function validateConnectorEnvelope(envelope) {
  if (!validJsonValue(envelope)) {
    fail("INVALID_ENVELOPE", "Canonical Connector Envelope is invalid.");
  }
  const requestKeys = [
    "document_status",
    "contract_version",
    "message_type",
    "operation_id",
    "trace_id",
    "principal_id",
    "purpose",
    "request",
  ];
  const resultKeys = [
    "document_status",
    "contract_version",
    "message_type",
    "operation_id",
    "trace_id",
    "principal_id",
    "purpose",
    "result",
  ];
  const validRequest =
    envelope?.message_type === "REQUEST" &&
    exactKeys(envelope, requestKeys) &&
    validEnvelopeBase(envelope) &&
    exactKeys(envelope.request, ["parameters", "requested_as_of"]) &&
    plainObject(envelope.request.parameters) &&
    validJsonValue(envelope.request.parameters) &&
    canonicalInstantOrNull(envelope.request.requested_as_of);
  const validResult =
    envelope?.message_type === "RESULT" &&
    exactKeys(envelope, resultKeys) &&
    validEnvelopeBase(envelope) &&
    validResultPart(envelope.result);
  if (!validRequest && !validResult) {
    fail("INVALID_ENVELOPE", "Canonical Connector Envelope is invalid.");
  }
  const normalized = structuredClone(envelope);
  if (normalized.message_type === "REQUEST") {
    if (normalized.request.requested_as_of !== null) {
      normalized.request.requested_as_of = normalizeC17DateTime(
        normalized.request.requested_as_of,
      );
    }
  } else {
    for (const field of ["as_of", "observed_at"]) {
      if (normalized.result.provenance[field] !== null) {
        normalized.result.provenance[field] = normalizeC17DateTime(
          normalized.result.provenance[field],
        );
      }
    }
  }
  return deepFreeze(normalized);
}
