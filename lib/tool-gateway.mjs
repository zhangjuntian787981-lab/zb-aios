import { createHash, randomBytes } from "node:crypto";

const UUID_V7 =
  "[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}";
const SYNTHETIC_TENANT_ID = new RegExp(`^stn_${UUID_V7}$`);
const OPERATION_ID = /^synthetic\.(?:approval\.status|erp\.order|bi\.metric)\.get$/;
const SAFE_SLUG = /^[a-z0-9][a-z0-9-]{0,63}$/;
const EXPECTED_OPERATIONS = Object.freeze([
  "synthetic.approval.status.get",
  "synthetic.bi.metric.get",
  "synthetic.erp.order.get",
]);
const PUBLIC_STORE_ERRORS = new Set([
  "APPEND_ONLY_VIOLATION",
  "CALL_NOT_FOUND",
  "CALL_RESULT_CONFLICT",
  "CALL_STATE_CONFLICT",
  "CONFIRMATION_REPLAYED",
  "CONFIRMATION_TAMPERED",
  "IDEMPOTENCY_CONFLICT",
  "TENANT_SCOPE_VIOLATION",
]);

export class ToolGatewayError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "ToolGatewayError";
    this.code = code;
  }
}

function fail(code, message) {
  throw new ToolGatewayError(code, message);
}

function storageFailure(error) {
  if (error instanceof ToolGatewayError) return error;
  if (
    error?.name === "PostgresToolGatewayStoreError" &&
    PUBLIC_STORE_ERRORS.has(error.code)
  ) {
    return new ToolGatewayError(
      error.code,
      "C16 storage rejected the request.",
    );
  }
  return new ToolGatewayError(
    "STORE_UNAVAILABLE",
    "C16 storage failed closed.",
  );
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

function plainObject(value, field) {
  if (
    !value ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    Object.getPrototypeOf(value) !== Object.prototype
  ) {
    fail("INVALID_INPUT", `${field} must be a plain object.`);
  }
}

function exactKeys(value, allowed, field) {
  plainObject(value, field);
  if (
    Object.keys(value).length !== allowed.length ||
    Object.keys(value).some((key) => !allowed.includes(key))
  ) {
    fail("INVALID_INPUT", `${field} has unsupported fields.`);
  }
}

function nonEmpty(value, field, max = 256) {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > max
  ) {
    fail("INVALID_INPUT", `${field} is invalid.`);
  }
}

function canonicalize(value) {
  if (
    value === null ||
    typeof value === "boolean" ||
    typeof value === "string"
  ) {
    return JSON.stringify(value);
  }
  if (typeof value === "number" && Number.isFinite(value)) {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map(canonicalize).join(",")}]`;
  }
  if (value && typeof value === "object") {
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalize(value[key])}`)
      .join(",")}}`;
  }
  fail("INVALID_INPUT", "C16 accepts only finite JSON values.");
}

export function toolGatewaySha256(value) {
  return `sha256:${createHash("sha256")
    .update(typeof value === "string" ? value : canonicalize(value))
    .digest("hex")}`;
}

function validateStringSchema(schema, field) {
  plainObject(schema, field);
  const allowed = ["type", "pattern", "enum", "maxLength"];
  if (
    Object.keys(schema).some((key) => !allowed.includes(key)) ||
    schema.type !== "string" ||
    !Number.isSafeInteger(schema.maxLength) ||
    schema.maxLength < 1 ||
    schema.maxLength > 128 ||
    (schema.pattern === undefined) === (schema.enum === undefined)
  ) {
    fail("INVALID_CATALOG", "C16 parameter schema is invalid.");
  }
  if (schema.pattern !== undefined) {
    nonEmpty(schema.pattern, field, 128);
    try {
      new RegExp(schema.pattern);
    } catch {
      fail("INVALID_CATALOG", "C16 parameter pattern is invalid.");
    }
  }
  if (
    schema.enum !== undefined &&
    (!Array.isArray(schema.enum) ||
      schema.enum.length === 0 ||
      new Set(schema.enum).size !== schema.enum.length ||
      schema.enum.some(
        (item) =>
          typeof item !== "string" ||
          item.length === 0 ||
          item.length > schema.maxLength,
      ))
  ) {
    fail("INVALID_CATALOG", "C16 parameter enum is invalid.");
  }
}

function normalizeOperation(value) {
  exactKeys(
    value,
    [
      "operationId",
      "title",
      "purpose",
      "mode",
      "adapterVersion",
      "authorizationResourceSuffix",
      "audience",
      "parameterSchema",
    ],
    "operation",
  );
  if (
    !OPERATION_ID.test(value.operationId ?? "") ||
    value.mode !== "READ_ONLY" ||
    !SAFE_SLUG.test(value.authorizationResourceSuffix ?? "") ||
    !SAFE_SLUG.test(value.audience ?? "")
  ) {
    fail("INVALID_CATALOG", "C16 operation binding is invalid.");
  }
  for (const field of ["title", "purpose", "adapterVersion"]) {
    nonEmpty(value[field], field, 128);
  }
  exactKeys(
    value.parameterSchema,
    ["type", "additionalProperties", "required", "properties"],
    "parameterSchema",
  );
  const schema = value.parameterSchema;
  plainObject(schema.properties, "parameterSchema.properties");
  if (
    schema.type !== "object" ||
    schema.additionalProperties !== false ||
    !Array.isArray(schema.required) ||
    schema.required.length === 0 ||
    new Set(schema.required).size !== schema.required.length ||
    schema.required.some(
      (field) => !Object.hasOwn(schema.properties, field),
    ) ||
    Object.keys(schema.properties).some(
      (field) => !schema.required.includes(field),
    )
  ) {
    fail("INVALID_CATALOG", "C16 object parameter schema is invalid.");
  }
  for (const [field, definition] of Object.entries(schema.properties)) {
    if (!/^[a-z][A-Za-z0-9]{0,31}$/.test(field)) {
      fail("INVALID_CATALOG", "C16 parameter name is invalid.");
    }
    validateStringSchema(definition, `parameterSchema.${field}`);
  }
  return deepFreeze(clone(value));
}

export function createSyntheticToolCatalog(document) {
  exactKeys(
    document,
    [
      "schemaVersion",
      "catalogVersion",
      "phase",
      "dataClassification",
      "connectorStage",
      "networkAccess",
      "operations",
    ],
    "catalog",
  );
  if (
    document.schemaVersion !== "1.0.0" ||
    document.phase !== "P1_SYNTHETIC_ONLY" ||
    document.dataClassification !== "SYNTHETIC_ONLY" ||
    document.connectorStage !== "C0_MOCK" ||
    document.networkAccess !== "DISABLED" ||
    !Array.isArray(document.operations) ||
    document.operations.length !== 3
  ) {
    fail("INVALID_CATALOG", "C16 catalog envelope is invalid.");
  }
  nonEmpty(document.catalogVersion, "catalogVersion", 128);
  const operations = document.operations.map(normalizeOperation);
  const operationIds = operations
    .map((operation) => operation.operationId)
    .sort();
  if (
    operationIds.some(
      (operationId, index) =>
        operationId !== EXPECTED_OPERATIONS[index],
    )
  ) {
    fail("INVALID_CATALOG", "C16 operation catalog is not closed.");
  }
  const byId = new Map(
    operations.map((operation) => [operation.operationId, operation]),
  );
  const catalogSha256 = toolGatewaySha256(document);
  return Object.freeze({
    catalogVersion: document.catalogVersion,
    catalogSha256,
    operation(operationId) {
      const operation = byId.get(operationId);
      if (!operation) {
        fail("OPERATION_NOT_FOUND", "C16 operation is not in the catalog.");
      }
      return operation;
    },
    normalizeParameters(operationId, params) {
      const operation = byId.get(operationId);
      if (!operation) {
        fail("OPERATION_NOT_FOUND", "C16 operation is not in the catalog.");
      }
      plainObject(params, "params");
      const schema = operation.parameterSchema;
      const fields = schema.required;
      if (
        Object.keys(params).length !== fields.length ||
        Object.keys(params).some((field) => !fields.includes(field))
      ) {
        fail("INVALID_INPUT", "C16 parameters do not match the catalog.");
      }
      const normalized = {};
      for (const field of fields) {
        const value = params[field];
        const definition = schema.properties[field];
        if (
          typeof value !== "string" ||
          value.length === 0 ||
          value.length > definition.maxLength ||
          (definition.pattern !== undefined &&
            !new RegExp(definition.pattern).test(value)) ||
          (definition.enum !== undefined &&
            !definition.enum.includes(value))
        ) {
          fail("INVALID_INPUT", "C16 parameter value is invalid.");
        }
        normalized[field] = value;
      }
      return deepFreeze(normalized);
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
      "workloadTrustSource",
      "workloadActorPrincipalId",
    ],
    "serverContext",
  );
  if (
    context.synthetic !== true ||
    context.routeTrustSource !== "VERIFIED_ROUTE_DESCRIPTOR" ||
    context.workloadTrustSource !== "VERIFIED_WORKLOAD_CONTEXT" ||
    !SYNTHETIC_TENANT_ID.test(context.tenantId ?? "")
  ) {
    fail(
      "SYNTHETIC_BOUNDARY_VIOLATION",
      "C16 accepts only a trusted Synthetic Tenant route.",
    );
  }
  nonEmpty(
    context.workloadActorPrincipalId,
    "workloadActorPrincipalId",
    128,
  );
}

function validateEnvelope(request, extraFields) {
  exactKeys(
    request,
    [
      "sessionToken",
      "delegationId",
      "correlationId",
      "operationId",
      ...extraFields,
    ],
    "request",
  );
  nonEmpty(request.sessionToken, "sessionToken", 4096);
  nonEmpty(request.delegationId, "delegationId", 128);
  nonEmpty(request.correlationId, "correlationId", 128);
  if (!OPERATION_ID.test(request.operationId ?? "")) {
    fail("OPERATION_NOT_FOUND", "C16 operation is not in the catalog.");
  }
}

function identityBinding(identity, context, request) {
  const leaf =
    Array.isArray(identity?.delegationChain) &&
    identity.delegationChain.length > 0
      ? identity.delegationChain.at(-1)
      : null;
  if (
    identity?.tenantId !== context.tenantId ||
    identity?.tenantKind !== "SYNTHETIC" ||
    identity?.trustSource !==
      "VERIFIED_SESSION_IDENTITY_LINK_AND_WORKLOAD_CONTEXT" ||
    identity?.authorizationStatus !== "NOT_EVALUATED" ||
    identity?.humanSubject?.principalType !== "HUMAN" ||
    identity?.workloadActor?.principalId !==
      context.workloadActorPrincipalId ||
    !["AGENT", "SERVICE"].includes(identity?.workloadActor?.principalType) ||
    !Number.isSafeInteger(identity?.humanSubject?.securityEpoch) ||
    identity.humanSubject.securityEpoch < 1 ||
    !Number.isSafeInteger(identity?.workloadActor?.securityEpoch) ||
    identity.workloadActor.securityEpoch < 1 ||
    leaf?.delegationId !== request.delegationId ||
    leaf?.delegatePrincipalId !== context.workloadActorPrincipalId
  ) {
    fail("ACTION_IDENTITY_INVALID", "C05 action identity is invalid.");
  }
  return deepFreeze({
    humanPrincipalId: identity.humanSubject.principalId,
    humanSecurityEpoch: identity.humanSubject.securityEpoch,
    workloadActorPrincipalId: identity.workloadActor.principalId,
    workloadActorSecurityEpoch: identity.workloadActor.securityEpoch,
    leafDelegationId: leaf.delegationId,
    delegationChainSha256: toolGatewaySha256(identity.delegationChain),
    purposeRef: identity.purposeRef,
  });
}

function authorizationBinding(value, expected, context, descriptor) {
  const required = [
    "operationId",
    "decisionId",
    "evidenceRef",
    "policyVersion",
  ];
  if (
    value?.trustSource !== "C06_BOUND_DECISION_EVIDENCE" ||
    value?.operationId !== descriptor.operationId ||
    value?.tenantId !== context.tenantId ||
    value?.surface !== "TOOL_CALL" ||
    value?.resourceId !== descriptor.resourceId ||
    value?.humanPrincipalId !== expected.humanPrincipalId ||
    value?.humanSecurityEpoch !== expected.humanSecurityEpoch ||
    value?.workloadActorPrincipalId !==
      expected.workloadActorPrincipalId ||
    value?.workloadActorSecurityEpoch !==
      expected.workloadActorSecurityEpoch ||
    value?.leafDelegationId !== expected.leafDelegationId ||
    value?.delegationChainSha256 !==
      expected.delegationChainSha256 ||
    value?.purposeRef !== expected.purposeRef ||
    required.some(
      (field) => typeof value?.[field] !== "string" || !value[field],
    )
  ) {
    fail(
      "AUTHORIZATION_BINDING_INVALID",
      "C06 decision is not bound to the C16 action.",
    );
  }
  return deepFreeze(clone(value));
}

function tenantScope(tenant, authorization, correlationId) {
  return deepFreeze({
    trustSource: "C07_VERIFIED_TENANT_SCOPE",
    tenantId: tenant.tenantId,
    tenantKind: tenant.tenantKind,
    lifecycleVersion: tenant.lifecycleVersion,
    correlationId,
    decisionId: authorization.decisionId,
    evidenceRef: authorization.evidenceRef,
    policyVersion: authorization.policyVersion,
  });
}

function publicConfirmation(value, replayed = false) {
  return deepFreeze({
    schemaVersion: value.schemaVersion,
    confirmationId: value.confirmationId,
    tenantId: value.tenantId,
    tenantKind: value.tenantKind,
    operationId: value.operationId,
    catalogVersion: value.catalogVersion,
    catalogSha256: value.catalogSha256,
    adapterVersion: value.adapterVersion,
    normalizedParamSha256: value.normalizedParamSha256,
    identitySha256: value.identitySha256,
    authorizationSha256: value.authorizationSha256,
    confirmationSha256: value.confirmationSha256,
    confirmedAt: value.confirmedAt,
    expiresAt: value.expiresAt,
    replayed,
  });
}

function publicCall(value, replayed = false) {
  return deepFreeze({
    schemaVersion: "c16-tool-call-result.v1",
    callId: value.callId,
    tenantId: value.tenantId,
    tenantKind: value.tenantKind,
    operationId: value.operationId,
    status: value.status,
    result: clone(value.result),
    receipt: clone(value.receipt),
    replayed,
  });
}

function validateScope(scope) {
  if (
    scope?.trustSource !== "C07_VERIFIED_TENANT_SCOPE" ||
    scope?.tenantKind !== "SYNTHETIC" ||
    !SYNTHETIC_TENANT_ID.test(scope?.tenantId ?? "") ||
    !Number.isSafeInteger(scope?.lifecycleVersion) ||
    scope.lifecycleVersion < 1
  ) {
    fail("TENANT_SCOPE_VIOLATION", "C16 requires a verified Tenant scope.");
  }
}

export function createMemoryToolGatewayStore({
  clock = () => new Date().toISOString(),
} = {}) {
  if (typeof clock !== "function") {
    fail("INVALID_CONFIGURATION", "C16 memory store clock is invalid.");
  }
  const confirmations = new Map();
  const receipts = new Map();
  const auditIntents = new Map();
  const auditOutbox = new Map();
  const calls = new Map();
  const confirmationExecutions = new Map();

  function insertAudit(scope, intent) {
    auditIntents.set(
      `${scope.tenantId}|${intent.intentId}`,
      deepFreeze(clone(intent)),
    );
    auditOutbox.set(`${scope.tenantId}|${intent.intentId}`, {
      tenantId: scope.tenantId,
      tenantKind: "SYNTHETIC",
      intentId: intent.intentId,
      status: "PENDING",
      attemptCount: 0,
      leaseVersion: 0,
      leasedBy: null,
      leaseUntil: null,
      availableAt: intent.occurredAt,
      publishedAt: null,
      lastErrorCode: null,
      createdAt: intent.occurredAt,
    });
  }

  return Object.freeze({
    async saveConfirmation(scope, command) {
      validateScope(scope);
      if (command.tenantId !== scope.tenantId) {
        fail(
          "TENANT_SCOPE_VIOLATION",
          "C16 confirmation escaped Tenant scope.",
        );
      }
      const receiptKey = `${scope.tenantId}|CONFIRM|${command.idempotencyKey}`;
      const prior = receipts.get(receiptKey);
      if (prior) {
        if (prior.requestHash !== command.requestHash) {
          fail(
            "IDEMPOTENCY_CONFLICT",
            "C16 idempotency key was reused.",
          );
        }
        return publicConfirmation(prior.response, true);
      }
      const confirmationKey =
        `${scope.tenantId}|${command.confirmation.confirmationId}`;
      confirmations.set(
        confirmationKey,
        deepFreeze(clone(command.confirmation)),
      );
      insertAudit(scope, command.auditIntent);
      const response = publicConfirmation(command.confirmation);
      receipts.set(receiptKey, {
        requestHash: command.requestHash,
        response,
      });
      return response;
    },

    async getConfirmation(scope, confirmationId) {
      validateScope(scope);
      return (
        confirmations.get(`${scope.tenantId}|${confirmationId}`) ?? null
      );
    },

    async beginExecution(scope, command) {
      validateScope(scope);
      if (command.tenantId !== scope.tenantId) {
        fail(
          "TENANT_SCOPE_VIOLATION",
          "C16 execution escaped Tenant scope.",
        );
      }
      const receiptKey = `${scope.tenantId}|EXECUTE|${command.idempotencyKey}`;
      const prior = receipts.get(receiptKey);
      if (prior) {
        if (prior.requestHash !== command.requestHash) {
          fail(
            "IDEMPOTENCY_CONFLICT",
            "C16 idempotency key was reused.",
          );
        }
        const existing = calls.get(
          `${scope.tenantId}|${prior.callId}`,
        );
        if (existing.status === "FAILED") {
          existing.status = "STARTED";
          existing.lastErrorCode = null;
          return publicCall(existing);
        }
        return publicCall(existing, existing.status === "SUCCEEDED");
      }
      const confirmationKey =
        `${scope.tenantId}|${command.call.confirmationId}`;
      if (confirmationExecutions.has(confirmationKey)) {
        fail(
          "CONFIRMATION_REPLAYED",
          "C16 confirmation was already executed.",
        );
      }
      const callKey = `${scope.tenantId}|${command.call.callId}`;
      const call = {
        ...clone(command.call),
        status: "STARTED",
        result: null,
        receipt: null,
        lastErrorCode: null,
      };
      calls.set(callKey, call);
      confirmationExecutions.set(confirmationKey, call.callId);
      receipts.set(receiptKey, {
        requestHash: command.requestHash,
        callId: call.callId,
      });
      return publicCall(call);
    },

    async completeExecution(scope, command) {
      validateScope(scope);
      const call = calls.get(`${scope.tenantId}|${command.callId}`);
      if (!call) {
        fail("CALL_NOT_FOUND", "C16 call was not found.");
      }
      if (call.status === "SUCCEEDED") {
        if (
          call.receipt?.receiptSha256 !==
          command.receipt?.receiptSha256
        ) {
          fail("CALL_RESULT_CONFLICT", "C16 call result changed.");
        }
        return publicCall(call, true);
      }
      if (call.status !== "STARTED") {
        fail("CALL_STATE_CONFLICT", "C16 call is not active.");
      }
      if (
        command.receipt?.tenantId !== scope.tenantId ||
        command.receipt?.callId !== call.callId ||
        command.receipt?.operationId !== call.operationId ||
        command.receipt?.effectKey !== call.effectKey ||
        command.receipt?.resultSha256 !==
          toolGatewaySha256(command.result)
      ) {
        fail("CALL_RESULT_CONFLICT", "C16 call receipt is invalid.");
      }
      call.status = "SUCCEEDED";
      call.result = clone(command.result);
      call.receipt = clone(command.receipt);
      call.completedAt = command.completedAt;
      insertAudit(scope, command.auditIntent);
      return publicCall(call);
    },

    async failExecution(scope, command) {
      validateScope(scope);
      const call = calls.get(`${scope.tenantId}|${command.callId}`);
      if (!call || call.status !== "STARTED") {
        fail("CALL_STATE_CONFLICT", "C16 call is not active.");
      }
      call.status = "FAILED";
      call.lastErrorCode = command.errorCode;
      return publicCall(call);
    },

    async claimAudit(scope, input) {
      validateScope(scope);
      if (
        typeof input?.workerId !== "string" ||
        !input.workerId ||
        !Number.isSafeInteger(input?.limit) ||
        input.limit < 1 ||
        input.limit > 100 ||
        !Number.isSafeInteger(input?.leaseDurationSeconds) ||
        input.leaseDurationSeconds < 1 ||
        input.leaseDurationSeconds > 300
      ) {
        fail("INVALID_INPUT", "C16 audit lease is invalid.");
      }
      const now = new Date(clock()).getTime();
      const candidates = [...auditOutbox.values()]
        .filter(
          (item) =>
            item.tenantId === scope.tenantId &&
            ((["PENDING", "FAILED"].includes(item.status) &&
              new Date(item.availableAt).getTime() <= now) ||
              (item.status === "PROCESSING" &&
                new Date(item.leaseUntil).getTime() <= now)),
        )
        .sort((left, right) =>
          left.createdAt < right.createdAt
            ? -1
            : left.createdAt > right.createdAt
              ? 1
              : left.intentId.localeCompare(right.intentId),
        )
        .slice(0, input.limit);
      return deepFreeze(
        candidates.map((item) => {
          item.status = "PROCESSING";
          item.attemptCount += 1;
          item.leaseVersion += 1;
          item.leasedBy = input.workerId;
          item.leaseUntil = new Date(
            now + input.leaseDurationSeconds * 1000,
          ).toISOString();
          item.lastErrorCode = null;
          return {
            ...clone(item),
            intent: clone(
              auditIntents.get(`${scope.tenantId}|${item.intentId}`),
            ),
          };
        }),
      );
    },

    async completeAudit(scope, input) {
      validateScope(scope);
      if (input?.ackIntentId !== input?.intentId) {
        fail("AUDIT_ACK_MISMATCH", "C18 audit ACK is invalid.");
      }
      const item = auditOutbox.get(
        `${scope.tenantId}|${input.intentId}`,
      );
      const now = new Date(clock()).getTime();
      if (
        !item ||
        item.status !== "PROCESSING" ||
        item.leasedBy !== input.workerId ||
        item.leaseVersion !== input.leaseVersion ||
        new Date(item.leaseUntil).getTime() < now
      ) {
        fail("STALE_OUTBOX_LEASE", "C16 audit lease is stale.");
      }
      item.status = "PUBLISHED";
      item.leasedBy = null;
      item.leaseUntil = null;
      item.publishedAt = new Date(now).toISOString();
      item.lastErrorCode = null;
      return deepFreeze(clone(item));
    },

    async failAudit(scope, input) {
      validateScope(scope);
      const item = auditOutbox.get(
        `${scope.tenantId}|${input?.intentId}`,
      );
      const now = new Date(clock()).getTime();
      if (
        !item ||
        item.status !== "PROCESSING" ||
        item.leasedBy !== input.workerId ||
        item.leaseVersion !== input.leaseVersion ||
        new Date(item.leaseUntil).getTime() < now
      ) {
        fail("STALE_OUTBOX_LEASE", "C16 audit lease is stale.");
      }
      item.status = "FAILED";
      item.leasedBy = null;
      item.leaseUntil = null;
      item.availableAt = new Date(
        now + input.retryDelaySeconds * 1000,
      ).toISOString();
      item.publishedAt = null;
      item.lastErrorCode = input.errorCode;
      return deepFreeze(clone(item));
    },

    snapshot() {
      return deepFreeze({
        confirmations: [...confirmations.values()].map(clone),
        calls: [...calls.values()].map(clone),
        auditIntents: [...auditIntents.values()].map(clone),
        auditOutbox: [...auditOutbox.values()].map(clone),
      });
    },
  });
}

function uuidV7() {
  const bytes = randomBytes(16);
  let milliseconds = BigInt(Date.now());
  for (let index = 5; index >= 0; index -= 1) {
    bytes[index] = Number(milliseconds & 0xffn);
    milliseconds >>= 8n;
  }
  bytes[6] = (bytes[6] & 0x0f) | 0x70;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = bytes.toString("hex");
  return [
    hex.slice(0, 8),
    hex.slice(8, 12),
    hex.slice(12, 16),
    hex.slice(16, 20),
    hex.slice(20),
  ].join("-");
}

export function createToolGateway({
  tenantRegistry,
  stablePrincipalRegistry,
  authorizer,
  catalog,
  store,
  credentialBroker,
  adapter,
  idFactory = uuidV7,
  clock = () => new Date().toISOString(),
}) {
  if (
    typeof tenantRegistry?.admitNewRequest !== "function" ||
    typeof stablePrincipalRegistry?.resolveActionIdentity !== "function" ||
    typeof authorizer?.enforce !== "function" ||
    typeof catalog?.operation !== "function" ||
    typeof catalog?.normalizeParameters !== "function" ||
    typeof store?.saveConfirmation !== "function" ||
    typeof store?.getConfirmation !== "function" ||
    typeof store?.beginExecution !== "function" ||
    typeof store?.completeExecution !== "function" ||
    typeof store?.failExecution !== "function" ||
    typeof credentialBroker?.issue !== "function" ||
    typeof credentialBroker?.revoke !== "function" ||
    typeof adapter?.execute !== "function" ||
    typeof idFactory !== "function" ||
    typeof clock !== "function"
  ) {
    fail("INVALID_CONFIGURATION", "C16 dependencies are incomplete.");
  }

  function generatedId(prefix) {
    const value = `${prefix}_${idFactory()}`;
    const pattern = new RegExp(`^${prefix}_${UUID_V7}$`);
    if (!pattern.test(value)) {
      fail("INVALID_CONFIGURATION", "C16 ID factory is invalid.");
    }
    return value;
  }

  function canonicalInstant(value, field) {
    if (
      typeof value !== "string" ||
      !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value) ||
      new Date(value).toISOString() !== value
    ) {
      fail("INVALID_CONFIGURATION", `${field} is invalid.`);
    }
    return value;
  }

  function auditIntent({
    tenantId,
    eventType,
    subjectId,
    operationId,
    identitySha256,
    authorizationSha256,
    normalizedParamSha256,
    resultReceiptSha256 = null,
    correlationId,
    occurredAt,
  }) {
    const value = {
      schemaVersion: "c16-c18-outbox-intent.v1",
      intentId: generatedId("tai"),
      tenantId,
      tenantKind: "SYNTHETIC",
      eventType,
      subjectId,
      operationId,
      identitySha256,
      authorizationSha256,
      catalogSha256: catalog.catalogSha256,
      normalizedParamSha256,
      resultReceiptSha256,
      correlationId,
      metadataOnly: true,
      occurredAt,
    };
    return deepFreeze({
      ...value,
      intentSha256: toolGatewaySha256(value),
    });
  }

  async function authorizeStage(serverContext, request, operation, stage) {
    const identityRequest = Object.freeze({
      sessionToken: request.sessionToken,
      expectedTenantId: serverContext.tenantId,
      delegationId: request.delegationId,
    });
    const identityContext = Object.freeze({
      synthetic: true,
      workloadTrustSource: serverContext.workloadTrustSource,
      workloadActorPrincipalId:
        serverContext.workloadActorPrincipalId,
    });
    let first;
    try {
      first = identityBinding(
        await stablePrincipalRegistry.resolveActionIdentity(
          identityContext,
          identityRequest,
        ),
        serverContext,
        request,
      );
    } catch (error) {
      if (error instanceof ToolGatewayError) throw error;
      fail("ACTION_IDENTITY_INVALID", "C05 identity resolution failed.");
    }
    const resourceId =
      `c16-${operation.authorizationResourceSuffix}`;
    const descriptor = Object.freeze({
      operationId: `C16_${stage}_TOOL`,
      surface: "TOOL_CALL",
      resourceId,
    });
    let authorized;
    try {
      authorized = authorizationBinding(
        await authorizer.enforce(
          Object.freeze({ ...serverContext }),
          Object.freeze({
            sessionToken: request.sessionToken,
            delegationId: request.delegationId,
            correlationId: request.correlationId,
            resourceId,
          }),
          Object.freeze({
            operationId: descriptor.operationId,
            surface: "TOOL_CALL",
            path: "tool-gateway",
            mode: "READ",
          }),
        ),
        first,
        serverContext,
        descriptor,
      );
    } catch (error) {
      if (error instanceof ToolGatewayError) throw error;
      fail("ACCESS_DENIED", "C06 denied the C16 action.");
    }
    let final;
    try {
      final = identityBinding(
        await stablePrincipalRegistry.resolveActionIdentity(
          identityContext,
          identityRequest,
        ),
        serverContext,
        request,
      );
    } catch (error) {
      if (error instanceof ToolGatewayError) throw error;
      fail("ACTION_IDENTITY_INVALID", "C05 identity resolution failed.");
    }
    if (toolGatewaySha256(first) !== toolGatewaySha256(final)) {
      fail(
        "ACTION_IDENTITY_CHANGED",
        "C05 identity changed during the C16 action.",
      );
    }
    let tenant;
    try {
      tenant = await tenantRegistry.admitNewRequest({
        tenantId: serverContext.tenantId,
        expectedTenantKind: "SYNTHETIC",
      });
    } catch {
      fail("TENANT_NOT_ACTIVE", "C03 admission failed.");
    }
    if (
      tenant?.tenantId !== serverContext.tenantId ||
      tenant?.tenantKind !== "SYNTHETIC" ||
      !Number.isSafeInteger(tenant?.lifecycleVersion) ||
      tenant.lifecycleVersion < 1
    ) {
      fail("TENANT_NOT_ACTIVE", "C03 admission failed.");
    }
    return {
      identity: final,
      authorization: authorized,
      tenant,
      scope: tenantScope(tenant, authorized, request.correlationId),
    };
  }

  return Object.freeze({
    async discover(serverContext, request) {
      validateServerContext(serverContext);
      validateEnvelope(request, []);
      const operation = catalog.operation(request.operationId);
      await authorizeStage(serverContext, request, operation, "DISCOVER");
      return deepFreeze({
        schemaVersion: "c16-tool-discovery.v1",
        catalogVersion: catalog.catalogVersion,
        catalogSha256: catalog.catalogSha256,
        operation: clone(operation),
        authorizationGranted: false,
      });
    },

    async confirm(serverContext, request) {
      validateServerContext(serverContext);
      validateEnvelope(request, ["idempotencyKey", "params"]);
      nonEmpty(request.idempotencyKey, "idempotencyKey", 128);
      const operation = catalog.operation(request.operationId);
      const normalizedParams = catalog.normalizeParameters(
        request.operationId,
        request.params,
      );
      const access = await authorizeStage(
        serverContext,
        request,
        operation,
        "CONFIRM",
      );
      const confirmedAt = canonicalInstant(clock(), "clock");
      const expiresAt = new Date(
        new Date(confirmedAt).getTime() + 120_000,
      ).toISOString();
      const identitySha256 = toolGatewaySha256(access.identity);
      const authorizationSha256 = toolGatewaySha256(
        access.authorization,
      );
      const normalizedParamSha256 = toolGatewaySha256(normalizedParams);
      const confirmationBase = {
        schemaVersion: "c16-tool-confirmation.v1",
        confirmationId: generatedId("tcf"),
        tenantId: serverContext.tenantId,
        tenantKind: "SYNTHETIC",
        operationId: operation.operationId,
        catalogVersion: catalog.catalogVersion,
        catalogSha256: catalog.catalogSha256,
        adapterVersion: operation.adapterVersion,
        normalizedParams,
        normalizedParamSha256,
        identityBinding: access.identity,
        identitySha256,
        authorizationBinding: access.authorization,
        authorizationSha256,
        confirmedAt,
        expiresAt,
      };
      const confirmation = deepFreeze({
        ...confirmationBase,
        confirmationSha256: toolGatewaySha256(confirmationBase),
      });
      const requestHash = toolGatewaySha256({
        operationId: operation.operationId,
        catalogVersion: catalog.catalogVersion,
        catalogSha256: catalog.catalogSha256,
        adapterVersion: operation.adapterVersion,
        normalizedParamSha256,
        identitySha256,
      });
      const audit = auditIntent({
        tenantId: serverContext.tenantId,
        eventType: "TOOL_PARAMETERS_CONFIRMED",
        subjectId: confirmation.confirmationId,
        operationId: operation.operationId,
        identitySha256,
        authorizationSha256,
        normalizedParamSha256,
        correlationId: request.correlationId,
        occurredAt: confirmedAt,
      });
      try {
        return await store.saveConfirmation(access.scope, {
          tenantId: serverContext.tenantId,
          idempotencyKey: request.idempotencyKey,
          requestHash,
          confirmation,
          auditIntent: audit,
        });
      } catch (error) {
        throw storageFailure(error);
      }
    },

    async execute(serverContext, request) {
      validateServerContext(serverContext);
      validateEnvelope(request, [
        "idempotencyKey",
        "confirmationId",
        "confirmationSha256",
        "expectedParamSha256",
      ]);
      nonEmpty(request.idempotencyKey, "idempotencyKey", 128);
      nonEmpty(request.confirmationId, "confirmationId", 64);
      if (
        !/^sha256:[a-f0-9]{64}$/.test(
          request.confirmationSha256 ?? "",
        ) ||
        !/^sha256:[a-f0-9]{64}$/.test(
          request.expectedParamSha256 ?? "",
        )
      ) {
        fail("CONFIRMATION_TAMPERED", "C16 confirmation hash is invalid.");
      }
      const operation = catalog.operation(request.operationId);
      const access = await authorizeStage(
        serverContext,
        request,
        operation,
        "EXECUTE",
      );
      let confirmation;
      try {
        confirmation = await store.getConfirmation(
          access.scope,
          request.confirmationId,
        );
      } catch (error) {
        throw storageFailure(error);
      }
      if (!confirmation) {
        fail(
          "CONFIRMATION_NOT_FOUND",
          "C16 confirmation was not found.",
        );
      }
      const confirmationBase = clone(confirmation);
      delete confirmationBase.confirmationSha256;
      if (
        confirmation.tenantId !== serverContext.tenantId ||
        confirmation.tenantKind !== "SYNTHETIC" ||
        confirmation.operationId !== operation.operationId ||
        confirmation.catalogVersion !== catalog.catalogVersion ||
        confirmation.catalogSha256 !== catalog.catalogSha256 ||
        confirmation.adapterVersion !== operation.adapterVersion ||
        confirmation.confirmationSha256 !==
          toolGatewaySha256(confirmationBase) ||
        confirmation.confirmationSha256 !==
          request.confirmationSha256 ||
        confirmation.normalizedParamSha256 !==
          request.expectedParamSha256 ||
        confirmation.normalizedParamSha256 !==
          toolGatewaySha256(confirmation.normalizedParams)
      ) {
        fail(
          "CONFIRMATION_TAMPERED",
          "C16 confirmation binding changed.",
        );
      }
      const currentIdentitySha256 = toolGatewaySha256(access.identity);
      if (
        confirmation.identitySha256 !==
          toolGatewaySha256(confirmation.identityBinding) ||
        confirmation.identitySha256 !== currentIdentitySha256
      ) {
        fail(
          "CONFIRMATION_AUTHORITY_CHANGED",
          "C16 confirmation authority changed.",
        );
      }
      const currentTime = new Date(
        canonicalInstant(clock(), "clock"),
      ).getTime();
      if (currentTime >= new Date(confirmation.expiresAt).getTime()) {
        fail("CONFIRMATION_EXPIRED", "C16 confirmation expired.");
      }
      const callBase = {
        schemaVersion: "c16-tool-call.v1",
        callId: generatedId("tcl"),
        tenantId: serverContext.tenantId,
        tenantKind: "SYNTHETIC",
        operationId: operation.operationId,
        confirmationId: confirmation.confirmationId,
        confirmationSha256: confirmation.confirmationSha256,
        catalogVersion: catalog.catalogVersion,
        catalogSha256: catalog.catalogSha256,
        adapterVersion: operation.adapterVersion,
        audience: operation.audience,
        normalizedParams: confirmation.normalizedParams,
        normalizedParamSha256: confirmation.normalizedParamSha256,
        identityBinding: access.identity,
        identitySha256: currentIdentitySha256,
        authorizationBinding: access.authorization,
        authorizationSha256: toolGatewaySha256(
          access.authorization,
        ),
        effectKey: toolGatewaySha256({
          tenantId: serverContext.tenantId,
          operationId: operation.operationId,
          confirmationSha256: confirmation.confirmationSha256,
        }),
        startedAt: new Date(currentTime).toISOString(),
      };
      const call = deepFreeze({
        ...callBase,
        callSha256: toolGatewaySha256(callBase),
      });
      const requestHash = toolGatewaySha256({
        operationId: call.operationId,
        confirmationId: call.confirmationId,
        confirmationSha256: call.confirmationSha256,
        normalizedParamSha256: call.normalizedParamSha256,
        identitySha256: call.identitySha256,
        catalogVersion: call.catalogVersion,
        catalogSha256: call.catalogSha256,
        adapterVersion: call.adapterVersion,
      });
      let started;
      try {
        started = await store.beginExecution(access.scope, {
          tenantId: serverContext.tenantId,
          idempotencyKey: request.idempotencyKey,
          requestHash,
          call,
        });
      } catch (error) {
        throw storageFailure(error);
      }
      if (started.status === "SUCCEEDED") return started;
      let storedCall;
      try {
        storedCall =
          started.callId === call.callId
            ? call
            : await store.getCall?.(access.scope, started.callId);
      } catch (error) {
        throw storageFailure(error);
      }
      const executable =
        storedCall && storedCall.normalizedParams
          ? storedCall
          : call;
      const adapterCall = deepFreeze({
        tenantId: executable.tenantId,
        tenantKind: executable.tenantKind,
        operationId: executable.operationId,
        callId: started.callId,
        effectKey: executable.effectKey,
        adapterVersion: executable.adapterVersion,
        audience: executable.audience,
        normalizedParams: executable.normalizedParams,
      });
      let capability;
      let outcome;
      try {
        capability = credentialBroker.issue({
          tenantId: adapterCall.tenantId,
          operationId: adapterCall.operationId,
          callId: adapterCall.callId,
          audience: adapterCall.audience,
        });
        outcome = await adapter.execute(adapterCall, capability);
      } catch (error) {
        try {
          await store.failExecution(access.scope, {
            callId: started.callId,
            errorCode:
              typeof error?.code === "string" &&
              /^[A-Z][A-Z0-9_]{0,63}$/.test(error.code)
                ? error.code
                : "ADAPTER_UNAVAILABLE",
          });
        } catch {
          // Preserve the Adapter failure.
        }
        fail(
          [
            "ADAPTER_UNAVAILABLE",
            "CREDENTIAL_REJECTED",
            "EFFECT_KEY_CONFLICT",
            "RATE_LIMITED",
            "SYNTHETIC_RECORD_NOT_FOUND",
          ].includes(error?.code)
            ? error.code
            : "ADAPTER_UNAVAILABLE",
          "C16 C0 Adapter failed closed.",
        );
      } finally {
        if (capability) {
          try {
            credentialBroker.revoke(capability);
          } catch {
            // Capability expiry or prior revocation cannot make it reusable.
          }
        }
      }
      const completedAt = canonicalInstant(clock(), "clock");
      const completionAudit = auditIntent({
        tenantId: serverContext.tenantId,
        eventType: "TOOL_CALL_COMPLETED",
        subjectId: started.callId,
        operationId: operation.operationId,
        identitySha256: currentIdentitySha256,
        authorizationSha256: toolGatewaySha256(
          access.authorization,
        ),
        normalizedParamSha256:
          confirmation.normalizedParamSha256,
        resultReceiptSha256: outcome.receipt.receiptSha256,
        correlationId: request.correlationId,
        occurredAt: completedAt,
      });
      try {
        return await store.completeExecution(access.scope, {
          callId: started.callId,
          result: outcome.result,
          receipt: outcome.receipt,
          auditIntent: completionAudit,
          completedAt,
        });
      } catch (error) {
        throw storageFailure(error);
      }
    },
  });
}
