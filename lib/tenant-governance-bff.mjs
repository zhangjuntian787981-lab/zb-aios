import { createHash } from "node:crypto";

const SYNTHETIC_TENANT =
  /^stn_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const REFERENCE =
  /^(?:evidence|synthetic):\/\/[A-Za-z0-9][A-Za-z0-9._~:/-]*$/;
const SHA256 = /^sha256:[0-9a-f]{64}$/;
const RESOURCE_ID = /^c02-[a-z0-9-]{1,123}$/;
const READ_FIELDS = Object.freeze({
  TENANT_CONFIG_VIEW: Object.freeze([
    "settingRef",
    "status",
    "version",
  ]),
  PRINCIPAL_ROLE_VIEW: Object.freeze([
    "principalRef",
    "principalType",
    "status",
    "roleRef",
  ]),
  KNOWLEDGE_RELEASE_VIEW: Object.freeze([
    "knowledgeRef",
    "status",
    "version",
  ]),
  SKILL_RELEASE_VIEW: Object.freeze([
    "skillRef",
    "releaseChannel",
    "status",
    "contentSha256",
  ]),
  QUOTA_VIEW: Object.freeze([
    "quotaRef",
    "metric",
    "limit",
    "used",
    "unit",
  ]),
  FORMAL_ARTIFACT_VIEW: Object.freeze([
    "artifactRef",
    "artifactSha256",
    "status",
    "decisionRef",
  ]),
  AUDIT_VIEW: Object.freeze([
    "auditRef",
    "eventType",
    "occurredAt",
    "traceId",
  ]),
  CONNECTOR_STAGE_VIEW: Object.freeze([
    "connectorRef",
    "templateRef",
    "stage",
    "status",
  ]),
  OBSERVABILITY_VIEW: Object.freeze([
    "metricRef",
    "value",
    "unit",
    "status",
  ]),
});
const WRITE_OPERATIONS = new Set([
  "TENANT_CONFIG_CHANGE",
  "PRINCIPAL_ROLE_CHANGE",
  "KNOWLEDGE_RELEASE_CHANGE",
  "SKILL_RELEASE_CHANGE",
  "QUOTA_CHANGE",
  "FORMAL_ARTIFACT_PUBLISH",
  "CONNECTOR_STAGE_CHANGE",
]);

export class TenantGovernanceBffError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "TenantGovernanceBffError";
    this.code = code;
  }
}

function fail(code, message) {
  throw new TenantGovernanceBffError(code, message);
}

function clone(value) {
  return structuredClone(value);
}

function deepFreeze(value) {
  if (!value || typeof value !== "object" || Object.isFrozen(value)) {
    return value;
  }
  for (const nested of Object.values(value)) deepFreeze(nested);
  return Object.freeze(value);
}

function canonical(value) {
  if (
    value === null ||
    typeof value === "boolean" ||
    typeof value === "number" ||
    typeof value === "string"
  ) {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map(canonical).join(",")}]`;
  }
  return `{${Object.keys(value)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`)
    .join(",")}}`;
}

function c02Sha256(value) {
  return `sha256:${createHash("sha256")
    .update(canonical(value))
    .digest("hex")}`;
}

function exactKeys(value, allowed, field) {
  if (
    !value ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    Object.getPrototypeOf(value) !== Object.prototype ||
    Object.keys(value).length !== allowed.length ||
    Object.keys(value).some((key) => !allowed.includes(key))
  ) {
    fail("INVALID_INPUT", `${field} has an invalid shape.`);
  }
}

function nonEmpty(value, field, max = 256) {
  if (
    typeof value !== "string" ||
    value.length < 1 ||
    value.length > max
  ) {
    fail("INVALID_INPUT", `${field} is invalid.`);
  }
}

function reference(value, field) {
  nonEmpty(value, field, 1024);
  if (!REFERENCE.test(value)) {
    fail("SYNTHETIC_BOUNDARY_VIOLATION", `${field} is not Synthetic.`);
  }
}

function resourceId(value) {
  if (!RESOURCE_ID.test(value ?? "")) {
    fail("INVALID_INPUT", "resourceId is invalid.");
  }
}

function validateItem(item, operationId) {
  exactKeys(item, READ_FIELDS[operationId], "view.item");
  for (const [field, value] of Object.entries(item)) {
    if (field.endsWith("Ref")) {
      reference(value, `view.item.${field}`);
    } else if (field.endsWith("Sha256")) {
      if (!SHA256.test(value ?? "")) {
        fail("CORE_RESULT_INVALID", `view.item.${field} is invalid.`);
      }
    } else if (["version", "limit", "used"].includes(field)) {
      const minimum = field === "version" ? 1 : 0;
      if (!Number.isSafeInteger(value) || value < minimum) {
        fail("CORE_RESULT_INVALID", `view.item.${field} is invalid.`);
      }
    } else if (field === "value") {
      if (typeof value !== "number" || !Number.isFinite(value)) {
        fail("CORE_RESULT_INVALID", "view.item.value is invalid.");
      }
    } else if (field === "occurredAt") {
      if (
        typeof value !== "string" ||
        !Number.isFinite(Date.parse(value)) ||
        new Date(value).toISOString() !== value
      ) {
        fail("CORE_RESULT_INVALID", "view.item.occurredAt is invalid.");
      }
    } else {
      nonEmpty(value, `view.item.${field}`, 256);
    }
  }
}

function validateContext(context) {
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
    !SYNTHETIC_TENANT.test(context.tenantId) ||
    !context.workloadActorPrincipalId
  ) {
    fail("UNTRUSTED_ROUTE", "C02 requires a trusted Synthetic route.");
  }
}

function validateReadRequest(request) {
  exactKeys(
    request,
    [
      "sessionToken",
      "delegationId",
      "correlationId",
      "operationId",
      "resourceId",
    ],
    "request",
  );
  nonEmpty(request.sessionToken, "sessionToken", 4096);
  nonEmpty(request.delegationId, "delegationId", 128);
  nonEmpty(request.correlationId, "correlationId", 128);
  if (!Object.hasOwn(READ_FIELDS, request.operationId)) {
    fail("OPERATION_NOT_ALLOWED", "C02 operation is not allowed.");
  }
  resourceId(request.resourceId);
}

function validateMutationRequest(request) {
  exactKeys(
    request,
    [
      "sessionToken",
      "delegationId",
      "correlationId",
      "idempotencyKey",
      "operationId",
      "resourceId",
      "expectedVersion",
      "candidateRef",
      "candidateSha256",
      "confirmation",
    ],
    "request",
  );
  nonEmpty(request.sessionToken, "sessionToken", 4096);
  nonEmpty(request.delegationId, "delegationId", 128);
  nonEmpty(request.correlationId, "correlationId", 128);
  nonEmpty(request.idempotencyKey, "idempotencyKey", 128);
  if (!WRITE_OPERATIONS.has(request.operationId)) {
    fail("OPERATION_NOT_ALLOWED", "C02 operation is not allowed.");
  }
  resourceId(request.resourceId);
  reference(request.candidateRef, "candidateRef");
  if (!SHA256.test(request.candidateSha256 ?? "")) {
    fail("INVALID_INPUT", "candidateSha256 is invalid.");
  }
  if (
    !Number.isSafeInteger(request.expectedVersion) ||
    request.expectedVersion < 1
  ) {
    fail("INVALID_INPUT", "expectedVersion is invalid.");
  }
  exactKeys(
    request.confirmation,
    [
      "confirmationRef",
      "confirmationSha256",
      "confirmedByHumanPrincipalId",
      "evidenceRefs",
    ],
    "confirmation",
  );
  reference(request.confirmation.confirmationRef, "confirmationRef");
  if (!SHA256.test(request.confirmation.confirmationSha256 ?? "")) {
    fail("INVALID_INPUT", "confirmationSha256 is invalid.");
  }
  nonEmpty(
    request.confirmation.confirmedByHumanPrincipalId,
    "confirmedByHumanPrincipalId",
    256,
  );
  if (
    !Array.isArray(request.confirmation.evidenceRefs) ||
    request.confirmation.evidenceRefs.length < 1
  ) {
    fail("CONFIRMATION_REQUIRED", "C02 requires confirmation evidence.");
  }
  request.confirmation.evidenceRefs.forEach((item) =>
    reference(item, "confirmation.evidenceRef"),
  );
}

async function authorize(authorizer, context, request, mode) {
  let result;
  const operationId = `C02_${request.operationId}`;
  try {
    result = await authorizer.enforce(
      context,
      {
        sessionToken: request.sessionToken,
        delegationId: request.delegationId,
        correlationId: request.correlationId,
        resourceId: request.resourceId,
      },
      {
        operationId,
        surface: "MANAGE",
        path: "tenant-governance",
        mode,
      },
    );
  } catch {
    fail("ACCESS_DENIED", "C02 authorization failed closed.");
  }
  exactKeys(
    result,
    [
      "trustSource",
      "tenantId",
      "humanPrincipalId",
      "workloadActorPrincipalId",
      "decisionId",
      "evidenceRef",
      "policyVersion",
      "resourceId",
      "operationId",
    ],
    "authorization",
  );
  if (
    result.trustSource !== "C06_BOUND_DECISION_EVIDENCE" ||
    result.tenantId !== context.tenantId ||
    result.workloadActorPrincipalId !==
      context.workloadActorPrincipalId ||
    result.resourceId !== request.resourceId ||
    result.operationId !== operationId ||
    typeof result.humanPrincipalId !== "string" ||
    result.humanPrincipalId.length < 1 ||
    typeof result.decisionId !== "string" ||
    result.decisionId.length < 1 ||
    typeof result.evidenceRef !== "string" ||
    result.evidenceRef.length < 1 ||
    typeof result.policyVersion !== "string" ||
    result.policyVersion.length < 1
  ) {
    fail("ACCESS_DENIED", "C02 authorization is unbound.");
  }
  reference(result.evidenceRef, "authorization.evidenceRef");
  return deepFreeze({
    tenantId: result.tenantId,
    humanPrincipalId: result.humanPrincipalId,
    workloadActorPrincipalId: result.workloadActorPrincipalId,
    decisionId: result.decisionId,
    evidenceRef: result.evidenceRef,
    policyVersion: result.policyVersion,
    correlationId: request.correlationId,
  });
}

function validateConfirmation(request, scope) {
  const confirmation = request.confirmation;
  if (
    confirmation.confirmedByHumanPrincipalId !==
      scope.humanPrincipalId ||
    confirmation.confirmationSha256 !==
      c02Sha256({
        tenantId: scope.tenantId,
        operationId: request.operationId,
        resourceId: request.resourceId,
        expectedVersion: request.expectedVersion,
        candidateRef: request.candidateRef,
        candidateSha256: request.candidateSha256,
        confirmationRef: confirmation.confirmationRef,
        confirmedByHumanPrincipalId:
          confirmation.confirmedByHumanPrincipalId,
        evidenceRefs: confirmation.evidenceRefs,
      })
  ) {
    fail("CONFIRMATION_INVALID", "C02 confirmation is unbound.");
  }
}

async function consumeConfirmation(
  confirmationVerifier,
  scope,
  request,
) {
  let result;
  try {
    result = await confirmationVerifier.consume(
      scope,
      deepFreeze({
        operationId: request.operationId,
        resourceId: request.resourceId,
        expectedVersion: request.expectedVersion,
        candidateRef: request.candidateRef,
        candidateSha256: request.candidateSha256,
        confirmationRef: request.confirmation.confirmationRef,
        confirmationSha256:
          request.confirmation.confirmationSha256,
      }),
    );
  } catch {
    fail(
      "CONFIRMATION_INVALID",
      "C02 trusted confirmation could not be consumed.",
    );
  }
  exactKeys(
    result,
    [
      "trustSource",
      "tenantId",
      "humanPrincipalId",
      "operationId",
      "resourceId",
      "expectedVersion",
      "candidateRef",
      "candidateSha256",
      "confirmationRef",
      "confirmationSha256",
      "consumptionId",
      "consumedAt",
      "evidenceRef",
      "expiresAt",
      "singleUse",
      "status",
    ],
    "confirmationVerification",
  );
  if (
    result.trustSource !== "TRUSTED_CONFIRMATION_CONSUMPTION" ||
    result.tenantId !== scope.tenantId ||
    result.humanPrincipalId !== scope.humanPrincipalId ||
    result.operationId !== request.operationId ||
    result.resourceId !== request.resourceId ||
    result.expectedVersion !== request.expectedVersion ||
    result.candidateRef !== request.candidateRef ||
    result.candidateSha256 !== request.candidateSha256 ||
    result.confirmationRef !==
      request.confirmation.confirmationRef ||
    result.confirmationSha256 !==
      request.confirmation.confirmationSha256 ||
    result.singleUse !== true ||
    typeof result.consumedAt !== "string" ||
    typeof result.expiresAt !== "string" ||
    !Number.isFinite(Date.parse(result.consumedAt)) ||
    !Number.isFinite(Date.parse(result.expiresAt)) ||
    new Date(result.consumedAt).toISOString() !== result.consumedAt ||
    new Date(result.expiresAt).toISOString() !== result.expiresAt ||
    Date.parse(result.consumedAt) >= Date.parse(result.expiresAt) ||
    result.status !== "CONSUMED"
  ) {
    fail(
      "CONFIRMATION_INVALID",
      "C02 trusted confirmation is unbound.",
    );
  }
  nonEmpty(result.consumptionId, "confirmation.consumptionId", 256);
  reference(result.evidenceRef, "confirmation.evidenceRef");
  return deepFreeze(clone(result));
}

function validateView(value, scope, request) {
  exactKeys(
    value,
    [
      "schemaVersion",
      "tenantId",
      "operationId",
      "resourceId",
      "resourceVersion",
      "items",
      "evidenceRefs",
      "allowedActions",
    ],
    "view",
  );
  if (
    value.schemaVersion !== "c02-governance-view.v1" ||
    value.tenantId !== scope.tenantId ||
    value.operationId !== request.operationId ||
    value.resourceId !== request.resourceId ||
    !Number.isSafeInteger(value.resourceVersion) ||
    value.resourceVersion < 1 ||
    !Array.isArray(value.items) ||
    !Array.isArray(value.evidenceRefs) ||
    value.evidenceRefs.length < 1 ||
    !Array.isArray(value.allowedActions) ||
    !value.allowedActions.includes(request.operationId) ||
    new Set(value.allowedActions).size !== value.allowedActions.length ||
    value.allowedActions.some(
      (operationId) =>
        !Object.hasOwn(READ_FIELDS, operationId) &&
        !WRITE_OPERATIONS.has(operationId),
    )
  ) {
    fail("CORE_RESULT_INVALID", "C02 Core view is unbound.");
  }
  for (const item of value.items) {
    validateItem(item, request.operationId);
  }
  value.evidenceRefs.forEach((item) => reference(item, "view.evidenceRef"));
}

function validateMutationReceipt(
  value,
  scope,
  request,
  confirmationVerification,
) {
  exactKeys(
    value,
    [
      "schemaVersion",
      "tenantId",
      "operationId",
      "resourceId",
      "resourceVersion",
      "candidateRef",
      "candidateSha256",
      "status",
      "auditRef",
      "evidenceRefs",
    ],
    "receipt",
  );
  if (
    value.schemaVersion !== "c02-governance-mutation-receipt.v1" ||
    value.tenantId !== scope.tenantId ||
    value.operationId !== request.operationId ||
    value.resourceId !== request.resourceId ||
    value.candidateRef !== request.candidateRef ||
    value.candidateSha256 !== request.candidateSha256 ||
    value.status !== "COMMITTED" ||
    !/^evidence:\/\/c18\//.test(value.auditRef ?? "") ||
    !Number.isSafeInteger(value.resourceVersion) ||
    value.resourceVersion !== request.expectedVersion + 1 ||
    !Array.isArray(value.evidenceRefs) ||
    value.evidenceRefs.length < 1
  ) {
    fail("CORE_RESULT_INVALID", "C02 Core receipt is unbound.");
  }
  reference(value.auditRef, "receipt.auditRef");
  value.evidenceRefs.forEach((item) =>
    reference(item, "receipt.evidenceRef"),
  );
  if (
    !value.evidenceRefs.includes(
      confirmationVerification.evidenceRef,
    )
  ) {
    fail(
      "CORE_RESULT_INVALID",
      "C02 trusted confirmation evidence was lost.",
    );
  }
}

export function createTenantGovernanceBff({
  authorizer,
  confirmationVerifier,
  corePort,
}) {
  if (
    typeof authorizer?.enforce !== "function" ||
    typeof confirmationVerifier?.consume !== "function" ||
    typeof corePort?.read !== "function" ||
    typeof corePort?.mutate !== "function"
  ) {
    fail("INVALID_CONFIGURATION", "C02 dependencies are incomplete.");
  }

  return Object.freeze({
    async read(serverContext, originalRequest) {
      const context = deepFreeze(clone(serverContext));
      const request = deepFreeze(clone(originalRequest));
      validateContext(context);
      validateReadRequest(request);
      const scope = await authorize(authorizer, context, request, "READ");
      let view;
      try {
        view = await corePort.read(scope, {
          operationId: request.operationId,
          resourceId: request.resourceId,
        });
      } catch {
        fail("CORE_UNAVAILABLE", "C02 Core read failed closed.");
      }
      validateView(view, scope, request);
      return deepFreeze({
        ...clone(view),
        authorityOwner: "PRODUCT_CORE",
        authorizationEvidenceRef: scope.evidenceRef,
      });
    },

    async mutate(serverContext, originalRequest) {
      const context = deepFreeze(clone(serverContext));
      const request = deepFreeze(clone(originalRequest));
      validateContext(context);
      validateMutationRequest(request);
      const scope = await authorize(
        authorizer,
        context,
        request,
        "WRITE",
      );
      validateConfirmation(request, scope);
      const confirmationVerification = await consumeConfirmation(
        confirmationVerifier,
        scope,
        request,
      );
      let receipt;
      try {
        receipt = await corePort.mutate(scope, {
          idempotencyKey: request.idempotencyKey,
          operationId: request.operationId,
          resourceId: request.resourceId,
          expectedVersion: request.expectedVersion,
          candidateRef: request.candidateRef,
          candidateSha256: request.candidateSha256,
          confirmation: clone(request.confirmation),
          confirmationVerification: clone(
            confirmationVerification,
          ),
        });
      } catch {
        fail("CORE_UNAVAILABLE", "C02 Core mutation failed closed.");
      }
      validateMutationReceipt(
        receipt,
        scope,
        request,
        confirmationVerification,
      );
      return deepFreeze({
        ...clone(receipt),
        authorityOwner: "PRODUCT_CORE",
        authorizationEvidenceRef: scope.evidenceRef,
      });
    },
  });
}
