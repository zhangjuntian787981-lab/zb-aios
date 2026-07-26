import { createHash, randomBytes } from "node:crypto";

const UUID_V7 =
  "[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}";
const SYNTHETIC_TENANT_ID = new RegExp(`^stn_${UUID_V7}$`);
const ROUTE_ID = new RegExp(`^mrt_${UUID_V7}$`);
const SHA256 = /^sha256:[0-9a-f]{64}$/;
const REFERENCE = /^(?:synthetic|fixture|test|policy):\/\/\S+$/;
const MODEL_REF = /^synthetic:\/\/c14\/models\/[a-z0-9-]+$/;
const PROVIDER_ID = /^c14-mock-[a-z0-9-]+$/;
const DATA_CLASSES = Object.freeze([
  "PUBLIC",
  "INTERNAL",
  "CONFIDENTIAL",
  "RESTRICTED",
]);
const PLANES = Object.freeze(["LOCAL", "CLOUD"]);
const TASK_CAPABILITIES = Object.freeze([
  "CHAT",
  "STRUCTURED_OUTPUT",
  "LONG_CONTEXT",
  "REASONING",
]);
const ROUTE_STATES = Object.freeze(["PREPARED", "SUCCEEDED", "FAILED"]);

export class ModelGatewayError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "ModelGatewayError";
    this.code = code;
  }
}

function fail(code, message) {
  throw new ModelGatewayError(code, message);
}

function clone(value) {
  return value === undefined ? undefined : structuredClone(value);
}

function deepFreeze(value) {
  if (!value || typeof value !== "object" || Object.isFrozen(value)) {
    return value;
  }
  for (const nested of Object.values(value)) {
    deepFreeze(nested);
  }
  return Object.freeze(value);
}

function exactKeys(value, allowed, field) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    fail("INVALID_INPUT", `${field} must be an object.`);
  }
  if (Object.keys(value).some((key) => !allowed.includes(key))) {
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

function positiveInteger(value, field, { zero = false } = {}) {
  if (
    !Number.isSafeInteger(value) ||
    value < (zero ? 0 : 1)
  ) {
    fail("INVALID_INPUT", `${field} is invalid.`);
  }
}

function canonicalInstant(value, field) {
  if (
    typeof value !== "string" ||
    !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value) ||
    new Date(value).toISOString() !== value
  ) {
    fail("INVALID_INPUT", `${field} must be a canonical UTC instant.`);
  }
  return value;
}

function canonicalize(value) {
  if (
    value === null ||
    typeof value === "boolean" ||
    typeof value === "string"
  ) {
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      fail("INVALID_INPUT", "Only finite JSON numbers are supported.");
    }
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
  fail("INVALID_INPUT", "Only JSON values are supported.");
}

export function modelGatewaySha256(value) {
  return `sha256:${createHash("sha256")
    .update(typeof value === "string" ? value : canonicalize(value))
    .digest("hex")}`;
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

function generatedRouteId(idFactory) {
  const value = `mrt_${idFactory()}`;
  if (!ROUTE_ID.test(value)) {
    fail("INVALID_CONFIGURATION", "C14 route ID factory is invalid.");
  }
  return value;
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
      "C14 accepts only trusted Synthetic server context.",
    );
  }
  nonEmpty(
    context.workloadActorPrincipalId,
    "workloadActorPrincipalId",
    128,
  );
}

function validateRequest(request) {
  exactKeys(
    request,
    [
      "sessionToken",
      "delegationId",
      "idempotencyKey",
      "correlationId",
      "taskRef",
      "inputRef",
      "inputSha256",
    ],
    "request",
  );
  for (const field of [
    "sessionToken",
    "delegationId",
    "idempotencyKey",
    "correlationId",
    "taskRef",
    "inputRef",
  ]) {
    nonEmpty(request[field], field, field === "inputRef" ? 1024 : 256);
  }
  if (
    !REFERENCE.test(request.taskRef) ||
    !REFERENCE.test(request.inputRef) ||
    !SHA256.test(request.inputSha256 ?? "")
  ) {
    fail(
      "SYNTHETIC_BOUNDARY_VIOLATION",
      "C14 request references must be frozen Synthetic references.",
    );
  }
}

function validateIdentity(identity, context) {
  if (
    identity?.tenantId !== context.tenantId ||
    identity?.tenantKind !== "SYNTHETIC" ||
    identity?.trustSource !==
      "VERIFIED_SESSION_IDENTITY_LINK_AND_WORKLOAD_CONTEXT" ||
    identity?.authorizationStatus !== "NOT_EVALUATED" ||
    identity?.workloadActor?.principalId !==
      context.workloadActorPrincipalId ||
    typeof identity?.humanSubject?.principalId !== "string" ||
    !Number.isSafeInteger(identity?.humanSubject?.securityEpoch) ||
    identity.humanSubject.securityEpoch < 1 ||
    !Number.isSafeInteger(identity?.workloadActor?.securityEpoch) ||
    identity.workloadActor.securityEpoch < 1 ||
    !Array.isArray(identity?.delegationChain) ||
    identity.delegationChain.length < 1
  ) {
    fail("ACTION_IDENTITY_INVALID", "C05 action identity is invalid.");
  }
}

function identityBinding(identity) {
  return Object.freeze({
    humanPrincipalId: identity.humanSubject.principalId,
    humanSecurityEpoch: identity.humanSubject.securityEpoch,
    workloadActorPrincipalId: identity.workloadActor.principalId,
    workloadActorSecurityEpoch: identity.workloadActor.securityEpoch,
    leafDelegationId:
      identity.delegationChain[identity.delegationChain.length - 1]
        .delegationId,
    delegationChainSha256: modelGatewaySha256(identity.delegationChain),
    purposeRef: identity.purposeRef,
  });
}

function validateAuthorization(authorization, identity, context, resourceId) {
  const expected = identityBinding(identity);
  if (
    authorization?.trustSource !== "C06_BOUND_DECISION_EVIDENCE" ||
    authorization?.tenantId !== context.tenantId ||
    authorization?.surface !== "MANAGE" ||
    authorization?.resourceId !== resourceId ||
    authorization?.humanPrincipalId !== expected.humanPrincipalId ||
    authorization?.humanSecurityEpoch !== expected.humanSecurityEpoch ||
    authorization?.workloadActorPrincipalId !==
      expected.workloadActorPrincipalId ||
    authorization?.workloadActorSecurityEpoch !==
      expected.workloadActorSecurityEpoch ||
    authorization?.leafDelegationId !== expected.leafDelegationId ||
    authorization?.delegationChainSha256 !==
      expected.delegationChainSha256 ||
    authorization?.purposeRef !== expected.purposeRef
  ) {
    fail(
      "AUTHORIZATION_BINDING_MISMATCH",
      "C06 decision is not bound to the C05 action identity.",
    );
  }
  for (const field of ["decisionId", "evidenceRef", "policyVersion"]) {
    nonEmpty(authorization[field], field, 512);
  }
}

function validateAdmission(admission, tenantId) {
  if (
    admission?.tenantId !== tenantId ||
    admission?.tenantKind !== "SYNTHETIC" ||
    admission?.trustSource !== "VERIFIED_SERVER_CONTEXT" ||
    !Number.isSafeInteger(admission?.lifecycleVersion) ||
    admission.lifecycleVersion < 1
  ) {
    fail("TENANT_NOT_ACTIVE", "C03 admission is invalid.");
  }
}

function sortedCapabilities(value, field) {
  if (
    !Array.isArray(value) ||
    value.length === 0 ||
    value.some((item) => !TASK_CAPABILITIES.includes(item)) ||
    new Set(value).size !== value.length
  ) {
    fail("INVALID_CATALOG", `${field} is invalid.`);
  }
  return [...value].sort();
}

function validateCatalog(document) {
  exactKeys(
    document,
    [
      "schemaVersion",
      "catalogVersion",
      "phase",
      "dataClassification",
      "enterpriseConnectors",
      "models",
      "tenantPolicies",
      "tasks",
    ],
    "catalog",
  );
  if (
    document.schemaVersion !== "1.0.0" ||
    document.phase !== "P1_SYNTHETIC_ONLY" ||
    document.dataClassification !== "SYNTHETIC_ONLY" ||
    document.enterpriseConnectors !== "C0_DISABLED" ||
    !Array.isArray(document.models) ||
    document.models.length < 2 ||
    !Array.isArray(document.tenantPolicies) ||
    document.tenantPolicies.length !== 3 ||
    !Array.isArray(document.tasks) ||
    document.tasks.length < 1
  ) {
    fail("INVALID_CATALOG", "C14 catalog envelope is invalid.");
  }
  nonEmpty(document.catalogVersion, "catalogVersion", 128);
}

function normalizeModel(model) {
  exactKeys(
    model,
    [
      "modelRef",
      "version",
      "contentSha256",
      "providerId",
      "plane",
      "regions",
      "allowedDataClasses",
      "capabilities",
      "contextWindow",
      "qualityScore",
      "p95LatencyMs",
      "inputMicrousdPerMillion",
      "outputMicrousdPerMillion",
      "rateVersion",
      "active",
      "canary",
    ],
    "model",
  );
  if (
    !MODEL_REF.test(model.modelRef ?? "") ||
    !SHA256.test(model.contentSha256 ?? "") ||
    !PROVIDER_ID.test(model.providerId ?? "") ||
    !PLANES.includes(model.plane) ||
    !Array.isArray(model.regions) ||
    model.regions.length === 0 ||
    model.regions.some(
      (region) => !["ANY", "CN", "EU", "US"].includes(region),
    ) ||
    !Array.isArray(model.allowedDataClasses) ||
    model.allowedDataClasses.length === 0 ||
    model.allowedDataClasses.some(
      (dataClass) => !DATA_CLASSES.includes(dataClass),
    ) ||
    typeof model.active !== "boolean" ||
    typeof model.canary !== "boolean"
  ) {
    fail("INVALID_CATALOG", "C14 model entry is invalid.");
  }
  nonEmpty(model.version, "model.version", 128);
  nonEmpty(model.rateVersion, "model.rateVersion", 128);
  sortedCapabilities(model.capabilities, "model.capabilities");
  for (const field of [
    "contextWindow",
    "qualityScore",
    "p95LatencyMs",
    "inputMicrousdPerMillion",
    "outputMicrousdPerMillion",
  ]) {
    positiveInteger(model[field], `model.${field}`, {
      zero: field.includes("Microusd"),
    });
  }
  const binding = clone(model);
  delete binding.contentSha256;
  if (modelGatewaySha256(binding) !== model.contentSha256) {
    fail(
      "INVALID_CATALOG",
      "C14 model content hash does not match its immutable binding.",
    );
  }
  return deepFreeze(clone(model));
}

function normalizeTenantPolicy(policy, knownModels) {
  exactKeys(
    policy,
    [
      "tenantId",
      "policyVersion",
      "authorizationResourceId",
      "region",
      "allowedModelRefs",
      "cloudAllowedDataClasses",
      "dailyTokenLimit",
      "dailyCostMicrousdLimit",
      "canaryPercent",
    ],
    "tenantPolicy",
  );
  if (
    !SYNTHETIC_TENANT_ID.test(policy.tenantId ?? "") ||
    !["CN", "EU", "US"].includes(policy.region) ||
    !Array.isArray(policy.allowedModelRefs) ||
    policy.allowedModelRefs.length === 0 ||
    policy.allowedModelRefs.some((modelRef) => !knownModels.has(modelRef)) ||
    new Set(policy.allowedModelRefs).size !==
      policy.allowedModelRefs.length ||
    !Array.isArray(policy.cloudAllowedDataClasses) ||
    policy.cloudAllowedDataClasses.some(
      (dataClass) => !DATA_CLASSES.includes(dataClass),
    )
  ) {
    fail("INVALID_CATALOG", "C14 Tenant policy is invalid.");
  }
  nonEmpty(policy.policyVersion, "policyVersion", 128);
  nonEmpty(
    policy.authorizationResourceId,
    "authorizationResourceId",
    128,
  );
  positiveInteger(policy.dailyTokenLimit, "dailyTokenLimit");
  positiveInteger(
    policy.dailyCostMicrousdLimit,
    "dailyCostMicrousdLimit",
  );
  if (
    !Number.isSafeInteger(policy.canaryPercent) ||
    policy.canaryPercent < 0 ||
    policy.canaryPercent > 100
  ) {
    fail("INVALID_CATALOG", "C14 canaryPercent is invalid.");
  }
  return deepFreeze(clone(policy));
}

function normalizeTask(task) {
  exactKeys(
    task,
    [
      "taskRef",
      "requiredCapabilities",
      "minimumQualityScore",
      "maxOutputTokens",
    ],
    "task",
  );
  if (!REFERENCE.test(task.taskRef ?? "")) {
    fail("INVALID_CATALOG", "C14 task reference is invalid.");
  }
  sortedCapabilities(task.requiredCapabilities, "task.requiredCapabilities");
  positiveInteger(task.minimumQualityScore, "minimumQualityScore");
  positiveInteger(task.maxOutputTokens, "maxOutputTokens");
  return deepFreeze(clone(task));
}

export function createSyntheticModelCatalog(document) {
  validateCatalog(document);
  const models = new Map();
  for (const item of document.models) {
    const model = normalizeModel(item);
    if (models.has(model.modelRef)) {
      fail("INVALID_CATALOG", "C14 model reference is duplicated.");
    }
    models.set(model.modelRef, model);
  }
  const policies = new Map();
  for (const item of document.tenantPolicies) {
    const policy = normalizeTenantPolicy(item, models);
    if (policies.has(policy.tenantId)) {
      fail("INVALID_CATALOG", "C14 Tenant policy is duplicated.");
    }
    policies.set(policy.tenantId, policy);
  }
  const tasks = new Map();
  for (const item of document.tasks) {
    const task = normalizeTask(item);
    if (tasks.has(task.taskRef)) {
      fail("INVALID_CATALOG", "C14 task reference is duplicated.");
    }
    tasks.set(task.taskRef, task);
  }
  const digest = modelGatewaySha256(document);

  return Object.freeze({
    catalogVersion: document.catalogVersion,
    digest,
    tenantPolicy(tenantId) {
      const value = policies.get(tenantId);
      if (!value) {
        fail("TENANT_POLICY_NOT_FOUND", "C14 Tenant policy is missing.");
      }
      return value;
    },
    task(taskRef) {
      const value = tasks.get(taskRef);
      if (!value) {
        fail("TASK_NOT_FOUND", "C14 task is not registered.");
      }
      return value;
    },
    model(modelRef) {
      return models.get(modelRef) ?? null;
    },
  });
}

function dateBucket(instant) {
  return instant.slice(0, 10);
}

function routeView(route) {
  return Object.freeze(clone(route));
}

function publicRouteView(route) {
  return Object.freeze({
    routeId: route.routeId,
    status: route.status,
    version: route.version,
    requestHash: route.requestHash,
    taskRef: route.taskRef,
    inputRef: route.inputRef,
    inputSha256: route.inputSha256,
    dataClassification: route.dataClassification,
    requiredPlane: route.requiredPlane,
    tenantRegion: route.tenantRegion,
    catalogVersion: route.catalogVersion,
    catalogSha256: route.catalogSha256,
    tenantPolicyVersion: route.tenantPolicyVersion,
    selectedModel: clone(route.selectedModel),
    responseRef: route.responseRef,
    responseSha256: route.responseSha256,
    usage: clone(route.usage),
    rateVersion: route.rateVersion,
    costMicrousd: route.costMicrousd,
  });
}

export function createMemoryModelGatewayStore() {
  const tenants = new Map();
  const locks = new Map();

  function tenantState(tenantId) {
    if (!tenants.has(tenantId)) {
      tenants.set(tenantId, {
        routes: new Map(),
        idempotency: new Map(),
      });
    }
    return tenants.get(tenantId);
  }

  async function withLock(tenantId, operation) {
    const previous = locks.get(tenantId) ?? Promise.resolve();
    let release;
    const next = new Promise((resolve) => {
      release = resolve;
    });
    const chained = previous.then(() => next);
    locks.set(tenantId, chained);
    await previous;
    try {
      return await operation();
    } finally {
      release();
      if (locks.get(tenantId) === chained) locks.delete(tenantId);
    }
  }

  function validateScope(scope) {
    if (
      scope?.trustSource !== "C07_VERIFIED_TENANT_SCOPE" ||
      scope?.tenantKind !== "SYNTHETIC" ||
      !SYNTHETIC_TENANT_ID.test(scope?.tenantId ?? "")
    ) {
      fail("TENANT_SCOPE_VIOLATION", "C14 requires C07 Tenant scope.");
    }
  }

  return Object.freeze({
    async prepareRoute(scope, metadata, record, quota) {
      validateScope(scope);
      return withLock(scope.tenantId, async () => {
        const state = tenantState(scope.tenantId);
        const existingId = state.idempotency.get(metadata.idempotencyKey);
        if (existingId) {
          const existing = state.routes.get(existingId);
          if (existing.requestHash !== metadata.requestHash) {
            fail(
              "IDEMPOTENCY_CONFLICT",
              "C14 idempotency key has another request hash.",
            );
          }
          return { duplicate: true, route: routeView(existing) };
        }
        const bucket = dateBucket(record.createdAt);
        const active = [...state.routes.values()].filter(
          (route) =>
            dateBucket(route.createdAt) === bucket &&
            route.status !== "FAILED",
        );
        const tokens = active.reduce(
          (sum, route) =>
            sum +
            (route.usage?.totalTokens ??
              route.reservedInputTokens +
                route.reservedOutputTokens),
          0,
        );
        const cost = active.reduce(
          (sum, route) =>
            sum +
            (route.costMicrousd ?? route.reservedCostMicrousd),
          0,
        );
        if (
          tokens +
              record.reservedInputTokens +
              record.reservedOutputTokens >
            quota.dailyTokenLimit ||
          cost + record.reservedCostMicrousd >
            quota.dailyCostMicrousdLimit
        ) {
          fail("QUOTA_EXCEEDED", "C14 Tenant quota is exhausted.");
        }
        const stored = routeView(record);
        state.routes.set(stored.routeId, stored);
        state.idempotency.set(metadata.idempotencyKey, stored.routeId);
        return { duplicate: false, route: routeView(stored) };
      });
    },
    async completeRoute(scope, routeId, expectedVersion, completion) {
      validateScope(scope);
      return withLock(scope.tenantId, async () => {
        const state = tenantState(scope.tenantId);
        const route = state.routes.get(routeId);
        if (!route) fail("ROUTE_NOT_FOUND", "C14 route was not found.");
        if (route.status === "SUCCEEDED") return routeView(route);
        if (
          route.status !== "PREPARED" ||
          route.version !== expectedVersion
        ) {
          fail("STALE_VERSION", "C14 route version is stale.");
        }
        if (
          !Number.isSafeInteger(completion?.costMicrousd) ||
          completion.costMicrousd < 0 ||
          completion.costMicrousd > route.reservedCostMicrousd
        ) {
          fail(
            "QUOTA_INVARIANT_VIOLATION",
            "C14 actual cost exceeds the frozen reservation.",
          );
        }
        const updated = routeView({
          ...route,
          ...clone(completion),
          status: "SUCCEEDED",
          version: route.version + 1,
        });
        state.routes.set(routeId, updated);
        return routeView(updated);
      });
    },
    async failRoute(scope, routeId, expectedVersion, failure) {
      validateScope(scope);
      return withLock(scope.tenantId, async () => {
        const state = tenantState(scope.tenantId);
        const route = state.routes.get(routeId);
        if (!route) fail("ROUTE_NOT_FOUND", "C14 route was not found.");
        if (route.status === "FAILED") return routeView(route);
        if (
          route.status !== "PREPARED" ||
          route.version !== expectedVersion
        ) {
          fail("STALE_VERSION", "C14 route version is stale.");
        }
        const updated = routeView({
          ...route,
          ...clone(failure),
          status: "FAILED",
          version: route.version + 1,
        });
        state.routes.set(routeId, updated);
        return routeView(updated);
      });
    },
    async readRoute(scope, routeId) {
      validateScope(scope);
      const route = tenantState(scope.tenantId).routes.get(routeId);
      return route ? routeView(route) : null;
    },
  });
}

function validateDataPolicy(value, request, tenantPolicy) {
  exactKeys(
    value,
    [
      "trustSource",
      "inputRef",
      "inputSha256",
      "dataClassification",
      "inputTokens",
      "requiredPlane",
    ],
    "dataPolicy",
  );
  if (
    value.trustSource !== "C14_SYNTHETIC_DATA_POLICY" ||
    value.inputRef !== request.inputRef ||
    value.inputSha256 !== request.inputSha256 ||
    !DATA_CLASSES.includes(value.dataClassification) ||
    !["ANY", "LOCAL_ONLY"].includes(value.requiredPlane)
  ) {
    fail("DATA_POLICY_INVALID", "C14 data policy is invalid.");
  }
  positiveInteger(value.inputTokens, "inputTokens");
  if (
    value.dataClassification === "RESTRICTED" &&
    value.requiredPlane !== "LOCAL_ONLY"
  ) {
    fail(
      "DATA_POLICY_INVALID",
      "Restricted Synthetic data must remain local.",
    );
  }
  if (
    !tenantPolicy.cloudAllowedDataClasses.includes(
      value.dataClassification,
    )
  ) {
    return Object.freeze({ ...value, requiredPlane: "LOCAL_ONLY" });
  }
  return Object.freeze(clone(value));
}

function canaryEligible(requestHash, percent) {
  if (percent === 0) return false;
  const bucket = Number.parseInt(requestHash.slice(-8), 16) % 100;
  return bucket < percent;
}

function filterModels({
  catalog,
  tenantPolicy,
  task,
  dataPolicy,
  requestHash,
}) {
  const allowCanary = canaryEligible(
    requestHash,
    tenantPolicy.canaryPercent,
  );
  const evaluated = [];
  for (const modelRef of tenantPolicy.allowedModelRefs) {
    const model = catalog.model(modelRef);
    const reasons = [];
    if (!model?.active) reasons.push("INACTIVE");
    if (
      !model?.allowedDataClasses.includes(
        dataPolicy.dataClassification,
      )
    ) {
      reasons.push("DATA_CLASS_DENIED");
    }
    if (
      model?.plane === "CLOUD" &&
      dataPolicy.requiredPlane === "LOCAL_ONLY"
    ) {
      reasons.push("LOCAL_ONLY");
    }
    if (
      model &&
      !model.regions.includes("ANY") &&
      !model.regions.includes(tenantPolicy.region)
    ) {
      reasons.push("REGION_DENIED");
    }
    if (
      task.requiredCapabilities.some(
        (capability) => !model?.capabilities.includes(capability),
      )
    ) {
      reasons.push("CAPABILITY_MISSING");
    }
    if (
      model?.contextWindow <
      dataPolicy.inputTokens + task.maxOutputTokens
    ) {
      reasons.push("CONTEXT_TOO_SMALL");
    }
    if (model?.qualityScore < task.minimumQualityScore) {
      reasons.push("QUALITY_TOO_LOW");
    }
    if (model?.canary && !allowCanary) {
      reasons.push("CANARY_NOT_SELECTED");
    }
    evaluated.push(
      Object.freeze({
        modelRef,
        modelVersion: model?.version ?? null,
        modelSha256: model?.contentSha256 ?? null,
        plane: model?.plane ?? null,
        allowed: reasons.length === 0,
        reasons,
      }),
    );
  }
  const allowed = evaluated
    .filter((entry) => entry.allowed)
    .map((entry) => catalog.model(entry.modelRef))
    .sort(
      (left, right) =>
        right.qualityScore - left.qualityScore ||
        calculateCost(left, {
          inputTokens: dataPolicy.inputTokens,
          outputTokens: task.maxOutputTokens,
        }) -
          calculateCost(right, {
            inputTokens: dataPolicy.inputTokens,
            outputTokens: task.maxOutputTokens,
          }) ||
        left.p95LatencyMs - right.p95LatencyMs ||
        left.modelRef.localeCompare(right.modelRef),
    );
  return { evaluated, allowed };
}

function calculateCost(model, usage) {
  const denominator = 1_000_000n;
  const ceilCost = (tokens, rate) => {
    const numerator = BigInt(tokens) * BigInt(rate);
    return (numerator + denominator - 1n) / denominator;
  };
  const cost =
    ceilCost(usage.inputTokens, model.inputMicrousdPerMillion) +
    ceilCost(usage.outputTokens, model.outputMicrousdPerMillion);
  if (cost > BigInt(Number.MAX_SAFE_INTEGER)) {
    fail("COST_OUT_OF_RANGE", "C14 calculated cost is out of range.");
  }
  return Number(cost);
}

function validateProviderReceipt(receipt, expected) {
  exactKeys(
    receipt,
    [
      "trustSource",
      "effectKey",
      "providerId",
      "modelRef",
      "modelVersion",
      "outcome",
      "responseRef",
      "responseSha256",
      "inputTokens",
      "outputTokens",
      "providerRequestId",
    ],
    "providerReceipt",
  );
  if (
    receipt.trustSource !== "C14_C0_MOCK_PROVIDER_RECEIPT" ||
    receipt.effectKey !== expected.effectKey ||
    receipt.providerId !== expected.providerId ||
    receipt.modelRef !== expected.modelRef ||
    receipt.modelVersion !== expected.modelVersion ||
    !["SUCCEEDED", "FAILED"].includes(receipt.outcome) ||
    typeof receipt.providerRequestId !== "string" ||
    receipt.providerRequestId.length === 0
  ) {
    fail(
      "PROVIDER_RECEIPT_INVALID",
      "C14 provider receipt binding is invalid.",
    );
  }
  if (receipt.outcome === "SUCCEEDED") {
    if (
      !REFERENCE.test(receipt.responseRef ?? "") ||
      !SHA256.test(receipt.responseSha256 ?? "")
    ) {
      fail(
        "PROVIDER_RECEIPT_INVALID",
        "C14 provider result evidence is invalid.",
      );
    }
    positiveInteger(receipt.inputTokens, "receipt.inputTokens");
    positiveInteger(receipt.outputTokens, "receipt.outputTokens", {
      zero: true,
    });
  } else if (
    receipt.responseRef !== null ||
    receipt.responseSha256 !== null ||
    receipt.inputTokens !== 0 ||
    receipt.outputTokens !== 0
  ) {
    fail(
      "PROVIDER_RECEIPT_INVALID",
      "C14 failed provider receipt contains usage or output.",
    );
  }
  return Object.freeze(clone(receipt));
}

function normalizeDependency(error, fallback) {
  if (error instanceof ModelGatewayError) return error;
  if (
    ["TENANT_NOT_ACTIVE", "TENANT_DELETED", "TENANT_NOT_FOUND"].includes(
      error?.code,
    )
  ) {
    return new ModelGatewayError(
      "TENANT_NOT_ACTIVE",
      "Synthetic Tenant is not accepting C14 requests.",
    );
  }
  return new ModelGatewayError(fallback, "C14 dependency failed closed.");
}

const STORE_ERROR_CODES = new Set([
  "APPEND_ONLY_VIOLATION",
  "IDEMPOTENCY_CONFLICT",
  "QUOTA_EXCEEDED",
  "ROUTE_NOT_FOUND",
  "STALE_VERSION",
  "TENANT_SCOPE_VIOLATION",
]);

function normalizeStoreDependency(error) {
  if (error instanceof ModelGatewayError) return error;
  if (
    error?.name === "PostgresModelGatewayStoreError" &&
    STORE_ERROR_CODES.has(error.code)
  ) {
    return new ModelGatewayError(
      error.code,
      "C14 storage rejected the request.",
    );
  }
  return normalizeDependency(error, "STORE_UNAVAILABLE");
}

export function createModelGateway({
  tenantRegistry,
  stablePrincipalRegistry,
  authorizer,
  catalog,
  dataPolicyResolver,
  providerInvoker,
  store,
  idFactory = uuidV7,
  clock = () => new Date().toISOString(),
}) {
  if (
    typeof tenantRegistry?.admitNewRequest !== "function" ||
    typeof stablePrincipalRegistry?.resolveActionIdentity !== "function" ||
    typeof authorizer?.enforce !== "function" ||
    typeof catalog?.tenantPolicy !== "function" ||
    typeof catalog?.task !== "function" ||
    typeof catalog?.model !== "function" ||
    typeof dataPolicyResolver?.resolve !== "function" ||
    typeof providerInvoker?.invoke !== "function" ||
    typeof store?.prepareRoute !== "function" ||
    typeof store?.completeRoute !== "function" ||
    typeof store?.failRoute !== "function" ||
    typeof store?.readRoute !== "function" ||
    typeof idFactory !== "function" ||
    typeof clock !== "function"
  ) {
    fail("INVALID_CONFIGURATION", "C14 dependencies are incomplete.");
  }

  async function resolveIdentity(serverContext, request) {
    let identity;
    try {
      identity = await stablePrincipalRegistry.resolveActionIdentity(
        Object.freeze({
          synthetic: true,
          workloadTrustSource: serverContext.workloadTrustSource,
          workloadActorPrincipalId:
            serverContext.workloadActorPrincipalId,
        }),
        Object.freeze({
          sessionToken: request.sessionToken,
          expectedTenantId: serverContext.tenantId,
          delegationId: request.delegationId,
        }),
      );
    } catch (error) {
      throw normalizeDependency(error, "ACTION_IDENTITY_INVALID");
    }
    validateIdentity(identity, serverContext);
    return Object.freeze(clone(identity));
  }

  async function trustedInputs(serverContext, request, tenantPolicy) {
    const firstIdentity = await resolveIdentity(serverContext, request);
    let authorization;
    try {
      authorization = await authorizer.enforce(
        Object.freeze({ ...serverContext }),
        Object.freeze({
          sessionToken: request.sessionToken,
          delegationId: request.delegationId,
          resourceId: tenantPolicy.authorizationResourceId,
          correlationId: request.correlationId,
        }),
        Object.freeze({
          operationId: "C14_ROUTE_MODEL",
          surface: "MANAGE",
          path: "model-gateway",
          mode: "WRITE",
        }),
      );
    } catch (error) {
      throw normalizeDependency(
        error?.code === "AUTHORIZATION_UNAVAILABLE"
          ? error
          : new ModelGatewayError("ACCESS_DENIED", "C14 route denied."),
        error?.code === "AUTHORIZATION_UNAVAILABLE"
          ? "AUTHORIZATION_UNAVAILABLE"
          : "ACCESS_DENIED",
      );
    }
    validateAuthorization(
      authorization,
      firstIdentity,
      serverContext,
      tenantPolicy.authorizationResourceId,
    );
    const finalIdentity = await resolveIdentity(serverContext, request);
    if (
      modelGatewaySha256(firstIdentity) !==
      modelGatewaySha256(finalIdentity)
    ) {
      fail(
        "ACTION_IDENTITY_CHANGED",
        "C05 action identity changed during C14 authorization.",
      );
    }
    let admission;
    try {
      admission = await tenantRegistry.admitNewRequest({
        tenantId: serverContext.tenantId,
        expectedTenantKind: "SYNTHETIC",
      });
    } catch (error) {
      throw normalizeDependency(error, "DEPENDENCY_UNAVAILABLE");
    }
    validateAdmission(admission, serverContext.tenantId);
    return Object.freeze({
      identity: finalIdentity,
      authorization: Object.freeze(clone(authorization)),
      scope: Object.freeze({
        trustSource: "C07_VERIFIED_TENANT_SCOPE",
        tenantId: serverContext.tenantId,
        tenantKind: "SYNTHETIC",
        lifecycleVersion: admission.lifecycleVersion,
        operationId: "C14_ROUTE_MODEL",
        storagePath: "model-gateway",
        correlationId: request.correlationId,
        decisionId: authorization.decisionId,
        evidenceRef: authorization.evidenceRef,
        policyVersion: authorization.policyVersion,
      }),
    });
  }

  async function route(serverContext, request) {
    validateServerContext(serverContext);
    validateRequest(request);
    const tenantPolicy = catalog.tenantPolicy(serverContext.tenantId);
    const task = catalog.task(request.taskRef);
    const trusted = await trustedInputs(
      serverContext,
      request,
      tenantPolicy,
    );
    let rawDataPolicy;
    try {
      rawDataPolicy = await dataPolicyResolver.resolve(
        Object.freeze({
          tenantId: serverContext.tenantId,
          inputRef: request.inputRef,
          inputSha256: request.inputSha256,
        }),
      );
    } catch (error) {
      throw normalizeDependency(error, "DATA_POLICY_UNAVAILABLE");
    }
    const dataPolicy = validateDataPolicy(
      rawDataPolicy,
      request,
      tenantPolicy,
    );
    const now = canonicalInstant(clock(), "clock");
    const requestHash = modelGatewaySha256({
      tenantId: serverContext.tenantId,
      humanPrincipalId:
        trusted.identity.humanSubject.principalId,
      workloadActorPrincipalId:
        trusted.identity.workloadActor.principalId,
      taskRef: request.taskRef,
      inputRef: request.inputRef,
      inputSha256: request.inputSha256,
      catalogVersion: catalog.catalogVersion,
      catalogSha256: catalog.digest,
      tenantPolicyVersion: tenantPolicy.policyVersion,
      dataPolicy,
    });
    const filtered = filterModels({
      catalog,
      tenantPolicy,
      task,
      dataPolicy,
      requestHash,
    });
    if (filtered.allowed.length === 0) {
      fail("NO_ALLOWED_MODEL", "C14 policy allows no model.");
    }
    const reservedCostMicrousd = Math.max(
      ...filtered.allowed.map((model) =>
        calculateCost(model, {
          inputTokens: dataPolicy.inputTokens,
          outputTokens: task.maxOutputTokens,
        })
      ),
    );
    const binding = identityBinding(trusted.identity);
    const routeId = generatedRouteId(idFactory);
    const prepared = {
      routeId,
      tenantId: serverContext.tenantId,
      tenantKind: "SYNTHETIC",
      status: "PREPARED",
      version: 1,
      idempotencyKey: request.idempotencyKey,
      requestHash,
      correlationId: request.correlationId,
      taskRef: request.taskRef,
      inputRef: request.inputRef,
      inputSha256: request.inputSha256,
      dataClassification: dataPolicy.dataClassification,
      requiredPlane: dataPolicy.requiredPlane,
      tenantRegion: tenantPolicy.region,
      catalogVersion: catalog.catalogVersion,
      catalogSha256: catalog.digest,
      tenantPolicyVersion: tenantPolicy.policyVersion,
      authorizationEvidence: {
        decisionId: trusted.authorization.decisionId,
        evidenceRef: trusted.authorization.evidenceRef,
        policyVersion: trusted.authorization.policyVersion,
      },
      identityBinding: binding,
      evaluatedCandidates: filtered.evaluated,
      candidateBindings: filtered.allowed.map((model) => ({
        modelRef: model.modelRef,
        modelVersion: model.version,
        modelSha256: model.contentSha256,
        providerId: model.providerId,
        plane: model.plane,
        rateVersion: model.rateVersion,
      })),
      selectedModel: null,
      attemptReceipts: [],
      responseRef: null,
      responseSha256: null,
      usage: null,
      rateVersion: null,
      costMicrousd: null,
      failureCode: null,
      reservedInputTokens: dataPolicy.inputTokens,
      reservedOutputTokens: task.maxOutputTokens,
      reservedCostMicrousd,
      createdAt: now,
      updatedAt: now,
    };
    let result;
    try {
      result = await store.prepareRoute(
        trusted.scope,
        Object.freeze({
          idempotencyKey: request.idempotencyKey,
          requestHash,
          correlationId: request.correlationId,
        }),
        Object.freeze(prepared),
        Object.freeze({
          dailyTokenLimit: tenantPolicy.dailyTokenLimit,
          dailyCostMicrousdLimit:
            tenantPolicy.dailyCostMicrousdLimit,
        }),
      );
    } catch (error) {
      throw normalizeStoreDependency(error);
    }
    let routeRecord = result.route;
    if (routeRecord.status === "SUCCEEDED") {
      return Object.freeze({
        route: publicRouteView(routeRecord),
        duplicate: true,
        verificationScope: "P1_SYNTHETIC_ONLY",
        productionVerificationStatus: "NOT_VERIFIED",
      });
    }
    if (routeRecord.status === "FAILED") {
      fail(
        routeRecord.failureCode ?? "MODEL_INVOCATION_FAILED",
        "C14 route is terminally failed.",
      );
    }

    const attemptReceipts = [];
    for (const bindingValue of routeRecord.candidateBindings) {
      const model = catalog.model(bindingValue.modelRef);
      if (
        !model ||
        model.version !== bindingValue.modelVersion ||
        model.contentSha256 !== bindingValue.modelSha256 ||
        model.providerId !== bindingValue.providerId ||
        model.rateVersion !== bindingValue.rateVersion
      ) {
        fail(
          "REGISTRY_BINDING_MISMATCH",
          "C14 frozen model binding no longer matches the registry.",
        );
      }
      const effectKey = `effect_${modelGatewaySha256({
        tenantId: routeRecord.tenantId,
        routeId: routeRecord.routeId,
        modelRef: model.modelRef,
        modelVersion: model.version,
      }).slice(7)}`;
      let receipt;
      try {
        receipt = validateProviderReceipt(
          await providerInvoker.invoke(
            Object.freeze({
              tenantId: routeRecord.tenantId,
              routeId: routeRecord.routeId,
              effectKey,
              providerId: model.providerId,
              modelRef: model.modelRef,
              modelVersion: model.version,
              inputRef: routeRecord.inputRef,
              inputSha256: routeRecord.inputSha256,
              maxOutputTokens: routeRecord.reservedOutputTokens,
            }),
          ),
          {
            effectKey,
            providerId: model.providerId,
            modelRef: model.modelRef,
            modelVersion: model.version,
          },
        );
      } catch (error) {
        throw normalizeDependency(error, "PROVIDER_UNAVAILABLE");
      }
      attemptReceipts.push(receipt);
      if (receipt.outcome !== "SUCCEEDED") continue;
      const usage = {
        inputTokens: receipt.inputTokens,
        outputTokens: receipt.outputTokens,
        totalTokens: receipt.inputTokens + receipt.outputTokens,
      };
      if (
        usage.inputTokens > routeRecord.reservedInputTokens ||
        usage.outputTokens > routeRecord.reservedOutputTokens
      ) {
        fail(
          "PROVIDER_RECEIPT_INVALID",
          "C14 provider usage exceeds the frozen reservation.",
        );
      }
      const costMicrousd = calculateCost(model, usage);
      if (costMicrousd > routeRecord.reservedCostMicrousd) {
        fail(
          "QUOTA_INVARIANT_VIOLATION",
          "C14 actual cost exceeds the frozen reservation.",
        );
      }
      const completedAt = canonicalInstant(clock(), "clock");
      try {
        routeRecord = await store.completeRoute(
          trusted.scope,
          routeRecord.routeId,
          routeRecord.version,
          Object.freeze({
            selectedModel: bindingValue,
            attemptReceipts,
            responseRef: receipt.responseRef,
            responseSha256: receipt.responseSha256,
            usage,
            rateVersion: model.rateVersion,
            costMicrousd,
            updatedAt: completedAt,
          }),
        );
      } catch (error) {
        throw normalizeStoreDependency(error);
      }
      return Object.freeze({
        route: publicRouteView(routeRecord),
        duplicate: result.duplicate === true,
        verificationScope: "P1_SYNTHETIC_ONLY",
        productionVerificationStatus: "NOT_VERIFIED",
      });
    }
    const failedAt = canonicalInstant(clock(), "clock");
    try {
      routeRecord = await store.failRoute(
        trusted.scope,
        routeRecord.routeId,
        routeRecord.version,
        Object.freeze({
          attemptReceipts,
          failureCode: "ALLOWED_MODELS_EXHAUSTED",
          updatedAt: failedAt,
        }),
      );
    } catch (error) {
      throw normalizeStoreDependency(error);
    }
    fail(
      routeRecord.failureCode,
      "All policy-allowed C14 models failed.",
    );
  }

  return Object.freeze({ route });
}

export const C14_DATA_CLASSES = DATA_CLASSES;
export const C14_PLANES = PLANES;
export const C14_ROUTE_STATES = ROUTE_STATES;
