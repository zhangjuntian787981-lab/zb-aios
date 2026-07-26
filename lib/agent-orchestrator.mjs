import { createHash, randomUUID } from "node:crypto";

const SHA256 = /^sha256:[a-f0-9]{64}$/;
const SYNTHETIC_TENANT =
  /^stn_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const TASK_ID =
  /^tsk_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const REFERENCE =
  /^(?:evidence|fixture|policy|synthetic|test):\/\/[A-Za-z0-9][A-Za-z0-9._~:/-]*$/;
const NODE_ORDER = Object.freeze([
  "CLASSIFY",
  "HARD_GATES",
  "RETRIEVE",
  "TOOL",
  "DRAFT",
  "VALIDATE",
  "INDEPENDENT_REVIEW",
  "HUMAN_GATE",
  "COMPLETE",
]);
const NODE_BINDING_FIELDS = Object.freeze({
  CLASSIFY: ["dataClass", "riskClass", "policy"],
  HARD_GATES: [
    "schemaVersion",
    "tenantId",
    "taskId",
    "effectKey",
    "effect",
    "reasonCode",
    "policyRef",
    "policyVersion",
    "policySha256",
    "budgetSha256",
    "dataClass",
    "riskClass",
  ],
  RETRIEVE: [
    "effectKey",
    "inputRef",
    "inputSha256",
    "knowledgeRef",
    "knowledgeVersion",
    "knowledgeSha256",
    "status",
  ],
  TOOL: [
    "operationId",
    "catalogVersion",
    "toolSha256",
    "authorizationDecisionSha256",
    "identitySha256",
    "parameterSha256",
    "confirmationSha256",
    "receiptSha256",
  ],
  DRAFT: [
    "modelRef",
    "modelVersion",
    "modelSha256",
    "modelTaskRef",
    "modelTaskVersion",
    "modelTaskSha256",
    "skillRef",
    "skillVersion",
    "skillSha256",
    "contextSha256",
  ],
  VALIDATE: [
    "effectKey",
    "artifactRef",
    "artifactSha256",
    "outcome",
    "ruleRef",
    "ruleVersion",
    "ruleSha256",
  ],
  INDEPENDENT_REVIEW: [
    "effectKey",
    "artifactRef",
    "artifactSha256",
    "outcome",
    "reviewerRef",
    "reviewerVersion",
    "reviewerSha256",
    "draftModelRef",
    "draftModelVersion",
    "draftModelSha256",
    "reviewModelRef",
    "reviewModelVersion",
    "reviewModelSha256",
    "modelIndependent",
    "inputTokens",
    "outputTokens",
    "totalTokens",
    "costMicrousd",
  ],
  HUMAN_GATE: [
    "schemaVersion",
    "tenantId",
    "taskId",
    "effectKey",
    "expectedStateSha256",
    "decisionRef",
    "decisionSha256",
    "outcome",
    "productionReusable",
    "externalEffectCount",
    "decidedByHumanPrincipalId",
  ],
  COMPLETE: ["decisionRef", "decisionSha256"],
});
const TERMINAL = new Set([
  "BLOCKED",
  "REFUSED",
  "INVALID",
  "REJECTED",
  "COMPLETED",
]);
const FORBIDDEN_STATE_KEYS = new Set([
  "body",
  "bytes",
  "content",
  "credential",
  "filebody",
  "filebytes",
  "modelinput",
  "modeloutput",
  "password",
  "prompt",
  "secret",
  "sessiontoken",
  "toolarguments",
  "toolparams",
  "token",
]);

export class AgentOrchestratorError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "AgentOrchestratorError";
    this.code = code;
  }
}

function fail(code, message) {
  throw new AgentOrchestratorError(code, message);
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

function exactKeys(value, allowed, field, required = allowed) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    fail("INVALID_INPUT", `${field} must be an object.`);
  }
  const keys = Object.keys(value);
  if (
    keys.some((key) => !allowed.includes(key)) ||
    required.some((key) => !keys.includes(key))
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
    fail("P3_REQUIRED", `${field} is not a P1 Synthetic reference.`);
  }
}

function sha256(value, field) {
  if (!SHA256.test(value ?? "")) {
    fail("INVALID_INPUT", `${field} is not a SHA-256 digest.`);
  }
}

function safeInteger(value, field, { min = 0 } = {}) {
  if (!Number.isSafeInteger(value) || value < min) {
    fail("INVALID_INPUT", `${field} is invalid.`);
  }
}

function canonical(value, ancestors = new Set()) {
  if (
    value === null ||
    typeof value === "boolean" ||
    typeof value === "string"
  ) {
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) fail("INVALID_JSON", "Number is not finite.");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    if (ancestors.has(value)) fail("INVALID_JSON", "JSON cannot be cyclic.");
    const next = new Set(ancestors).add(value);
    return `[${value.map((item) => canonical(item, next)).join(",")}]`;
  }
  if (value && typeof value === "object") {
    if (
      Object.getPrototypeOf(value) !== Object.prototype &&
      Object.getPrototypeOf(value) !== null
    ) {
      fail("INVALID_JSON", "Only plain JSON objects are supported.");
    }
    if (ancestors.has(value)) fail("INVALID_JSON", "JSON cannot be cyclic.");
    const next = new Set(ancestors).add(value);
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonical(value[key], next)}`)
      .join(",")}}`;
  }
  fail("INVALID_JSON", "Value is not JSON.");
}

export function c12Sha256(value) {
  return `sha256:${createHash("sha256")
    .update(typeof value === "string" ? value : canonical(value))
    .digest("hex")}`;
}

function assertMetadataOnly(value, field = "state") {
  if (typeof value === "string") {
    if (
      /https?:\/\//i.test(value) ||
      /(?:bearer\s+|basic\s+|(?:^|[^A-Za-z0-9])sk-[A-Za-z0-9]|-----BEGIN [A-Z ]+PRIVATE KEY-----)/i.test(
        value,
      )
    ) {
      fail(
        "SYNTHETIC_BOUNDARY_VIOLATION",
        `${field} contains a network or credential value.`,
      );
    }
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) =>
      assertMetadataOnly(item, `${field}[${index}]`),
    );
    return;
  }
  if (value && typeof value === "object") {
    for (const [key, nested] of Object.entries(value)) {
      const normalized = key.toLowerCase().replaceAll(/[_-]/g, "");
      if (FORBIDDEN_STATE_KEYS.has(normalized)) {
        fail(
          "SYNTHETIC_BOUNDARY_VIOLATION",
          `${field}.${key} is forbidden.`,
        );
      }
      assertMetadataOnly(nested, `${field}.${key}`);
    }
  }
}

function validateBinding(value, field) {
  exactKeys(value, ["ref", "version", "sha256"], field);
  reference(value.ref, `${field}.ref`);
  nonEmpty(value.version, `${field}.version`, 128);
  sha256(value.sha256, `${field}.sha256`);
}

function validateBudget(value, field = "budget") {
  exactKeys(value, [
    "maxInputTokens",
    "maxOutputTokens",
    "maxTotalTokens",
    "maxCostMicrousd",
    "maxToolCalls",
  ], field);
  safeInteger(value.maxInputTokens, `${field}.maxInputTokens`, { min: 1 });
  safeInteger(value.maxOutputTokens, `${field}.maxOutputTokens`, { min: 1 });
  safeInteger(value.maxTotalTokens, `${field}.maxTotalTokens`, { min: 1 });
  safeInteger(value.maxCostMicrousd, `${field}.maxCostMicrousd`, { min: 1 });
  safeInteger(value.maxToolCalls, `${field}.maxToolCalls`, { min: 1 });
  if (
    value.maxInputTokens + value.maxOutputTokens >
    value.maxTotalTokens
  ) {
    fail("INVALID_CATALOG", "C12 token budget is inconsistent.");
  }
}

function validateInstant(value, field) {
  if (
    typeof value !== "string" ||
    !Number.isFinite(Date.parse(value)) ||
    new Date(value).toISOString() !== value
  ) {
    fail("INTEGRITY_VIOLATION", `${field} is invalid.`);
  }
}

function validateStateBudget(value) {
  exactKeys(value, ["limits", "usage"], "state.budget");
  validateBudget(value.limits, "state.budget.limits");
  exactKeys(
    value.usage,
    [
      "inputTokens",
      "outputTokens",
      "totalTokens",
      "costMicrousd",
      "toolCalls",
    ],
    "state.budget.usage",
  );
  for (const name of [
    "inputTokens",
    "outputTokens",
    "totalTokens",
    "costMicrousd",
    "toolCalls",
  ]) {
    safeInteger(value.usage[name], `state.budget.usage.${name}`);
  }
  if (
    value.usage.inputTokens + value.usage.outputTokens !==
      value.usage.totalTokens ||
    value.usage.inputTokens > value.limits.maxInputTokens ||
    value.usage.outputTokens > value.limits.maxOutputTokens ||
    value.usage.totalTokens > value.limits.maxTotalTokens ||
    value.usage.costMicrousd > value.limits.maxCostMicrousd ||
    value.usage.toolCalls > value.limits.maxToolCalls
  ) {
    fail("INTEGRITY_VIOLATION", "C12 state budget is invalid.");
  }
}

function validateStateBindings(value) {
  exactKeys(
    value,
    ["policy", "skill", "knowledge", "modelTask", "reviewModel", "tool"],
    "state.bindings",
  );
  for (const name of [
    "policy",
    "skill",
    "knowledge",
    "modelTask",
    "reviewModel",
  ]) {
    validateBinding(value[name], `state.bindings.${name}`);
  }
  exactKeys(
    value.tool,
    ["operationId", "catalogVersion", "sha256"],
    "state.bindings.tool",
  );
  nonEmpty(value.tool.operationId, "state.bindings.tool.operationId", 128);
  nonEmpty(value.tool.catalogVersion, "state.bindings.tool.catalogVersion", 128);
  sha256(value.tool.sha256, "state.bindings.tool.sha256");
}

function validateNodeBinding(nodeId, binding, field) {
  const fields = NODE_BINDING_FIELDS[nodeId];
  if (!fields) {
    fail("INTEGRITY_VIOLATION", `${field} has an unknown node binding.`);
  }
  exactKeys(binding, fields, field);

  if (nodeId === "CLASSIFY") {
    if (
      binding.dataClass !== "SYNTHETIC" ||
      binding.riskClass !== "HIGH"
    ) {
      fail("INTEGRITY_VIOLATION", `${field} classification is invalid.`);
    }
    validateBinding(binding.policy, `${field}.policy`);
    return;
  }

  for (const [name, value] of Object.entries(binding)) {
    const nestedField = `${field}.${name}`;
    if (name === "effectKey" || name.endsWith("Sha256")) {
      sha256(value, nestedField);
    } else if (name.endsWith("Ref")) {
      reference(value, nestedField);
    } else if (name.endsWith("Version")) {
      nonEmpty(value, nestedField, 128);
    }
  }

  if (nodeId === "HARD_GATES") {
    if (
      binding.schemaVersion !== "c12-policy-gate.v1" ||
      !SYNTHETIC_TENANT.test(binding.tenantId) ||
      !TASK_ID.test(binding.taskId) ||
      !["ALLOW", "DENY"].includes(binding.effect) ||
      binding.dataClass !== "SYNTHETIC" ||
      binding.riskClass !== "HIGH"
    ) {
      fail("INTEGRITY_VIOLATION", `${field} policy result is invalid.`);
    }
    nonEmpty(binding.reasonCode, `${field}.reasonCode`, 128);
  } else if (nodeId === "RETRIEVE") {
    if (!["EVIDENCE_READY", "REFUSED"].includes(binding.status)) {
      fail("INTEGRITY_VIOLATION", `${field} retrieval result is invalid.`);
    }
  } else if (nodeId === "TOOL") {
    nonEmpty(binding.operationId, `${field}.operationId`, 128);
    nonEmpty(binding.catalogVersion, `${field}.catalogVersion`, 128);
  } else if (nodeId === "VALIDATE") {
    if (!["PASS", "FAIL"].includes(binding.outcome)) {
      fail("INTEGRITY_VIOLATION", `${field} validation result is invalid.`);
    }
  } else if (nodeId === "INDEPENDENT_REVIEW") {
    if (
      !["PASS", "FAIL"].includes(binding.outcome) ||
      binding.modelIndependent !== true ||
      binding.draftModelRef === binding.reviewModelRef ||
      binding.draftModelSha256 === binding.reviewModelSha256
    ) {
      fail("INTEGRITY_VIOLATION", `${field} review result is invalid.`);
    }
  } else if (nodeId === "HUMAN_GATE") {
    if (
      binding.schemaVersion !== "c12-synthetic-human-decision.v1" ||
      !SYNTHETIC_TENANT.test(binding.tenantId) ||
      !TASK_ID.test(binding.taskId) ||
      binding.outcome !== "APPROVE" ||
      binding.productionReusable !== false ||
      binding.externalEffectCount !== 0
    ) {
      fail("INTEGRITY_VIOLATION", `${field} HumanDecision is invalid.`);
    }
    nonEmpty(
      binding.decidedByHumanPrincipalId,
      `${field}.decidedByHumanPrincipalId`,
      256,
    );
  }
}

function validateNodeRecord(record, index) {
  exactKeys(
    record,
    [
      "nodeId",
      "nodeVersion",
      "owner",
      "sequence",
      "inputSha256",
      "outputRef",
      "outputSha256",
      "effectKey",
      "evidenceRefs",
      "binding",
      "bindingSha256",
      "completedAt",
    ],
    `state.nodeRecords[${index}]`,
  );
  if (
    record.nodeId !== NODE_ORDER[index] ||
    record.sequence !== index + 1 ||
    !Array.isArray(record.evidenceRefs)
  ) {
    fail("INTEGRITY_VIOLATION", "C12 node sequence is invalid.");
  }
  nonEmpty(record.nodeVersion, `state.nodeRecords[${index}].nodeVersion`, 128);
  nonEmpty(record.owner, `state.nodeRecords[${index}].owner`, 64);
  sha256(record.inputSha256, `state.nodeRecords[${index}].inputSha256`);
  reference(record.outputRef, `state.nodeRecords[${index}].outputRef`);
  sha256(record.outputSha256, `state.nodeRecords[${index}].outputSha256`);
  sha256(record.effectKey, `state.nodeRecords[${index}].effectKey`);
  sha256(record.bindingSha256, `state.nodeRecords[${index}].bindingSha256`);
  if (
    !record.binding ||
    typeof record.binding !== "object" ||
    Array.isArray(record.binding)
  ) {
    fail("INTEGRITY_VIOLATION", "C12 node binding is invalid.");
  }
  validateNodeBinding(
    record.nodeId,
    record.binding,
    `state.nodeRecords[${index}].binding`,
  );
  if (c12Sha256(record.binding) !== record.bindingSha256) {
    fail("INTEGRITY_VIOLATION", "C12 node binding is invalid.");
  }
  assertMetadataOnly(record.binding, `state.nodeRecords[${index}].binding`);
  record.evidenceRefs.forEach((item) =>
    reference(item, `state.nodeRecords[${index}].evidenceRef`),
  );
  validateInstant(record.completedAt, `state.nodeRecords[${index}].completedAt`);
}

function validateHumanDecision(value) {
  exactKeys(
    value,
    [
      "decisionRef",
      "decisionSha256",
      "decidedByHumanPrincipalId",
      "productionReusable",
    ],
    "state.humanDecision",
  );
  reference(value.decisionRef, "state.humanDecision.decisionRef");
  sha256(value.decisionSha256, "state.humanDecision.decisionSha256");
  nonEmpty(
    value.decidedByHumanPrincipalId,
    "state.humanDecision.decidedByHumanPrincipalId",
    256,
  );
  if (value.productionReusable !== false) {
    fail("INTEGRITY_VIOLATION", "C12 decision cannot be production reusable.");
  }
}

function validateGraph(graph) {
  exactKeys(
    graph,
    [
      "schemaVersion",
      "graphVersion",
      "phase",
      "dynamicNodes",
      "freeFormMultiAgentChat",
      "nodes",
    ],
    "graph",
  );
  if (
    graph.schemaVersion !== "c12-orchestration-graph.v1" ||
    graph.phase !== "P1_SYNTHETIC_ONLY" ||
    graph.dynamicNodes !== false ||
    graph.freeFormMultiAgentChat !== false ||
    !Array.isArray(graph.nodes) ||
    canonical(graph.nodes.map(({ nodeId }) => nodeId)) !==
      canonical(NODE_ORDER)
  ) {
    fail("INVALID_CATALOG", "C12 graph is not the frozen explicit graph.");
  }
  for (const [index, node] of graph.nodes.entries()) {
    exactKeys(
      node,
      ["nodeId", "version", "owner", "externalEffect"],
      `graph.nodes[${index}]`,
    );
    if (node.externalEffect !== false) {
      fail("INVALID_CATALOG", "C12 P1 graph cannot own external effects.");
    }
    nonEmpty(node.version, `graph.nodes[${index}].version`, 128);
    nonEmpty(node.owner, `graph.nodes[${index}].owner`, 64);
  }
}

export function createSyntheticOrchestrationCatalog({
  catalog,
  graph,
}) {
  validateGraph(graph);
  exactKeys(
    catalog,
    ["schemaVersion", "phase", "graphRef", "graphVersion", "tasks"],
    "catalog",
  );
  if (
    catalog.schemaVersion !== "c12-synthetic-task-catalog.v1" ||
    catalog.phase !== "P1_SYNTHETIC_ONLY" ||
    catalog.graphVersion !== graph.graphVersion ||
    !Array.isArray(catalog.tasks) ||
    catalog.tasks.length !== 3
  ) {
    fail("INVALID_CATALOG", "C12 Synthetic catalog is invalid.");
  }
  reference(catalog.graphRef, "catalog.graphRef");
  const tasks = new Map();
  const tenants = new Set();
  for (const [index, raw] of catalog.tasks.entries()) {
    exactKeys(
      raw,
      [
        "tenantId",
        "taskRef",
        "inputRef",
        "inputSha256",
        "dataClass",
        "riskClass",
        "humanDecisionRequired",
        "toolInvocation",
        "budget",
        "bindings",
      ],
      `catalog.tasks[${index}]`,
    );
    if (
      !SYNTHETIC_TENANT.test(raw.tenantId) ||
      raw.dataClass !== "SYNTHETIC" ||
      raw.riskClass !== "HIGH" ||
      raw.humanDecisionRequired !== true
    ) {
      fail("INVALID_CATALOG", "C12 task boundary is invalid.");
    }
    reference(raw.taskRef, "taskRef");
    reference(raw.inputRef, "inputRef");
    sha256(raw.inputSha256, "inputSha256");
    exactKeys(
      raw.toolInvocation,
      ["parameters", "parameterSha256"],
      "toolInvocation",
    );
    exactKeys(
      raw.toolInvocation.parameters,
      ["orderRef"],
      "toolInvocation.parameters",
    );
    if (
      !/^SYN-ORD-[0-9]{4}$/.test(
        raw.toolInvocation.parameters.orderRef ?? "",
      ) ||
      raw.toolInvocation.parameterSha256 !==
        c12Sha256(raw.toolInvocation.parameters)
    ) {
      fail("INVALID_CATALOG", "C12 Tool parameters are not frozen.");
    }
    validateBudget(raw.budget);
    exactKeys(
      raw.bindings,
      ["policy", "skill", "knowledge", "modelTask", "reviewModel", "tool"],
      "bindings",
    );
    for (const name of [
      "policy",
      "skill",
      "knowledge",
      "modelTask",
      "reviewModel",
    ]) {
      validateBinding(raw.bindings[name], `bindings.${name}`);
    }
    exactKeys(
      raw.bindings.tool,
      ["operationId", "catalogVersion", "sha256"],
      "bindings.tool",
    );
    if (
      raw.bindings.tool.operationId !== "synthetic.erp.order.get" ||
      raw.bindings.tool.catalogVersion !== "c16-synthetic-tools-v1"
    ) {
      fail("INVALID_CATALOG", "C12 Tool binding is not frozen.");
    }
    sha256(raw.bindings.tool.sha256, "bindings.tool.sha256");
    const key = `${raw.tenantId}\0${raw.taskRef}`;
    if (tasks.has(key) || tenants.has(raw.tenantId)) {
      fail("INVALID_CATALOG", "C12 catalog duplicates a Tenant task.");
    }
    const task = deepFreeze({
      ...clone(raw),
      graphRef: catalog.graphRef,
      graphVersion: graph.graphVersion,
      graphSha256: c12Sha256(graph),
      catalogBindingSha256: c12Sha256(raw),
    });
    tasks.set(key, task);
    tenants.add(raw.tenantId);
  }
  return Object.freeze({
    resolve(tenantId, taskRef) {
      const task = tasks.get(`${tenantId}\0${taskRef}`);
      if (!task) fail("TASK_NOT_FOUND", "C12 task is not frozen.");
      return task;
    },
    graph: deepFreeze(clone(graph)),
    tenantIds: Object.freeze([...tenants].sort()),
  });
}

function validateTaskStateBinding(state, task, graph) {
  if (
    state.taskRef !== task.taskRef ||
    state.inputRef !== task.inputRef ||
    state.inputSha256 !== task.inputSha256 ||
    state.graphRef !== task.graphRef ||
    state.graphVersion !== task.graphVersion ||
    state.graphSha256 !== task.graphSha256 ||
    state.catalogBindingSha256 !== task.catalogBindingSha256 ||
    canonical(state.budget.limits) !== canonical(task.budget) ||
    canonical(state.bindings) !== canonical(task.bindings)
  ) {
    fail("TASK_BINDING_CHANGED", "C12 task catalog binding changed.");
  }
  for (const [index, record] of state.nodeRecords.entries()) {
    if (
      record.nodeVersion !== graph.nodes[index].version ||
      record.owner !== graph.nodes[index].owner
    ) {
      fail("TASK_BINDING_CHANGED", "C12 node definition changed.");
    }
  }
}

function validateScope(scope) {
  exactKeys(
    scope,
    [
      "trustSource",
      "tenantId",
      "humanPrincipalId",
      "workloadActorPrincipalId",
      "decisionId",
      "evidenceRef",
      "policyVersion",
      "correlationId",
    ],
    "scope",
  );
  if (
    scope.trustSource !== "C12_AUTHORIZED_SCOPE" ||
    !SYNTHETIC_TENANT.test(scope.tenantId) ||
    !scope.humanPrincipalId ||
    !scope.workloadActorPrincipalId ||
    !scope.decisionId ||
    !scope.evidenceRef ||
    !scope.policyVersion ||
    !scope.correlationId
  ) {
    fail("AUTHORIZATION_REQUIRED", "C12 requires an authorized scope.");
  }
  return scope;
}

function withoutStateSha256(state) {
  const value = clone(state);
  delete value.stateSha256;
  return value;
}

function validateState(state) {
  exactKeys(
    state,
    [
      "schemaVersion",
      "tenantId",
      "tenantKind",
      "taskId",
      "taskRef",
      "inputRef",
      "inputSha256",
      "graphRef",
      "graphVersion",
      "graphSha256",
      "catalogBindingSha256",
      "ownerHumanPrincipalId",
      "workloadActorPrincipalId",
      "status",
      "nextNodeId",
      "version",
      "budget",
      "bindings",
      "nodeRecords",
      "humanDecision",
      "createdAt",
      "updatedAt",
      "stateSha256",
    ],
    "state",
  );
  if (
    state.schemaVersion !== "c12-task-state.v1" ||
    state.tenantKind !== "SYNTHETIC" ||
    !SYNTHETIC_TENANT.test(state.tenantId) ||
    !TASK_ID.test(state.taskId) ||
    ![
      "RUNNING",
      "WAITING_FOR_HUMAN",
      ...TERMINAL,
    ].includes(state.status) ||
    (state.nextNodeId !== null && !NODE_ORDER.includes(state.nextNodeId)) ||
    !Array.isArray(state.nodeRecords)
  ) {
    fail("INTEGRITY_VIOLATION", "C12 state is invalid.");
  }
  reference(state.taskRef, "state.taskRef");
  reference(state.inputRef, "state.inputRef");
  sha256(state.inputSha256, "state.inputSha256");
  reference(state.graphRef, "state.graphRef");
  nonEmpty(state.graphVersion, "state.graphVersion", 128);
  sha256(state.graphSha256, "state.graphSha256");
  sha256(state.catalogBindingSha256, "state.catalogBindingSha256");
  nonEmpty(
    state.ownerHumanPrincipalId,
    "state.ownerHumanPrincipalId",
    256,
  );
  nonEmpty(
    state.workloadActorPrincipalId,
    "state.workloadActorPrincipalId",
    256,
  );
  safeInteger(state.version, "state.version", { min: 1 });
  validateStateBudget(state.budget);
  validateStateBindings(state.bindings);
  if (state.nodeRecords.length > NODE_ORDER.length) {
    fail("INTEGRITY_VIOLATION", "C12 state has too many nodes.");
  }
  state.nodeRecords.forEach(validateNodeRecord);
  if (state.humanDecision !== null) {
    validateHumanDecision(state.humanDecision);
    if (
      state.humanDecision.decidedByHumanPrincipalId !==
      state.ownerHumanPrincipalId
    ) {
      fail("INTEGRITY_VIOLATION", "C12 decision owner changed.");
    }
  }
  validateInstant(state.createdAt, "state.createdAt");
  validateInstant(state.updatedAt, "state.updatedAt");
  if (
    Date.parse(state.updatedAt) < Date.parse(state.createdAt) ||
    state.nodeRecords.some(
      (record, index) =>
        Date.parse(record.completedAt) < Date.parse(state.createdAt) ||
        Date.parse(record.completedAt) > Date.parse(state.updatedAt) ||
        (index > 0 &&
          Date.parse(record.completedAt) <
            Date.parse(state.nodeRecords[index - 1].completedAt)),
    )
  ) {
    fail("INTEGRITY_VIOLATION", "C12 state time order is invalid.");
  }
  const nodeCount = state.nodeRecords.length;
  const terminalNodeCounts = {
    BLOCKED: 2,
    REFUSED: 3,
    INVALID: 6,
    REJECTED: 7,
    COMPLETED: 9,
  };
  const expectedVersion =
    nodeCount + 1 + (state.humanDecision !== null || state.status ===
      "WAITING_FOR_HUMAN"
      ? 1
      : 0);
  const runningValid =
    state.status === "RUNNING" &&
    ((state.humanDecision === null &&
      nodeCount <= 7 &&
      state.nextNodeId === NODE_ORDER[nodeCount]) ||
      (state.humanDecision !== null &&
        nodeCount === 8 &&
        state.nextNodeId === "COMPLETE"));
  const waitingValid =
    state.status === "WAITING_FOR_HUMAN" &&
    nodeCount === 7 &&
    state.nextNodeId === "HUMAN_GATE" &&
    state.humanDecision === null;
  const terminalValid =
    Object.hasOwn(terminalNodeCounts, state.status) &&
    terminalNodeCounts[state.status] === nodeCount &&
    state.nextNodeId === null &&
    (state.status === "COMPLETED"
      ? state.humanDecision !== null
      : state.humanDecision === null);
  if (
    state.version !== expectedVersion ||
    (!runningValid && !waitingValid && !terminalValid)
  ) {
    fail("INTEGRITY_VIOLATION", "C12 state transition is invalid.");
  }
  sha256(state.stateSha256, "state.stateSha256");
  if (c12Sha256(withoutStateSha256(state)) !== state.stateSha256) {
    fail("INTEGRITY_VIOLATION", "C12 state hash is invalid.");
  }
  assertMetadataOnly(state);
}

function validateLoadedState(state, scope, taskId) {
  validateState(state);
  if (
    state.tenantId !== scope.tenantId ||
    (taskId !== null && state.taskId !== taskId) ||
    state.ownerHumanPrincipalId !== scope.humanPrincipalId ||
    state.workloadActorPrincipalId !== scope.workloadActorPrincipalId
  ) {
    fail("INTEGRITY_VIOLATION", "C12 state escaped its requested scope.");
  }
}

function validateStatePortView(
  view,
  scope,
  taskId,
  catalog,
  command,
  expectedTask = null,
) {
  try {
    exactKeys(
      view,
      ["task", "replayed", "receipt"],
      "statePortView",
    );
  } catch {
    fail(
      "INTEGRITY_VIOLATION",
      "C12 State Port view shape is invalid.",
    );
  }
  if (typeof view.replayed !== "boolean") {
    fail("INTEGRITY_VIOLATION", "C12 State Port replay flag is invalid.");
  }
  validateLoadedState(view.task, scope, taskId);
  validateStatePortReceipt(view.receipt, scope, view.task, command);
  const task =
    expectedTask ??
    catalog.resolve(view.task.tenantId, view.task.taskRef);
  validateTaskStateBinding(view.task, task, catalog.graph);
  return deepFreeze(clone(view));
}

function validateExactStatePortView(
  view,
  scope,
  catalog,
  task,
  expectedState,
  command,
) {
  const validated = validateStatePortView(
    view,
    scope,
    expectedState.taskId,
    catalog,
    command,
    task,
  );
  if (canonical(validated.task) !== canonical(expectedState)) {
    fail(
      "INTEGRITY_VIOLATION",
      "C12 State Port returned the wrong command result.",
    );
  }
  return validated;
}

function validateStartReplay(view, scope, catalog, task, command) {
  const validated = validateStatePortView(
    view,
    scope,
    null,
    catalog,
    command,
    task,
  );
  if (
    validated.replayed !== true ||
    validated.task.version !== 1 ||
    validated.task.status !== "RUNNING" ||
    validated.task.nextNodeId !== "CLASSIFY" ||
    validated.task.nodeRecords.length !== 0
  ) {
    fail("INTEGRITY_VIOLATION", "C12 START replay is invalid.");
  }
  return validated;
}

function validateAdvanceReplay(
  view,
  scope,
  taskIdValue,
  expectedVersion,
  catalog,
  command,
) {
  const validated = validateStatePortView(
    view,
    scope,
    taskIdValue,
    catalog,
    command,
  );
  if (
    validated.replayed !== true ||
    validated.task.version !== expectedVersion + 1
  ) {
    fail("INTEGRITY_VIOLATION", "C12 ADVANCE replay is invalid.");
  }
  return validated;
}

function validateResumeReplay(view, scope, request, catalog, command) {
  const validated = validateStatePortView(
    view,
    scope,
    request.taskId,
    catalog,
    command,
  );
  const decision = validated.task.humanDecision;
  const record = validated.task.nodeRecords.at(-1);
  const effectKey = c12Sha256({
    tenantId: validated.task.tenantId,
    taskId: request.taskId,
    nodeId: "HUMAN_GATE",
    expectedVersion: request.expectedVersion,
    stateSha256: request.expectedStateSha256,
  });
  if (
    validated.replayed !== true ||
    validated.task.version !== request.expectedVersion + 1 ||
    validated.task.status !== "RUNNING" ||
    validated.task.nextNodeId !== "COMPLETE" ||
    decision?.decisionRef !== request.decisionRef ||
    decision?.decisionSha256 !== request.decisionSha256 ||
    decision?.decidedByHumanPrincipalId !== scope.humanPrincipalId ||
    record?.nodeId !== "HUMAN_GATE" ||
    record.effectKey !== effectKey ||
    record.binding.expectedStateSha256 !==
      request.expectedStateSha256 ||
    record.binding.decisionRef !== request.decisionRef ||
    record.binding.decisionSha256 !== request.decisionSha256
  ) {
    fail("INTEGRITY_VIOLATION", "C12 RESUME replay is invalid.");
  }
  return validated;
}

function receiptBody(scope, command, state) {
  return {
    schemaVersion: "c12-state-port-receipt.v1",
    tenantId: scope.tenantId,
    humanPrincipalId: scope.humanPrincipalId,
    workloadActorPrincipalId: scope.workloadActorPrincipalId,
    taskId: state.taskId,
    operation: command.operation,
    idempotencyKey: command.idempotencyKey,
    requestSha256: command.requestSha256,
    resultVersion: state.version,
    resultStateSha256: state.stateSha256,
  };
}

function validateStatePortReceipt(receipt, scope, state, command) {
  exactKeys(
    receipt,
    [
      "schemaVersion",
      "tenantId",
      "humanPrincipalId",
      "workloadActorPrincipalId",
      "taskId",
      "operation",
      "idempotencyKey",
      "requestSha256",
      "resultVersion",
      "resultStateSha256",
      "receiptSha256",
    ],
    "statePortReceipt",
  );
  const body = {
    schemaVersion: receipt.schemaVersion,
    tenantId: receipt.tenantId,
    humanPrincipalId: receipt.humanPrincipalId,
    workloadActorPrincipalId: receipt.workloadActorPrincipalId,
    taskId: receipt.taskId,
    operation: receipt.operation,
    idempotencyKey: receipt.idempotencyKey,
    requestSha256: receipt.requestSha256,
    resultVersion: receipt.resultVersion,
    resultStateSha256: receipt.resultStateSha256,
  };
  sha256(receipt.requestSha256, "statePortReceipt.requestSha256");
  sha256(
    receipt.resultStateSha256,
    "statePortReceipt.resultStateSha256",
  );
  sha256(receipt.receiptSha256, "statePortReceipt.receiptSha256");
  safeInteger(receipt.resultVersion, "statePortReceipt.resultVersion", {
    min: 1,
  });
  if (
    receipt.schemaVersion !== "c12-state-port-receipt.v1" ||
    receipt.tenantId !== scope.tenantId ||
    receipt.humanPrincipalId !== scope.humanPrincipalId ||
    receipt.workloadActorPrincipalId !==
      scope.workloadActorPrincipalId ||
    receipt.taskId !== state.taskId ||
    receipt.operation !== command.operation ||
    receipt.idempotencyKey !== command.idempotencyKey ||
    receipt.requestSha256 !== command.requestSha256 ||
    receipt.resultVersion !== state.version ||
    receipt.resultStateSha256 !== state.stateSha256 ||
    receipt.receiptSha256 !== c12Sha256(body)
  ) {
    fail(
      "INTEGRITY_VIOLATION",
      "C12 State Port receipt is unbound.",
    );
  }
}

function receiptView(receipt) {
  const viewReceipt = clone(receipt);
  delete viewReceipt.task;
  return viewReceipt;
}

function stateView(receipt, replayed = false) {
  const task = clone(receipt.task);
  const viewReceipt = receiptView(receipt);
  return deepFreeze({ task, replayed, receipt: viewReceipt });
}

function receiptKey(scope, idempotencyKey) {
  return [
    scope.tenantId,
    scope.humanPrincipalId,
    scope.workloadActorPrincipalId,
    idempotencyKey,
  ].join("\0");
}

export function createMemoryC12StatePort({ snapshot } = {}) {
  const states = new Map();
  const receipts = new Map();
  if (snapshot !== undefined) {
    exactKeys(snapshot, ["schemaVersion", "states", "receipts"], "snapshot");
    if (
      snapshot.schemaVersion !== "c12-memory-state-port.v1" ||
      !Array.isArray(snapshot.states) ||
      !Array.isArray(snapshot.receipts)
    ) {
      fail("RECOVERY_TAMPERED", "C12 snapshot is invalid.");
    }
    for (const state of snapshot.states) {
      validateState(state);
      const key = `${state.tenantId}\0${state.taskId}`;
      if (states.has(key)) {
        fail("RECOVERY_TAMPERED", "C12 snapshot duplicates a task.");
      }
      states.set(key, clone(state));
    }
    for (const receipt of snapshot.receipts) {
      exactKeys(
        receipt,
        [
          "schemaVersion",
          "tenantId",
          "humanPrincipalId",
          "workloadActorPrincipalId",
          "taskId",
          "operation",
          "idempotencyKey",
          "requestSha256",
          "resultVersion",
          "resultStateSha256",
          "receiptSha256",
          "task",
        ],
        "receipt",
      );
      validateState(receipt.task);
      nonEmpty(receipt.humanPrincipalId, "receipt.humanPrincipalId", 256);
      nonEmpty(
        receipt.workloadActorPrincipalId,
        "receipt.workloadActorPrincipalId",
        256,
      );
      nonEmpty(receipt.idempotencyKey, "receipt.idempotencyKey", 128);
      sha256(receipt.requestSha256, "receipt.requestSha256");
      const command = {
        operation: receipt.operation,
        idempotencyKey: receipt.idempotencyKey,
        requestSha256: receipt.requestSha256,
      };
      validateStatePortReceipt(
        receiptView(receipt),
        receipt,
        receipt.task,
        command,
      );
      if (
        receipt.tenantId !== receipt.task.tenantId ||
        receipt.humanPrincipalId !==
          receipt.task.ownerHumanPrincipalId ||
        receipt.workloadActorPrincipalId !==
          receipt.task.workloadActorPrincipalId
      ) {
        fail("RECOVERY_TAMPERED", "C12 receipt scope is invalid.");
      }
      const key = receiptKey(receipt, receipt.idempotencyKey);
      if (receipts.has(key)) {
        fail("RECOVERY_TAMPERED", "C12 snapshot duplicates a receipt.");
      }
      receipts.set(key, clone(receipt));
    }
  }

  function validateCommand(command, operations) {
    if (
      !operations.includes(command.operation) ||
      typeof command.idempotencyKey !== "string"
    ) {
      fail("INVALID_INPUT", "C12 State Port command is invalid.");
    }
    nonEmpty(command.idempotencyKey, "idempotencyKey", 128);
    sha256(command.requestSha256, "requestSha256");
  }

  function replay(scope, command) {
    validateScope(scope);
    exactKeys(
      command,
      ["operation", "idempotencyKey", "requestSha256"],
      "statePortCommand",
    );
    validateCommand(command, [
      "START",
      "ADVANCE",
      "RESUME_HUMAN_DECISION",
    ]);
    const receipt = receipts.get(
      receiptKey(scope, command.idempotencyKey),
    );
    if (!receipt) return null;
    if (
      receipt.operation !== command.operation ||
      receipt.requestSha256 !== command.requestSha256
    ) {
      fail("IDEMPOTENCY_CONFLICT", "C12 idempotency key was reused.");
    }
    return stateView(receipt, true);
  }

  function saveReceipt(scope, command, state) {
    const body = receiptBody(scope, command, state);
    const receipt = {
      ...body,
      receiptSha256: c12Sha256(body),
      task: clone(state),
    };
    receipts.set(
      receiptKey(scope, command.idempotencyKey),
      receipt,
    );
    return receipt;
  }

  return Object.freeze({
    async replay(scope, command) {
      return replay(scope, command);
    },

    async create(scope, command) {
      scope = validateScope(scope);
      exactKeys(
        command,
        ["operation", "idempotencyKey", "requestSha256", "state"],
        "statePortCommand",
      );
      validateCommand(command, ["START"]);
      const prior = replay(scope, {
        operation: command.operation,
        idempotencyKey: command.idempotencyKey,
        requestSha256: command.requestSha256,
      });
      if (prior) return prior;
      validateState(command.state);
      if (
        command.state.tenantId !== scope.tenantId ||
        command.state.ownerHumanPrincipalId !== scope.humanPrincipalId ||
        command.state.workloadActorPrincipalId !==
          scope.workloadActorPrincipalId
      ) {
        fail("TENANT_SCOPE_VIOLATION", "C12 state escaped its owner scope.");
      }
      const key = `${scope.tenantId}\0${command.state.taskId}`;
      if (states.has(key)) fail("TASK_CONFLICT", "C12 task already exists.");
      states.set(key, clone(command.state));
      const receipt = saveReceipt(scope, command, command.state);
      return stateView(receipt);
    },

    async get(scope, taskId) {
      scope = validateScope(scope);
      const state = states.get(`${scope.tenantId}\0${taskId}`);
      if (!state) return null;
      if (
        state.ownerHumanPrincipalId !== scope.humanPrincipalId ||
        state.workloadActorPrincipalId !== scope.workloadActorPrincipalId
      ) {
        fail("ACCESS_DENIED", "C12 task owner does not match.");
      }
      validateState(state);
      return deepFreeze(clone(state));
    },

    async transact(scope, command) {
      scope = validateScope(scope);
      exactKeys(
        command,
        [
          "operation",
          "taskId",
          "expectedVersion",
          "idempotencyKey",
          "requestSha256",
          "reduce",
        ],
        "statePortCommand",
      );
      validateCommand(command, [
        "ADVANCE",
        "RESUME_HUMAN_DECISION",
      ]);
      const prior = replay(scope, {
        operation: command.operation,
        idempotencyKey: command.idempotencyKey,
        requestSha256: command.requestSha256,
      });
      if (prior) return prior;
      const key = `${scope.tenantId}\0${command.taskId}`;
      const current = states.get(key);
      if (!current) fail("TASK_NOT_FOUND", "C12 task was not found.");
      if (
        current.ownerHumanPrincipalId !== scope.humanPrincipalId ||
        current.workloadActorPrincipalId !== scope.workloadActorPrincipalId
      ) {
        fail("ACCESS_DENIED", "C12 task owner does not match.");
      }
      if (current.version !== command.expectedVersion) {
        fail("VERSION_CONFLICT", "C12 task version changed.");
      }
      if (typeof command.reduce !== "function") {
        fail("INVALID_INPUT", "C12 transition reducer is required.");
      }
      const next = command.reduce(deepFreeze(clone(current)));
      if (typeof next?.then === "function") {
        fail("INVALID_INPUT", "C12 transition reducer must be synchronous.");
      }
      validateState(next);
      if (
        next.tenantId !== current.tenantId ||
        next.taskId !== current.taskId ||
        next.ownerHumanPrincipalId !== current.ownerHumanPrincipalId ||
        next.workloadActorPrincipalId !==
          current.workloadActorPrincipalId ||
        next.version !== current.version + 1
      ) {
        fail("INTEGRITY_VIOLATION", "C12 transition changed identity.");
      }
      states.set(key, clone(next));
      const receipt = saveReceipt(scope, command, next);
      return stateView(receipt);
    },

    snapshot() {
      return deepFreeze({
        schemaVersion: "c12-memory-state-port.v1",
        states: [...states.values()]
          .map(clone)
          .sort((left, right) => left.taskId.localeCompare(right.taskId)),
        receipts: [...receipts.values()]
          .map(clone)
          .sort((left, right) =>
            left.idempotencyKey.localeCompare(right.idempotencyKey),
          ),
      });
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
    !SYNTHETIC_TENANT.test(context.tenantId) ||
    !context.workloadActorPrincipalId
  ) {
    fail("UNTRUSTED_ROUTE", "C12 route is not trusted.");
  }
}

function validateRequest(request, fields, { idempotency = true } = {}) {
  const allowed = [
    "sessionToken",
    "delegationId",
    "correlationId",
    ...(idempotency ? ["idempotencyKey"] : []),
    ...fields,
  ];
  exactKeys(request, allowed, "request");
  nonEmpty(request.sessionToken, "sessionToken", 4096);
  nonEmpty(request.delegationId, "delegationId", 128);
  nonEmpty(request.correlationId, "correlationId", 128);
  if (idempotency) nonEmpty(request.idempotencyKey, "idempotencyKey", 128);
}

async function authorize(authorizer, context, request, operationId, resourceId) {
  let value;
  try {
    value = await authorizer.enforce(
      context,
      {
        sessionToken: request.sessionToken,
        delegationId: request.delegationId,
        correlationId: request.correlationId,
        resourceId,
      },
      {
        operationId,
        surface: operationId === "C12_INSPECT" ? "READ" : "MANAGE",
        path: "agent-orchestration",
        mode: operationId === "C12_INSPECT" ? "READ" : "WRITE",
      },
    );
  } catch {
    fail("AUTHORIZATION_UNAVAILABLE", "C12 authorization failed closed.");
  }
  exactKeys(
    value,
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
    value.trustSource !== "C06_BOUND_DECISION_EVIDENCE" ||
    value.tenantId !== context.tenantId ||
    value.workloadActorPrincipalId !==
      context.workloadActorPrincipalId ||
    value.resourceId !== resourceId ||
    value.operationId !== operationId ||
    !value.humanPrincipalId
  ) {
    fail("AUTHORIZATION_BINDING_INVALID", "C12 authorization is unbound.");
  }
  return deepFreeze({
    trustSource: "C12_AUTHORIZED_SCOPE",
    tenantId: value.tenantId,
    humanPrincipalId: value.humanPrincipalId,
    workloadActorPrincipalId: value.workloadActorPrincipalId,
    decisionId: value.decisionId,
    evidenceRef: value.evidenceRef,
    policyVersion: value.policyVersion,
    correlationId: request.correlationId,
  });
}

function taskId(idFactory) {
  const value = `tsk_${idFactory()}`;
  if (!TASK_ID.test(value)) fail("INVALID_CONFIGURATION", "taskId is invalid.");
  return value;
}

function now(clock) {
  const value = clock();
  if (
    typeof value !== "string" ||
    !Number.isFinite(Date.parse(value)) ||
    new Date(value).toISOString() !== value
  ) {
    fail("INVALID_CONFIGURATION", "C12 clock is invalid.");
  }
  return value;
}

function sealState(body) {
  const state = {
    ...clone(body),
    stateSha256: c12Sha256(body),
  };
  validateState(state);
  return deepFreeze(state);
}

function commandSha256(operation, scope, request, fields) {
  return c12Sha256({
    operation,
    tenantId: scope.tenantId,
    humanPrincipalId: scope.humanPrincipalId,
    workloadActorPrincipalId: scope.workloadActorPrincipalId,
    delegationId: request.delegationId,
    ...fields,
  });
}

function nextNode(nodeId) {
  const index = NODE_ORDER.indexOf(nodeId);
  return index < 0 || index === NODE_ORDER.length - 1
    ? null
    : NODE_ORDER[index + 1];
}

function nodeRecord({
  graph,
  state,
  nodeId,
  effectKey,
  outputRef,
  outputSha256,
  evidenceRefs = [],
  binding,
  completedAt,
}) {
  const definition = graph.nodes.find((node) => node.nodeId === nodeId);
  const record = {
    nodeId,
    nodeVersion: definition.version,
    owner: definition.owner,
    sequence: state.nodeRecords.length + 1,
    inputSha256: c12Sha256({
      stateSha256: state.stateSha256,
      nodeId,
      effectKey,
    }),
    outputRef,
    outputSha256,
    effectKey,
    evidenceRefs: [...evidenceRefs].sort(),
    binding: clone(binding),
    bindingSha256: c12Sha256(binding),
    completedAt,
  };
  assertMetadataOnly(record, "nodeRecord");
  return deepFreeze(record);
}

function portFailure() {
  fail("DEPENDENCY_FAILED", "C12 dependency failed closed.");
}

async function callPort(call) {
  try {
    return await call();
  } catch {
    portFailure();
  }
}

function exactPortResult(value, fields, field) {
  exactKeys(value, fields, field);
  assertMetadataOnly(value, field);
  return value;
}

function budgetUsage(state, additions = {}) {
  const current = state.budget.usage;
  const next = {
    inputTokens: current.inputTokens + (additions.inputTokens ?? 0),
    outputTokens: current.outputTokens + (additions.outputTokens ?? 0),
    totalTokens: current.totalTokens + (additions.totalTokens ?? 0),
    costMicrousd: current.costMicrousd + (additions.costMicrousd ?? 0),
    toolCalls: current.toolCalls + (additions.toolCalls ?? 0),
  };
  const limits = state.budget.limits;
  if (
    next.inputTokens > limits.maxInputTokens ||
    next.outputTokens > limits.maxOutputTokens ||
    next.totalTokens > limits.maxTotalTokens ||
    next.costMicrousd > limits.maxCostMicrousd ||
    next.toolCalls > limits.maxToolCalls
  ) {
    fail("BUDGET_EXCEEDED", "C12 node exceeded its frozen budget.");
  }
  return next;
}

function transition(state, {
  record,
  status = "RUNNING",
  nextNodeId = nextNode(record.nodeId),
  budget = state.budget,
  humanDecision = state.humanDecision,
  updatedAt,
}) {
  return sealState({
    ...withoutStateSha256(state),
    status,
    nextNodeId,
    version: state.version + 1,
    budget,
    nodeRecords: [...state.nodeRecords, record],
    humanDecision,
    updatedAt,
  });
}

function waiting(state, updatedAt) {
  return sealState({
    ...withoutStateSha256(state),
    status: "WAITING_FOR_HUMAN",
    version: state.version + 1,
    updatedAt,
  });
}

export function createAgentOrchestrator({
  authorizer,
  statePort,
  catalog,
  policyGate,
  ragPort,
  toolPort,
  modelPort,
  validator,
  reviewer,
  humanDecisionPort,
  clock = () => new Date().toISOString(),
  idFactory = randomUUID,
}) {
  for (const [name, value, method] of [
    ["authorizer", authorizer, "enforce"],
    ["statePort", statePort, "create"],
    ["policyGate", policyGate, "evaluate"],
    ["ragPort", ragPort, "retrieve"],
    ["toolPort", toolPort, "execute"],
    ["modelPort", modelPort, "route"],
    ["validator", validator, "validate"],
    ["reviewer", reviewer, "review"],
    ["humanDecisionPort", humanDecisionPort, "verify"],
  ]) {
    if (typeof value?.[method] !== "function") {
      fail("INVALID_CONFIGURATION", `${name} is invalid.`);
    }
  }
  for (const method of ["replay", "get", "transact"]) {
    if (typeof statePort[method] !== "function") {
      fail("INVALID_CONFIGURATION", "statePort is incomplete.");
    }
  }
  if (typeof catalog?.resolve !== "function" || !catalog?.graph) {
    fail("INVALID_CONFIGURATION", "catalog is invalid.");
  }

  async function start(context, request) {
    context = deepFreeze(clone(context));
    request = deepFreeze(clone(request));
    validateServerContext(context);
    validateRequest(request, ["taskRef", "inputRef", "inputSha256"]);
    reference(request.taskRef, "taskRef");
    reference(request.inputRef, "inputRef");
    sha256(request.inputSha256, "inputSha256");
    const scope = await authorize(
      authorizer,
      context,
      request,
      "C12_START",
      request.taskRef,
    );
    const task = catalog.resolve(context.tenantId, request.taskRef);
    if (
      task.inputRef !== request.inputRef ||
      task.inputSha256 !== request.inputSha256
    ) {
      fail("TASK_BINDING_INVALID", "C12 input is not frozen.");
    }
    const requestSha256 = commandSha256("START", scope, request, {
      taskRef: request.taskRef,
      inputRef: request.inputRef,
      inputSha256: request.inputSha256,
    });
    const receiptCommand = {
      operation: "START",
      idempotencyKey: request.idempotencyKey,
      requestSha256,
    };
    const replay = await statePort.replay(scope, receiptCommand);
    if (replay) {
      return validateStartReplay(
        replay,
        scope,
        catalog,
        task,
        receiptCommand,
      );
    }
    const createdAt = now(clock);
    const state = sealState({
      schemaVersion: "c12-task-state.v1",
      tenantId: context.tenantId,
      tenantKind: "SYNTHETIC",
      taskId: taskId(idFactory),
      taskRef: task.taskRef,
      inputRef: task.inputRef,
      inputSha256: task.inputSha256,
      graphRef: task.graphRef,
      graphVersion: task.graphVersion,
      graphSha256: task.graphSha256,
      catalogBindingSha256: task.catalogBindingSha256,
      ownerHumanPrincipalId: scope.humanPrincipalId,
      workloadActorPrincipalId: scope.workloadActorPrincipalId,
      status: "RUNNING",
      nextNodeId: "CLASSIFY",
      version: 1,
      budget: {
        limits: clone(task.budget),
        usage: {
          inputTokens: 0,
          outputTokens: 0,
          totalTokens: 0,
          costMicrousd: 0,
          toolCalls: 0,
        },
      },
      bindings: clone(task.bindings),
      nodeRecords: [],
      humanDecision: null,
      createdAt,
      updatedAt: createdAt,
    });
    const view = await statePort.create(scope, {
      ...receiptCommand,
      state,
    });
    if (view?.replayed === true) {
      return validateStartReplay(
        view,
        scope,
        catalog,
        task,
        receiptCommand,
      );
    }
    const validated = validateExactStatePortView(
      view,
      scope,
      catalog,
      task,
      state,
      receiptCommand,
    );
    if (validated.replayed !== false) {
      fail("INTEGRITY_VIOLATION", "C12 START create replay is invalid.");
    }
    return validated;
  }

  async function advance(context, request) {
    context = deepFreeze(clone(context));
    request = deepFreeze(clone(request));
    validateServerContext(context);
    validateRequest(request, ["taskId", "expectedVersion"]);
    if (!TASK_ID.test(request.taskId ?? "")) {
      fail("INVALID_INPUT", "taskId is invalid.");
    }
    safeInteger(request.expectedVersion, "expectedVersion", { min: 1 });
    const scope = await authorize(
      authorizer,
      context,
      request,
      "C12_ADVANCE",
      request.taskId,
    );
    const requestSha256 = commandSha256("ADVANCE", scope, request, {
      taskId: request.taskId,
      expectedVersion: request.expectedVersion,
    });
    const receiptCommand = {
      operation: "ADVANCE",
      idempotencyKey: request.idempotencyKey,
      requestSha256,
    };
    const replay = await statePort.replay(scope, receiptCommand);
    if (replay) {
      return validateAdvanceReplay(
        replay,
        scope,
        request.taskId,
        request.expectedVersion,
        catalog,
        receiptCommand,
      );
    }
    const state = await statePort.get(scope, request.taskId);
    if (!state) fail("TASK_NOT_FOUND", "C12 task was not found.");
    validateLoadedState(state, scope, request.taskId);
    if (state.version !== request.expectedVersion) {
      fail("VERSION_CONFLICT", "C12 task version changed.");
    }
    if (state.status === "WAITING_FOR_HUMAN") {
      fail("HUMAN_DECISION_REQUIRED", "C12 waits for a HumanDecision.");
    }
    if (TERMINAL.has(state.status)) {
      fail("TASK_TERMINAL", "C12 task is terminal.");
    }
    const task = catalog.resolve(state.tenantId, state.taskRef);
    validateTaskStateBinding(state, task, catalog.graph);
    const nodeId = state.nextNodeId;
    const effectKey = c12Sha256({
      tenantId: state.tenantId,
      taskId: state.taskId,
      nodeId,
      expectedVersion: state.version,
      graphVersion: state.graphVersion,
    });
    const completedAt = now(clock);
    if (nodeId === "HUMAN_GATE") {
      const expectedState = waiting(state, completedAt);
      const view = await statePort.transact(scope, {
        operation: receiptCommand.operation,
        taskId: state.taskId,
        expectedVersion: state.version,
        idempotencyKey: receiptCommand.idempotencyKey,
        requestSha256: receiptCommand.requestSha256,
        reduce(current) {
          if (current.stateSha256 !== state.stateSha256) {
            fail(
              "INTEGRITY_VIOLATION",
              "C12 State Port changed the transition input.",
            );
          }
          return expectedState;
        },
      });
      if (view?.replayed === true) {
        return validateAdvanceReplay(
          view,
          scope,
          state.taskId,
          request.expectedVersion,
          catalog,
          receiptCommand,
        );
      }
      return validateExactStatePortView(
        view,
        scope,
        catalog,
        task,
        expectedState,
        receiptCommand,
      );
    }

    let record;
    let terminalStatus = null;
    let nextBudget = state.budget;
    if (nodeId === "CLASSIFY") {
      record = nodeRecord({
        graph: catalog.graph,
        state,
        nodeId,
        effectKey,
        outputRef: `policy://c12/classification/${state.taskId}`,
        outputSha256: c12Sha256({
          dataClass: task.dataClass,
          riskClass: task.riskClass,
        }),
        binding: {
          dataClass: task.dataClass,
          riskClass: task.riskClass,
          policy: task.bindings.policy,
        },
        completedAt,
      });
    } else if (nodeId === "HARD_GATES") {
      const result = exactPortResult(
        await callPort(() =>
          policyGate.evaluate({
            tenantId: state.tenantId,
            taskId: state.taskId,
            effectKey,
            dataClass: task.dataClass,
            riskClass: task.riskClass,
            budget: clone(task.budget),
            policy: clone(task.bindings.policy),
          }),
        ),
        [
          "schemaVersion",
          "tenantId",
          "taskId",
          "effectKey",
          "effect",
          "reasonCode",
          "policyRef",
          "policyVersion",
          "policySha256",
          "budgetSha256",
          "dataClass",
          "riskClass",
        ],
        "policyResult",
      );
      if (
        result.schemaVersion !== "c12-policy-gate.v1" ||
        result.tenantId !== state.tenantId ||
        result.taskId !== state.taskId ||
        result.effectKey !== effectKey ||
        !["ALLOW", "DENY"].includes(result.effect) ||
        result.policyRef !== task.bindings.policy.ref ||
        result.policyVersion !== task.bindings.policy.version ||
        result.policySha256 !== task.bindings.policy.sha256 ||
        result.budgetSha256 !== c12Sha256(task.budget) ||
        result.dataClass !== task.dataClass ||
        result.riskClass !== task.riskClass
      ) {
        fail("POLICY_RESULT_INVALID", "C12 policy result is unbound.");
      }
      nonEmpty(result.reasonCode, "policyResult.reasonCode", 128);
      record = nodeRecord({
        graph: catalog.graph,
        state,
        nodeId,
        effectKey,
        outputRef: `evidence://c12/policy/${effectKey.slice(7)}`,
        outputSha256: c12Sha256(result),
        evidenceRefs: [result.policyRef],
        binding: result,
        completedAt,
      });
      if (result.effect === "DENY") terminalStatus = "BLOCKED";
    } else if (nodeId === "RETRIEVE") {
      const result = exactPortResult(
        await callPort(() =>
          ragPort.retrieve({
            tenantId: state.tenantId,
            taskId: state.taskId,
            effectKey,
            inputRef: state.inputRef,
            inputSha256: state.inputSha256,
            knowledge: clone(task.bindings.knowledge),
          }),
        ),
        [
          "schemaVersion",
          "tenantId",
          "taskId",
          "effectKey",
          "inputRef",
          "inputSha256",
          "status",
          "resultRef",
          "resultSha256",
          "knowledgeRef",
          "knowledgeVersion",
          "knowledgeSha256",
          "evidenceRefs",
        ],
        "ragResult",
      );
      if (
        result.schemaVersion !== "c12-rag-result.v1" ||
        result.tenantId !== state.tenantId ||
        result.taskId !== state.taskId ||
        result.effectKey !== effectKey ||
        result.inputRef !== state.inputRef ||
        result.inputSha256 !== state.inputSha256 ||
        !["EVIDENCE_READY", "REFUSED"].includes(result.status) ||
        result.knowledgeRef !== task.bindings.knowledge.ref ||
        result.knowledgeVersion !== task.bindings.knowledge.version ||
        result.knowledgeSha256 !== task.bindings.knowledge.sha256 ||
        !Array.isArray(result.evidenceRefs) ||
        (result.status === "EVIDENCE_READY" &&
          result.evidenceRefs.length === 0)
      ) {
        fail("RAG_RESULT_INVALID", "C12 RAG result is unbound.");
      }
      reference(result.resultRef, "ragResult.resultRef");
      sha256(result.resultSha256, "ragResult.resultSha256");
      result.evidenceRefs.forEach((item) => reference(item, "evidenceRef"));
      record = nodeRecord({
        graph: catalog.graph,
        state,
        nodeId,
        effectKey,
        outputRef: result.resultRef,
        outputSha256: result.resultSha256,
        evidenceRefs: result.evidenceRefs,
        binding: {
          effectKey: result.effectKey,
          inputRef: result.inputRef,
          inputSha256: result.inputSha256,
          knowledgeRef: result.knowledgeRef,
          knowledgeVersion: result.knowledgeVersion,
          knowledgeSha256: result.knowledgeSha256,
          status: result.status,
        },
        completedAt,
      });
      if (result.status === "REFUSED") terminalStatus = "REFUSED";
    } else if (nodeId === "TOOL") {
      const toolUsage = budgetUsage(state, { toolCalls: 1 });
      const toolResult = await callPort(() =>
        toolPort.execute(clone(context), {
          sessionToken: request.sessionToken,
          delegationId: request.delegationId,
          correlationId: request.correlationId,
          idempotencyKey: effectKey,
          tenantId: state.tenantId,
          taskId: state.taskId,
          humanPrincipalId: scope.humanPrincipalId,
          workloadActorPrincipalId:
            scope.workloadActorPrincipalId,
          effectKey,
          operationId: task.bindings.tool.operationId,
          catalogVersion: task.bindings.tool.catalogVersion,
          parameters: clone(task.toolInvocation.parameters),
          parameterSha256: task.toolInvocation.parameterSha256,
        }),
      );
      if (
        toolResult?.authorizationTrustSource !==
        "C16_REAUTHORIZED_TOOL_CALL"
      ) {
        fail(
          "TOOL_RESULT_INVALID",
          "C12 Tool reauthorization evidence is missing.",
        );
      }
      const result = exactPortResult(
        toolResult,
        [
          "schemaVersion",
          "tenantId",
          "taskId",
          "effectKey",
          "operationId",
          "catalogVersion",
          "authorizationTrustSource",
          "authorizationDecisionRef",
          "authorizationDecisionSha256",
          "identitySha256",
          "parameterSha256",
          "confirmationSha256",
          "humanPrincipalId",
          "workloadActorPrincipalId",
          "resultRef",
          "resultSha256",
          "receiptSha256",
          "networkRequestCount",
          "externalEffectCount",
        ],
        "toolResult",
      );
      if (
        result.schemaVersion !== "c12-tool-result.v1" ||
        result.tenantId !== state.tenantId ||
        result.taskId !== state.taskId ||
        result.effectKey !== effectKey ||
        result.operationId !== task.bindings.tool.operationId ||
        result.catalogVersion !== task.bindings.tool.catalogVersion ||
        result.authorizationTrustSource !==
          "C16_REAUTHORIZED_TOOL_CALL" ||
        result.parameterSha256 !==
          task.toolInvocation.parameterSha256 ||
        result.humanPrincipalId !== scope.humanPrincipalId ||
        result.workloadActorPrincipalId !==
          scope.workloadActorPrincipalId ||
        result.networkRequestCount !== 0 ||
        result.externalEffectCount !== 0
      ) {
        fail("TOOL_RESULT_INVALID", "C12 Tool result is unbound.");
      }
      reference(result.resultRef, "toolResult.resultRef");
      reference(
        result.authorizationDecisionRef,
        "toolResult.authorizationDecisionRef",
      );
      sha256(result.resultSha256, "toolResult.resultSha256");
      sha256(result.receiptSha256, "toolResult.receiptSha256");
      sha256(
        result.authorizationDecisionSha256,
        "toolResult.authorizationDecisionSha256",
      );
      sha256(result.identitySha256, "toolResult.identitySha256");
      sha256(result.confirmationSha256, "toolResult.confirmationSha256");
      nextBudget = {
        limits: state.budget.limits,
        usage: toolUsage,
      };
      record = nodeRecord({
        graph: catalog.graph,
        state,
        nodeId,
        effectKey,
        outputRef: result.resultRef,
        outputSha256: result.resultSha256,
        evidenceRefs: [
          result.authorizationDecisionRef,
          `evidence://c16/receipt/${result.receiptSha256.slice(7)}`,
        ],
        binding: {
          operationId: result.operationId,
          catalogVersion: result.catalogVersion,
          toolSha256: task.bindings.tool.sha256,
          authorizationDecisionSha256:
            result.authorizationDecisionSha256,
          identitySha256: result.identitySha256,
          parameterSha256: result.parameterSha256,
          confirmationSha256: result.confirmationSha256,
          receiptSha256: result.receiptSha256,
        },
        completedAt,
      });
    } else if (nodeId === "DRAFT") {
      const retrieval = state.nodeRecords.find(
        (item) => item.nodeId === "RETRIEVE",
      );
      const tool = state.nodeRecords.find(
        (item) => item.nodeId === "TOOL",
      );
      if (!retrieval || !tool) {
        fail("INTEGRITY_VIOLATION", "C12 Draft inputs are missing.");
      }
      const evidenceContext = {
        inputRef: state.inputRef,
        inputSha256: state.inputSha256,
        retrievalResultRef: retrieval.outputRef,
        retrievalResultSha256: retrieval.outputSha256,
        evidenceRefs: clone(retrieval.evidenceRefs),
        toolResultRef: tool.outputRef,
        toolResultSha256: tool.outputSha256,
        toolEvidenceRefs: clone(tool.evidenceRefs),
      };
      const contextSha256 = c12Sha256(evidenceContext);
      const result = exactPortResult(
        await callPort(() =>
          modelPort.route({
            tenantId: state.tenantId,
            taskId: state.taskId,
            effectKey,
            inputRef: state.inputRef,
            inputSha256: state.inputSha256,
            modelTask: clone(task.bindings.modelTask),
            skill: clone(task.bindings.skill),
            evidenceContext: clone(evidenceContext),
            contextSha256,
            budget: clone(state.budget.limits),
          }),
        ),
        [
          "schemaVersion",
          "tenantId",
          "taskId",
          "effectKey",
          "outputRef",
          "outputSha256",
          "modelRef",
          "modelVersion",
          "modelSha256",
          "modelTaskRef",
          "modelTaskVersion",
          "modelTaskSha256",
          "skillRef",
          "skillVersion",
          "skillSha256",
          "contextSha256",
          "inputTokens",
          "outputTokens",
          "totalTokens",
          "costMicrousd",
        ],
        "modelResult",
      );
      if (
        result.schemaVersion !== "c12-model-result.v1" ||
        result.tenantId !== state.tenantId ||
        result.taskId !== state.taskId ||
        result.effectKey !== effectKey ||
        result.modelTaskRef !== task.bindings.modelTask.ref ||
        result.modelTaskVersion !== task.bindings.modelTask.version ||
        result.modelTaskSha256 !== task.bindings.modelTask.sha256 ||
        result.skillRef !== task.bindings.skill.ref ||
        result.skillVersion !== task.bindings.skill.version ||
        result.skillSha256 !== task.bindings.skill.sha256 ||
        result.contextSha256 !== contextSha256
      ) {
        fail("MODEL_RESULT_INVALID", "C12 model result is unbound.");
      }
      reference(result.outputRef, "modelResult.outputRef");
      sha256(result.outputSha256, "modelResult.outputSha256");
      reference(result.modelRef, "modelResult.modelRef");
      nonEmpty(result.modelVersion, "modelResult.modelVersion", 128);
      sha256(result.modelSha256, "modelResult.modelSha256");
      for (const name of [
        "inputTokens",
        "outputTokens",
        "totalTokens",
        "costMicrousd",
      ]) {
        safeInteger(result[name], `modelResult.${name}`);
      }
      if (
        result.inputTokens + result.outputTokens !== result.totalTokens
      ) {
        fail("MODEL_RESULT_INVALID", "C12 model usage is inconsistent.");
      }
      nextBudget = {
        limits: state.budget.limits,
        usage: budgetUsage(state, {
          inputTokens: result.inputTokens,
          outputTokens: result.outputTokens,
          totalTokens: result.totalTokens,
          costMicrousd: result.costMicrousd,
        }),
      };
      record = nodeRecord({
        graph: catalog.graph,
        state,
        nodeId,
        effectKey,
        outputRef: result.outputRef,
        outputSha256: result.outputSha256,
        evidenceRefs: [
          ...evidenceContext.evidenceRefs,
          ...evidenceContext.toolEvidenceRefs,
        ],
        binding: {
          modelRef: result.modelRef,
          modelVersion: result.modelVersion,
          modelSha256: result.modelSha256,
          modelTaskRef: result.modelTaskRef,
          modelTaskVersion: result.modelTaskVersion,
          modelTaskSha256: result.modelTaskSha256,
          skillRef: result.skillRef,
          skillVersion: result.skillVersion,
          skillSha256: result.skillSha256,
          contextSha256: result.contextSha256,
        },
        completedAt,
      });
    } else if (nodeId === "VALIDATE") {
      const draft = state.nodeRecords.find(
        (item) => item.nodeId === "DRAFT",
      );
      const result = exactPortResult(
        await callPort(() =>
          validator.validate({
            tenantId: state.tenantId,
            taskId: state.taskId,
            effectKey,
            artifactRef: draft.outputRef,
            artifactSha256: draft.outputSha256,
          }),
        ),
        [
          "schemaVersion",
          "tenantId",
          "taskId",
          "effectKey",
          "artifactRef",
          "artifactSha256",
          "outcome",
          "resultRef",
          "resultSha256",
          "ruleRef",
          "ruleVersion",
          "ruleSha256",
        ],
        "validationResult",
      );
      if (
        result.schemaVersion !== "c12-validation-result.v1" ||
        result.tenantId !== state.tenantId ||
        result.taskId !== state.taskId ||
        result.effectKey !== effectKey ||
        result.artifactRef !== draft.outputRef ||
        result.artifactSha256 !== draft.outputSha256 ||
        !["PASS", "FAIL"].includes(result.outcome)
      ) {
        fail("VALIDATION_RESULT_INVALID", "C12 validation is unbound.");
      }
      reference(result.resultRef, "validationResult.resultRef");
      sha256(result.resultSha256, "validationResult.resultSha256");
      reference(result.ruleRef, "validationResult.ruleRef");
      nonEmpty(result.ruleVersion, "validationResult.ruleVersion", 128);
      sha256(result.ruleSha256, "validationResult.ruleSha256");
      record = nodeRecord({
        graph: catalog.graph,
        state,
        nodeId,
        effectKey,
        outputRef: result.resultRef,
        outputSha256: result.resultSha256,
        evidenceRefs: [result.ruleRef],
        binding: {
          effectKey: result.effectKey,
          artifactRef: result.artifactRef,
          artifactSha256: result.artifactSha256,
          outcome: result.outcome,
          ruleRef: result.ruleRef,
          ruleVersion: result.ruleVersion,
          ruleSha256: result.ruleSha256,
        },
        completedAt,
      });
      if (result.outcome === "FAIL") terminalStatus = "INVALID";
    } else if (nodeId === "INDEPENDENT_REVIEW") {
      const draft = state.nodeRecords.find(
        (item) => item.nodeId === "DRAFT",
      );
      const draftModel = {
        ref: draft.binding.modelRef,
        version: draft.binding.modelVersion,
        sha256: draft.binding.modelSha256,
      };
      const reviewModel = clone(task.bindings.reviewModel);
      if (
        draftModel.ref === reviewModel.ref ||
        draftModel.sha256 === reviewModel.sha256
      ) {
        fail(
          "REVIEW_MODEL_NOT_INDEPENDENT",
          "C12 review model must differ from the draft model.",
        );
      }
      const result = exactPortResult(
        await callPort(() =>
          reviewer.review({
            tenantId: state.tenantId,
            taskId: state.taskId,
            effectKey,
            artifactRef: draft.outputRef,
            artifactSha256: draft.outputSha256,
            draftModel: clone(draftModel),
            reviewModel: clone(reviewModel),
            budget: clone(state.budget),
          }),
        ),
        [
          "schemaVersion",
          "tenantId",
          "taskId",
          "effectKey",
          "artifactRef",
          "artifactSha256",
          "outcome",
          "resultRef",
          "resultSha256",
          "reviewerRef",
          "reviewerVersion",
          "reviewerSha256",
          "draftModelRef",
          "draftModelVersion",
          "draftModelSha256",
          "reviewModelRef",
          "reviewModelVersion",
          "reviewModelSha256",
          "inputTokens",
          "outputTokens",
          "totalTokens",
          "costMicrousd",
        ],
        "reviewResult",
      );
      if (
        result.schemaVersion !== "c12-review-result.v1" ||
        result.tenantId !== state.tenantId ||
        result.taskId !== state.taskId ||
        result.effectKey !== effectKey ||
        result.artifactRef !== draft.outputRef ||
        result.artifactSha256 !== draft.outputSha256 ||
        !["PASS", "FAIL"].includes(result.outcome) ||
        result.draftModelRef !== draftModel.ref ||
        result.draftModelVersion !== draftModel.version ||
        result.draftModelSha256 !== draftModel.sha256 ||
        result.reviewModelRef !== reviewModel.ref ||
        result.reviewModelVersion !== reviewModel.version ||
        result.reviewModelSha256 !== reviewModel.sha256
      ) {
        fail("REVIEW_RESULT_INVALID", "C12 review is unbound.");
      }
      reference(result.resultRef, "reviewResult.resultRef");
      sha256(result.resultSha256, "reviewResult.resultSha256");
      reference(result.reviewerRef, "reviewResult.reviewerRef");
      nonEmpty(
        result.reviewerVersion,
        "reviewResult.reviewerVersion",
        128,
      );
      sha256(result.reviewerSha256, "reviewResult.reviewerSha256");
      reference(result.draftModelRef, "reviewResult.draftModelRef");
      nonEmpty(
        result.draftModelVersion,
        "reviewResult.draftModelVersion",
        128,
      );
      sha256(result.draftModelSha256, "reviewResult.draftModelSha256");
      reference(result.reviewModelRef, "reviewResult.reviewModelRef");
      nonEmpty(
        result.reviewModelVersion,
        "reviewResult.reviewModelVersion",
        128,
      );
      sha256(result.reviewModelSha256, "reviewResult.reviewModelSha256");
      for (const name of [
        "inputTokens",
        "outputTokens",
        "totalTokens",
        "costMicrousd",
      ]) {
        safeInteger(result[name], `reviewResult.${name}`);
      }
      if (
        result.inputTokens + result.outputTokens !== result.totalTokens
      ) {
        fail(
          "REVIEW_RESULT_INVALID",
          "C12 review usage is inconsistent.",
        );
      }
      nextBudget = {
        limits: state.budget.limits,
        usage: budgetUsage(state, {
          inputTokens: result.inputTokens,
          outputTokens: result.outputTokens,
          totalTokens: result.totalTokens,
          costMicrousd: result.costMicrousd,
        }),
      };
      record = nodeRecord({
        graph: catalog.graph,
        state,
        nodeId,
        effectKey,
        outputRef: result.resultRef,
        outputSha256: result.resultSha256,
        evidenceRefs: [result.reviewerRef],
        binding: {
          effectKey: result.effectKey,
          artifactRef: result.artifactRef,
          artifactSha256: result.artifactSha256,
          outcome: result.outcome,
          reviewerRef: result.reviewerRef,
          reviewerVersion: result.reviewerVersion,
          reviewerSha256: result.reviewerSha256,
          draftModelRef: result.draftModelRef,
          draftModelVersion: result.draftModelVersion,
          draftModelSha256: result.draftModelSha256,
          reviewModelRef: result.reviewModelRef,
          reviewModelVersion: result.reviewModelVersion,
          reviewModelSha256: result.reviewModelSha256,
          modelIndependent: true,
          inputTokens: result.inputTokens,
          outputTokens: result.outputTokens,
          totalTokens: result.totalTokens,
          costMicrousd: result.costMicrousd,
        },
        completedAt,
      });
      if (result.outcome === "FAIL") terminalStatus = "REJECTED";
    } else if (nodeId === "COMPLETE") {
      const decision = state.humanDecision;
      if (!decision) {
        fail("HUMAN_DECISION_REQUIRED", "C12 completion needs a decision.");
      }
      record = nodeRecord({
        graph: catalog.graph,
        state,
        nodeId,
        effectKey,
        outputRef: `evidence://c12/completed/${state.taskId}`,
        outputSha256: c12Sha256({
          taskId: state.taskId,
          decisionSha256: decision.decisionSha256,
          nodeRecords: state.nodeRecords.map((item) => item.outputSha256),
        }),
        evidenceRefs: [decision.decisionRef],
        binding: {
          decisionRef: decision.decisionRef,
          decisionSha256: decision.decisionSha256,
        },
        completedAt,
      });
      terminalStatus = "COMPLETED";
    } else {
      fail("INTEGRITY_VIOLATION", "C12 next node is invalid.");
    }

    const expectedState = transition(state, {
      record,
      status: terminalStatus ?? "RUNNING",
      nextNodeId: terminalStatus ? null : nextNode(nodeId),
      budget: nextBudget,
      updatedAt: completedAt,
    });
    const view = await statePort.transact(scope, {
      operation: receiptCommand.operation,
      taskId: state.taskId,
      expectedVersion: state.version,
      idempotencyKey: receiptCommand.idempotencyKey,
      requestSha256: receiptCommand.requestSha256,
      reduce(current) {
        if (current.stateSha256 !== state.stateSha256) {
          fail(
            "INTEGRITY_VIOLATION",
            "C12 State Port changed the transition input.",
          );
        }
        return expectedState;
      },
    });
    if (view?.replayed === true) {
      return validateAdvanceReplay(
        view,
        scope,
        state.taskId,
        request.expectedVersion,
        catalog,
        receiptCommand,
      );
    }
    return validateExactStatePortView(
      view,
      scope,
      catalog,
      task,
      expectedState,
      receiptCommand,
    );
  }

  async function resumeWithHumanDecision(context, request) {
    context = deepFreeze(clone(context));
    request = deepFreeze(clone(request));
    validateServerContext(context);
    validateRequest(request, [
      "taskId",
      "expectedVersion",
      "expectedStateSha256",
      "decisionRef",
      "decisionSha256",
    ]);
    if (!TASK_ID.test(request.taskId ?? "")) {
      fail("INVALID_INPUT", "taskId is invalid.");
    }
    safeInteger(request.expectedVersion, "expectedVersion", { min: 1 });
    sha256(request.expectedStateSha256, "expectedStateSha256");
    reference(request.decisionRef, "decisionRef");
    sha256(request.decisionSha256, "decisionSha256");
    const scope = await authorize(
      authorizer,
      context,
      request,
      "C12_RESUME_HUMAN_DECISION",
      request.taskId,
    );
    const requestSha256 = commandSha256("RESUME_HUMAN_DECISION", scope, request, {
      taskId: request.taskId,
      expectedVersion: request.expectedVersion,
      expectedStateSha256: request.expectedStateSha256,
      decisionRef: request.decisionRef,
      decisionSha256: request.decisionSha256,
    });
    const receiptCommand = {
      operation: "RESUME_HUMAN_DECISION",
      idempotencyKey: request.idempotencyKey,
      requestSha256,
    };
    const replay = await statePort.replay(scope, receiptCommand);
    if (replay) {
      return validateResumeReplay(
        replay,
        scope,
        request,
        catalog,
        receiptCommand,
      );
    }
    const state = await statePort.get(scope, request.taskId);
    if (!state) fail("TASK_NOT_FOUND", "C12 task was not found.");
    validateLoadedState(state, scope, request.taskId);
    if (
      state.version !== request.expectedVersion ||
      state.stateSha256 !== request.expectedStateSha256
    ) {
      fail("VERSION_CONFLICT", "C12 waiting state changed.");
    }
    if (
      state.status !== "WAITING_FOR_HUMAN" ||
      state.nextNodeId !== "HUMAN_GATE"
    ) {
      fail("HUMAN_GATE_NOT_READY", "C12 is not waiting for a decision.");
    }
    const task = catalog.resolve(state.tenantId, state.taskRef);
    validateTaskStateBinding(state, task, catalog.graph);
    const effectKey = c12Sha256({
      tenantId: state.tenantId,
      taskId: state.taskId,
      nodeId: "HUMAN_GATE",
      expectedVersion: state.version,
      stateSha256: state.stateSha256,
    });
    const result = exactPortResult(
      await callPort(() =>
        humanDecisionPort.verify({
          tenantId: state.tenantId,
          taskId: state.taskId,
          effectKey,
          expectedStateSha256: state.stateSha256,
          decisionRef: request.decisionRef,
          decisionSha256: request.decisionSha256,
          humanPrincipalId: scope.humanPrincipalId,
        }),
      ),
      [
        "schemaVersion",
        "tenantId",
        "taskId",
        "effectKey",
        "expectedStateSha256",
        "decisionRef",
        "decisionSha256",
        "outcome",
        "productionReusable",
        "externalEffectCount",
        "decidedByHumanPrincipalId",
      ],
      "humanDecision",
    );
    if (
      result.schemaVersion !== "c12-synthetic-human-decision.v1" ||
      result.tenantId !== state.tenantId ||
      result.taskId !== state.taskId ||
      result.effectKey !== effectKey ||
      result.expectedStateSha256 !== state.stateSha256 ||
      result.decisionRef !== request.decisionRef ||
      result.decisionSha256 !== request.decisionSha256 ||
      result.outcome !== "APPROVE" ||
      result.productionReusable !== false ||
      result.externalEffectCount !== 0 ||
      result.decidedByHumanPrincipalId !== scope.humanPrincipalId
    ) {
      fail("HUMAN_DECISION_INVALID", "C12 HumanDecision is unbound.");
    }
    const completedAt = now(clock);
    const record = nodeRecord({
      graph: catalog.graph,
      state,
      nodeId: "HUMAN_GATE",
      effectKey,
      outputRef: result.decisionRef,
      outputSha256: result.decisionSha256,
      evidenceRefs: [result.decisionRef],
      binding: result,
      completedAt,
    });
    const humanDecision = {
      decisionRef: result.decisionRef,
      decisionSha256: result.decisionSha256,
      decidedByHumanPrincipalId: result.decidedByHumanPrincipalId,
      productionReusable: false,
    };
    const expectedState = transition(state, {
      record,
      humanDecision,
      updatedAt: completedAt,
    });
    const view = await statePort.transact(scope, {
      operation: receiptCommand.operation,
      taskId: state.taskId,
      expectedVersion: state.version,
      idempotencyKey: receiptCommand.idempotencyKey,
      requestSha256: receiptCommand.requestSha256,
      reduce(current) {
        if (current.stateSha256 !== state.stateSha256) {
          fail(
            "INTEGRITY_VIOLATION",
            "C12 State Port changed the transition input.",
          );
        }
        return expectedState;
      },
    });
    if (view?.replayed === true) {
      return validateResumeReplay(
        view,
        scope,
        request,
        catalog,
        receiptCommand,
      );
    }
    return validateExactStatePortView(
      view,
      scope,
      catalog,
      task,
      expectedState,
      receiptCommand,
    );
  }

  async function inspect(context, request) {
    context = deepFreeze(clone(context));
    request = deepFreeze(clone(request));
    validateServerContext(context);
    validateRequest(request, ["taskId"], { idempotency: false });
    if (!TASK_ID.test(request.taskId ?? "")) {
      fail("INVALID_INPUT", "taskId is invalid.");
    }
    const scope = await authorize(
      authorizer,
      context,
      request,
      "C12_INSPECT",
      request.taskId,
    );
    const state = await statePort.get(scope, request.taskId);
    if (!state) fail("TASK_NOT_FOUND", "C12 task was not found.");
    validateLoadedState(state, scope, request.taskId);
    const task = catalog.resolve(state.tenantId, state.taskRef);
    validateTaskStateBinding(state, task, catalog.graph);
    return deepFreeze(clone(state));
  }

  return Object.freeze({
    start,
    advance,
    resumeWithHumanDecision,
    inspect,
  });
}

export const C12_NODE_ORDER = NODE_ORDER;
