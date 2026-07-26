import { createHash } from "node:crypto";

const UUID_V7 =
  "[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}";
const SYNTHETIC_TENANT_ID = new RegExp(`^stn_${UUID_V7}$`);
const PRINCIPAL_ID = new RegExp(`^prn_${UUID_V7}$`);
const DELEGATION_ID = new RegExp(`^dlg_${UUID_V7}$`);
const CASE_ID = new RegExp(`^cas_${UUID_V7}$`);
const THREAD_ID = new RegExp(`^thd_${UUID_V7}$`);
const RUN_ID = new RegExp(`^run_${UUID_V7}$`);
const ARTIFACT_ID = new RegExp(`^art_${UUID_V7}$`);
const TOOL_CALL_ID = new RegExp(`^tcl_${UUID_V7}$`);
const SHA256 = /^sha256:[a-f0-9]{64}$/;
const REFERENCE =
  /^(?:evidence|fixture|policy|profile|synthetic|test):\/\/\S+$/;
const VERSION = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const IDEMPOTENCY_KEY = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const CORRELATION_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const RESOURCE_ID = /^[a-z][a-z0-9_-]{0,127}$/;
const MOCK_RECEIPT_ID = /^mrc_[0-9a-f]{64}$/;
const TOOL_OUTBOX_TYPE = "product.aios.tool-call-prepared.v1";
const TERMINAL_RUN_STATES = new Set(["SUCCEEDED", "FAILED", "CANCELLED"]);
const TERMINAL_TOOL_STATES = new Set(["SUCCEEDED", "FAILED"]);
const RUN_STATES = new Set(["RUNNING", ...TERMINAL_RUN_STATES]);
const TOOL_STATES = new Set(["PREPARED", ...TERMINAL_TOOL_STATES]);
const PUBLIC_STORE_ERROR_CODES = new Set([
  "EVIDENCE_PAIR_INVALID",
  "ID_COLLISION",
  "IDEMPOTENCY_CONFLICT",
  "INTEGRITY_VIOLATION",
  "STORE_UNAVAILABLE",
  "STALE_VERSION",
  "TENANT_SCOPE_VIOLATION",
  "TOOL_CALL_IN_FLIGHT",
  "VERSION_CONFLICT",
]);

const COMMAND_FIELDS = Object.freeze({
  CREATE_CASE: Object.freeze(["kind", "goalRef"]),
  OPEN_THREAD: Object.freeze(["kind", "caseId", "purposeRef"]),
  RECORD_ARTIFACT_VERSION: Object.freeze([
    "kind",
    "artifactId",
    "caseId",
    "threadId",
    "expectedArtifactVersion",
    "artifactKind",
    "contentRef",
    "contentSha256",
  ]),
  START_RUN: Object.freeze(["kind", "threadId", "manifest"]),
  PREPARE_TOOL_CALL: Object.freeze([
    "kind",
    "runId",
    "expectedRunVersion",
    "operationRef",
    "operationVersion",
    "requestHash",
    "compensationRef",
  ]),
  FINISH_RUN: Object.freeze([
    "kind",
    "runId",
    "expectedRunVersion",
    "outcome",
    "resultArtifact",
  ]),
});
const TOOL_RESULT_FIELDS = Object.freeze([
  "kind",
  "runId",
  "expectedRunVersion",
  "toolCallId",
  "expectedToolCallVersion",
  "receiptId",
]);

const EVENT_TYPES = Object.freeze({
  CREATE_CASE: "product.aios.case-created.v1",
  OPEN_THREAD: "product.aios.thread-opened.v1",
  RECORD_ARTIFACT_VERSION: "product.aios.artifact-version-recorded.v1",
  START_RUN: "product.aios.run-started.v1",
  PREPARE_TOOL_CALL: TOOL_OUTBOX_TYPE,
  RECORD_TOOL_CALL_RESULT: "product.aios.tool-call-result-recorded.v1",
  FINISH_RUN: "product.aios.run-finished.v1",
});

export class AiosStateError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "AiosStateError";
    this.code = code;
  }
}

function fail(code, message) {
  throw new AiosStateError(code, message);
}

function clone(value) {
  return value === undefined ? undefined : structuredClone(value);
}

function exactKeys(value, allowed, field, required = allowed) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    fail("INVALID_INPUT", `${field} must be an object.`);
  }
  const keys = Object.keys(value);
  if (keys.some((key) => !allowed.includes(key))) {
    fail("INVALID_INPUT", `${field} contains unsupported fields.`);
  }
  if (required.some((key) => !keys.includes(key))) {
    fail("INVALID_INPUT", `${field} is incomplete.`);
  }
}

function nonEmptyString(value, field, maxLength = 256) {
  if (
    typeof value !== "string" ||
    !value.trim() ||
    value.length > maxLength
  ) {
    fail("INVALID_INPUT", `${field} is invalid.`);
  }
}

function identifier(value, expression, field) {
  nonEmptyString(value, field, 128);
  if (!expression.test(value)) {
    fail("INVALID_INPUT", `${field} is invalid.`);
  }
}

function positiveInteger(value, field) {
  if (!Number.isSafeInteger(value) || value < 1) {
    fail("INVALID_INPUT", `${field} must be a positive safe integer.`);
  }
}

function sha256String(value, field) {
  if (!SHA256.test(value ?? "")) {
    fail("INVALID_INPUT", `${field} must be a SHA-256 reference.`);
  }
}

function reference(value, field) {
  nonEmptyString(value, field, 512);
  if (!REFERENCE.test(value)) {
    fail(
      "P3_REQUIRED",
      `${field} must use an approved P1 Synthetic reference.`,
    );
  }
}

function version(value, field) {
  if (!VERSION.test(value ?? "")) {
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

function sha256(value) {
  return `sha256:${createHash("sha256")
    .update(typeof value === "string" ? value : canonicalize(value))
    .digest("hex")}`;
}

function uuidV7() {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  let milliseconds = BigInt(Date.now());
  for (let index = 5; index >= 0; index -= 1) {
    bytes[index] = Number(milliseconds & 0xffn);
    milliseconds >>= 8n;
  }
  bytes[6] = (bytes[6] & 0x0f) | 0x70;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = Array.from(bytes, (byte) =>
    byte.toString(16).padStart(2, "0"),
  ).join("");
  return [
    hex.slice(0, 8),
    hex.slice(8, 12),
    hex.slice(12, 16),
    hex.slice(16, 20),
    hex.slice(20),
  ].join("-");
}

function generatedId(prefix, expression, idFactory, field) {
  const value = `${prefix}${idFactory()}`;
  identifier(value, expression, field);
  return value;
}

function validateSyntheticTenantId(value) {
  if (!SYNTHETIC_TENANT_ID.test(value ?? "")) {
    fail(
      "P3_REQUIRED",
      "C08 accepts only Synthetic Tenant IDs before P3.",
    );
  }
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
    "trusted server context",
  );
  if (
    context.synthetic !== true ||
    context.routeTrustSource !== "VERIFIED_ROUTE_DESCRIPTOR" ||
    context.workloadTrustSource !== "VERIFIED_WORKLOAD_CONTEXT"
  ) {
    fail("UNTRUSTED_ROUTE", "C08 route or workload context is untrusted.");
  }
  validateSyntheticTenantId(context.tenantId);
  identifier(
    context.workloadActorPrincipalId,
    PRINCIPAL_ID,
    "workloadActorPrincipalId",
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
      "command",
    ],
    "state command request",
  );
  nonEmptyString(request.sessionToken, "sessionToken", 128);
  identifier(request.delegationId, DELEGATION_ID, "delegationId");
  if (!IDEMPOTENCY_KEY.test(request.idempotencyKey ?? "")) {
    fail("INVALID_INPUT", "idempotencyKey is invalid.");
  }
  if (!CORRELATION_ID.test(request.correlationId ?? "")) {
    fail("INVALID_INPUT", "correlationId is invalid.");
  }
  validateCommand(request.command);
}

function validateReconstructQuery(query) {
  exactKeys(
    query,
    ["sessionToken", "delegationId", "runId", "correlationId"],
    "reconstruct query",
  );
  nonEmptyString(query.sessionToken, "sessionToken", 128);
  identifier(query.delegationId, DELEGATION_ID, "delegationId");
  identifier(query.runId, RUN_ID, "runId");
  if (!CORRELATION_ID.test(query.correlationId ?? "")) {
    fail("INVALID_INPUT", "correlationId is invalid.");
  }
}

function validateToolResultWorkerContext(context) {
  exactKeys(
    context,
    [
      "synthetic",
      "routeTrustSource",
      "tenantId",
      "workerTrustSource",
      "workerPrincipalId",
    ],
    "Tool result Worker context",
  );
  if (
    context.synthetic !== true ||
    context.routeTrustSource !==
      "VERIFIED_TOOL_RESULT_ROUTE_DESCRIPTOR" ||
    context.workerTrustSource !== "VERIFIED_C0_MOCK_TOOL_WORKER"
  ) {
    fail(
      "UNTRUSTED_TOOL_RESULT_ROUTE",
      "C08 Tool result route is not trusted.",
    );
  }
  validateSyntheticTenantId(context.tenantId);
  identifier(context.workerPrincipalId, PRINCIPAL_ID, "workerPrincipalId");
}

function validateToolResultRequest(request) {
  exactKeys(
    request,
    ["idempotencyKey", "correlationId", "command"],
    "Tool result request",
  );
  if (
    !IDEMPOTENCY_KEY.test(request.idempotencyKey ?? "") ||
    !CORRELATION_ID.test(request.correlationId ?? "")
  ) {
    fail("INVALID_INPUT", "Tool result request metadata is invalid.");
  }
  exactKeys(request.command, TOOL_RESULT_FIELDS, "Tool result command");
  if (request.command.kind !== "RECORD_TOOL_CALL_RESULT") {
    fail("UNKNOWN_COMMAND", "Tool result command is not registered.");
  }
  identifier(request.command.runId, RUN_ID, "runId");
  positiveInteger(
    request.command.expectedRunVersion,
    "expectedRunVersion",
  );
  identifier(request.command.toolCallId, TOOL_CALL_ID, "toolCallId");
  positiveInteger(
    request.command.expectedToolCallVersion,
    "expectedToolCallVersion",
  );
  if (!MOCK_RECEIPT_ID.test(request.command.receiptId ?? "")) {
    fail("INVALID_INPUT", "C0 Mock receipt ID is invalid.");
  }
}

function validateVersionRef(value, field, { hash = true } = {}) {
  exactKeys(
    value,
    hash ? ["ref", "version", "sha256"] : ["ref", "version"],
    field,
  );
  reference(value.ref, `${field}.ref`);
  version(value.version, `${field}.version`);
  if (hash) sha256String(value.sha256, `${field}.sha256`);
}

function validateArtifactRef(value, field) {
  exactKeys(
    value,
    ["artifactId", "artifactVersion", "contentSha256"],
    field,
  );
  identifier(value.artifactId, ARTIFACT_ID, `${field}.artifactId`);
  positiveInteger(value.artifactVersion, `${field}.artifactVersion`);
  sha256String(value.contentSha256, `${field}.contentSha256`);
}

function validateRunManifest(value) {
  exactKeys(
    value,
    ["inputArtifact", "model", "prompt", "skill", "knowledge", "traceRef"],
    "run manifest",
  );
  validateArtifactRef(value.inputArtifact, "run manifest.inputArtifact");
  validateVersionRef(value.model, "run manifest.model");
  validateVersionRef(value.prompt, "run manifest.prompt");
  validateVersionRef(value.skill, "run manifest.skill");
  if (
    !Array.isArray(value.knowledge) ||
    value.knowledge.length < 1 ||
    value.knowledge.length > 32
  ) {
    fail(
      "INVALID_INPUT",
      "run manifest.knowledge must contain 1 to 32 references.",
    );
  }
  for (const [index, knowledge] of value.knowledge.entries()) {
    exactKeys(
      knowledge,
      ["evidenceRef", "version", "asOf", "sha256"],
      `run manifest.knowledge[${index}]`,
    );
    reference(
      knowledge.evidenceRef,
      `run manifest.knowledge[${index}].evidenceRef`,
    );
    version(
      knowledge.version,
      `run manifest.knowledge[${index}].version`,
    );
    canonicalInstant(
      knowledge.asOf,
      `run manifest.knowledge[${index}].asOf`,
    );
    sha256String(
      knowledge.sha256,
      `run manifest.knowledge[${index}].sha256`,
    );
  }
  if (
    new Set(
      value.knowledge.map(
        ({ evidenceRef, version: itemVersion }) =>
          `${evidenceRef}\u0000${itemVersion}`,
      ),
    ).size !== value.knowledge.length
  ) {
    fail("INVALID_INPUT", "run manifest.knowledge contains duplicates.");
  }
  reference(value.traceRef, "run manifest.traceRef");
}

function validateCommand(command) {
  if (!command || typeof command !== "object" || Array.isArray(command)) {
    fail("INVALID_INPUT", "command must be an object.");
  }
  const fields = COMMAND_FIELDS[command.kind];
  if (!fields) fail("UNKNOWN_COMMAND", "C08 command is not registered.");
  exactKeys(command, fields, "command");

  if (command.kind === "CREATE_CASE") {
    reference(command.goalRef, "goalRef");
  } else if (command.kind === "OPEN_THREAD") {
    identifier(command.caseId, CASE_ID, "caseId");
    reference(command.purposeRef, "purposeRef");
  } else if (command.kind === "RECORD_ARTIFACT_VERSION") {
    if (command.artifactId !== null) {
      identifier(command.artifactId, ARTIFACT_ID, "artifactId");
    }
    identifier(command.caseId, CASE_ID, "caseId");
    identifier(command.threadId, THREAD_ID, "threadId");
    if (
      !Number.isSafeInteger(command.expectedArtifactVersion) ||
      command.expectedArtifactVersion < 0
    ) {
      fail("INVALID_INPUT", "expectedArtifactVersion is invalid.");
    }
    if (
      (command.artifactId === null &&
        command.expectedArtifactVersion !== 0) ||
      (command.artifactId !== null &&
        command.expectedArtifactVersion < 1)
    ) {
      fail(
        "INVALID_INPUT",
        "Artifact version one creates an ID; later versions require it.",
      );
    }
    if (!["INPUT", "RESULT"].includes(command.artifactKind)) {
      fail("INVALID_INPUT", "artifactKind is invalid.");
    }
    reference(command.contentRef, "contentRef");
    sha256String(command.contentSha256, "contentSha256");
  } else if (command.kind === "START_RUN") {
    identifier(command.threadId, THREAD_ID, "threadId");
    validateRunManifest(command.manifest);
  } else if (command.kind === "PREPARE_TOOL_CALL") {
    identifier(command.runId, RUN_ID, "runId");
    positiveInteger(command.expectedRunVersion, "expectedRunVersion");
    reference(command.operationRef, "operationRef");
    version(command.operationVersion, "operationVersion");
    sha256String(command.requestHash, "requestHash");
    if (command.compensationRef !== null) {
      reference(command.compensationRef, "compensationRef");
    }
  } else if (command.kind === "FINISH_RUN") {
    identifier(command.runId, RUN_ID, "runId");
    positiveInteger(command.expectedRunVersion, "expectedRunVersion");
    if (!TERMINAL_RUN_STATES.has(command.outcome)) {
      fail("INVALID_INPUT", "Run outcome is invalid.");
    }
    validateArtifactRef(command.resultArtifact, "resultArtifact");
  }
}

function validateIdentity(identity, serverContext) {
  if (
    identity?.tenantId !== serverContext.tenantId ||
    identity?.tenantKind !== "SYNTHETIC" ||
    identity?.trustSource !==
      "VERIFIED_SESSION_IDENTITY_LINK_AND_WORKLOAD_CONTEXT" ||
    identity?.authorizationStatus !== "NOT_EVALUATED" ||
    identity?.workloadActor?.principalId !==
      serverContext.workloadActorPrincipalId ||
    !PRINCIPAL_ID.test(identity?.humanSubject?.principalId ?? "") ||
    !PRINCIPAL_ID.test(identity?.workloadActor?.principalId ?? "") ||
    !Array.isArray(identity?.delegationChain) ||
    identity.delegationChain.length < 1
  ) {
    fail("ACTION_IDENTITY_INVALID", "C05 action identity is inconsistent.");
  }
}

function validateAuthorization(
  authorization,
  identity,
  serverContext,
  surface,
  resourceId,
) {
  const leafDelegation = identity?.delegationChain?.at(-1);
  if (
    authorization?.trustSource !== "C06_BOUND_DECISION_EVIDENCE" ||
    typeof authorization?.decisionId !== "string" ||
    !authorization.decisionId ||
    typeof authorization?.evidenceRef !== "string" ||
    !authorization.evidenceRef ||
    typeof authorization?.policyVersion !== "string" ||
    !authorization.policyVersion ||
    authorization.tenantId !== serverContext.tenantId ||
    authorization.surface !== surface ||
    authorization.resourceId !== resourceId ||
    authorization.humanPrincipalId !==
      identity?.humanSubject?.principalId ||
    authorization.humanSecurityEpoch !==
      identity?.humanSubject?.securityEpoch ||
    authorization.workloadActorPrincipalId !==
      identity?.workloadActor?.principalId ||
    authorization.workloadActorSecurityEpoch !==
      identity?.workloadActor?.securityEpoch ||
    authorization.leafDelegationId !==
      leafDelegation?.delegationId ||
    authorization.delegationChainSha256 !==
      sha256(identity?.delegationChain) ||
    authorization.purposeRef !== identity?.purposeRef
  ) {
    fail(
      "AUTHORIZATION_BINDING_MISMATCH",
      "C06 decision is not bound to the resolved C05 identity.",
    );
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
    fail("TENANT_NOT_ACTIVE", "C03 Tenant admission is inconsistent.");
  }
}

function safeIdentity(identity) {
  return Object.freeze({
    identityAccountId: identity.identityAccountId,
    identityLinkId: identity.identityLinkId,
    sessionId: identity.sessionId,
    humanSubject: Object.freeze(clone(identity.humanSubject)),
    workloadActor: Object.freeze(clone(identity.workloadActor)),
    purposeRef: identity.purposeRef,
    delegationChain: Object.freeze(
      identity.delegationChain.map((entry) => Object.freeze(clone(entry))),
    ),
    trustSource: identity.trustSource,
  });
}

function safeAuthorization(authorization) {
  return Object.freeze({
    decisionId: authorization.decisionId,
    evidenceRef: authorization.evidenceRef,
    policyVersion: authorization.policyVersion,
  });
}

function actionIdentityBinding(identity) {
  return {
    humanPrincipalId: identity?.humanSubject?.principalId,
    humanSecurityEpoch: identity?.humanSubject?.securityEpoch,
    workloadActorPrincipalId: identity?.workloadActor?.principalId,
    workloadActorSecurityEpoch:
      identity?.workloadActor?.securityEpoch,
  };
}

function assertRunActionIdentity(run, identity) {
  if (
    sha256(actionIdentityBinding(run?.identity)) !==
    sha256(actionIdentityBinding(identity))
  ) {
    fail(
      "RUN_ACTION_IDENTITY_MISMATCH",
      "Run is bound to another action identity.",
    );
  }
}

function catalogQuery(
  tenantId,
  kind,
  ref,
  versionValue = null,
  hashValue = null,
  asOf = null,
) {
  return Object.freeze({
    tenantId,
    kind,
    ref,
    version: versionValue,
    sha256: hashValue,
    asOf,
  });
}

function verifyCommandReferences(referenceCatalog, tenantId, command) {
  const verify = (...values) => {
    try {
      referenceCatalog.verify(catalogQuery(tenantId, ...values));
    } catch {
      fail(
        "SYNTHETIC_REFERENCE_UNVERIFIED",
        "C08 reference is not in the frozen Synthetic catalog.",
      );
    }
  };
  if (command.kind === "CREATE_CASE") {
    verify("GOAL", command.goalRef);
  } else if (command.kind === "OPEN_THREAD") {
    verify("PURPOSE", command.purposeRef);
  } else if (command.kind === "RECORD_ARTIFACT_VERSION") {
    verify(
      "ARTIFACT_CONTENT",
      command.contentRef,
      String(command.expectedArtifactVersion + 1),
      command.contentSha256,
    );
  } else if (command.kind === "START_RUN") {
    verify(
      "MODEL",
      command.manifest.model.ref,
      command.manifest.model.version,
      command.manifest.model.sha256,
    );
    verify(
      "PROMPT",
      command.manifest.prompt.ref,
      command.manifest.prompt.version,
      command.manifest.prompt.sha256,
    );
    verify(
      "SKILL",
      command.manifest.skill.ref,
      command.manifest.skill.version,
      command.manifest.skill.sha256,
    );
    for (const item of command.manifest.knowledge) {
      verify(
        "KNOWLEDGE",
        item.evidenceRef,
        item.version,
        item.sha256,
        item.asOf,
      );
    }
    verify("TRACE", command.manifest.traceRef);
  } else if (command.kind === "PREPARE_TOOL_CALL") {
    verify(
      "TOOL_OPERATION",
      command.operationRef,
      command.operationVersion,
    );
    if (command.compensationRef !== null) {
      verify("COMPENSATION", command.compensationRef);
    }
  }
}

function authorizationResource(referenceCatalog, tenantId, surface) {
  let resources;
  try {
    resources = referenceCatalog.authorizationResources(tenantId);
  } catch {
    fail(
      "SYNTHETIC_REFERENCE_UNVERIFIED",
      "Synthetic Tenant authorization resources are not frozen.",
    );
  }
  const value = resources?.[surface];
  if (!RESOURCE_ID.test(value ?? "")) {
    fail(
      "SYNTHETIC_REFERENCE_UNVERIFIED",
      "Synthetic authorization resource is invalid.",
    );
  }
  return value;
}

function eventRecord({
  idFactory,
  now,
  tenantId,
  correlationId,
  commandKind,
  aggregateType,
  aggregateId,
  aggregateVersion,
  data,
}) {
  const eventId = generatedId("evt_", new RegExp(`^evt_${UUID_V7}$`), idFactory, "eventId");
  const event = Object.freeze({
    specversion: "1.0",
    id: eventId,
    source: "/aios-core/state",
    type: EVENT_TYPES[commandKind],
    subject: aggregateId,
    time: now,
    datacontenttype: "application/json",
    tenantkind: "SYNTHETIC",
    correlationid: correlationId,
    synthetic: true,
    data: Object.freeze({
      tenant_id: tenantId,
      aggregate_type: aggregateType,
      aggregate_id: aggregateId,
      aggregate_version: aggregateVersion,
      ...clone(data),
    }),
  });
  return Object.freeze({
    eventId,
    aggregateType,
    aggregateId,
    aggregateVersion,
    event,
    createdAt: now,
  });
}

function effectKey({ tenantId, runId, toolCallId, requestHash }) {
  return `effect_${sha256({
    tenantId,
    runId,
    toolCallId,
    requestHash,
  }).slice(7)}`;
}

function reconstructionValue(value) {
  const { run, inputArtifact, resultArtifact, toolCalls } = value;
  return Object.freeze({
    runId: run.runId,
    caseId: run.caseId,
    threadId: run.threadId,
    input: Object.freeze({
      artifactId: inputArtifact.artifactId,
      artifactVersion: inputArtifact.artifactVersion,
      contentRef: inputArtifact.contentRef,
      contentSha256: inputArtifact.contentSha256,
    }),
    model: Object.freeze(clone(run.baseManifest.model)),
    prompt: Object.freeze(clone(run.baseManifest.prompt)),
    skill: Object.freeze(clone(run.baseManifest.skill)),
    knowledge: Object.freeze(
      run.baseManifest.knowledge.map((item) => Object.freeze(clone(item))),
    ),
    tools: Object.freeze(
      [...toolCalls]
        .sort((left, right) => left.toolCallId.localeCompare(right.toolCallId))
        .map((toolCall) =>
          Object.freeze({
            toolCallId: toolCall.toolCallId,
            operationRef: toolCall.operationRef,
            operationVersion: toolCall.operationVersion,
            requestHash: toolCall.requestHash,
            effectKey: toolCall.effectKey,
            compensationRef: toolCall.compensationRef,
            policy: Object.freeze(clone(toolCall.authorization)),
            outcome: toolCall.outcome,
            receiptRef: toolCall.receiptRef,
            receiptHash: toolCall.receiptHash,
          }),
        ),
    ),
    policy: Object.freeze(clone(run.authorization)),
    result: Object.freeze({
      artifactId: resultArtifact.artifactId,
      artifactVersion: resultArtifact.artifactVersion,
      contentRef: resultArtifact.contentRef,
      contentSha256: resultArtifact.contentSha256,
    }),
    tenantLifecycleVersion: run.tenantLifecycleVersion,
    actor: Object.freeze(clone(run.identity)),
    traceRef: run.baseManifest.traceRef,
    dependentPackageStatus: "PENDING_DEPENDENT_PACKAGE",
  });
}

function operationalRunValue(value) {
  const {
    case: runCase,
    thread,
    run,
    inputArtifact,
    resultArtifact,
    toolCalls,
  } = value;
  return Object.freeze({
    runId: run.runId,
    caseId: run.caseId,
    threadId: run.threadId,
    case: Object.freeze({
      caseId: runCase.caseId,
      state: runCase.state,
      version: runCase.version,
      goalRef: runCase.goalRef,
    }),
    thread: Object.freeze({
      threadId: thread.threadId,
      caseId: thread.caseId,
      state: thread.state,
      version: thread.version,
      purposeRef: thread.purposeRef,
    }),
    state: run.state,
    version: run.version,
    input: Object.freeze({
      artifactId: inputArtifact.artifactId,
      artifactVersion: inputArtifact.artifactVersion,
      contentRef: inputArtifact.contentRef,
      contentSha256: inputArtifact.contentSha256,
    }),
    model: Object.freeze(clone(run.baseManifest.model)),
    prompt: Object.freeze(clone(run.baseManifest.prompt)),
    skill: Object.freeze(clone(run.baseManifest.skill)),
    knowledge: Object.freeze(
      run.baseManifest.knowledge.map((item) => Object.freeze(clone(item))),
    ),
    tools: Object.freeze(
      [...toolCalls]
        .sort((left, right) => left.toolCallId.localeCompare(right.toolCallId))
        .map((toolCall) =>
          Object.freeze({
            toolCallId: toolCall.toolCallId,
            state: toolCall.state,
            version: toolCall.version,
            operationRef: toolCall.operationRef,
            operationVersion: toolCall.operationVersion,
            requestHash: toolCall.requestHash,
            effectKey: toolCall.effectKey,
            compensationRef: toolCall.compensationRef,
            policy: Object.freeze(clone(toolCall.authorization)),
            outcome: toolCall.outcome,
            receiptRef: toolCall.receiptRef,
            receiptHash: toolCall.receiptHash,
          }),
        ),
    ),
    policy: Object.freeze(clone(run.authorization)),
    result: resultArtifact
      ? Object.freeze({
          artifactId: resultArtifact.artifactId,
          artifactVersion: resultArtifact.artifactVersion,
          contentRef: resultArtifact.contentRef,
          contentSha256: resultArtifact.contentSha256,
        })
      : null,
    tenantLifecycleVersion: run.tenantLifecycleVersion,
    actor: Object.freeze(clone(run.identity)),
    traceRef: run.baseManifest.traceRef,
    reconstructionHash: run.reconstructionHash,
    dependentPackageStatus: "PENDING_DEPENDENT_PACKAGE",
  });
}

function mapClone(value) {
  return new Map(
    [...value.entries()].map(([key, item]) => [key, clone(item)]),
  );
}

function emptyTenantState() {
  return {
    cases: new Map(),
    threads: new Map(),
    runs: new Map(),
    artifacts: new Map(),
    toolCalls: new Map(),
    events: new Map(),
    outbox: new Map(),
    receipts: new Map(),
  };
}

function cloneTenantState(state) {
  return {
    cases: mapClone(state.cases),
    threads: mapClone(state.threads),
    runs: mapClone(state.runs),
    artifacts: mapClone(state.artifacts),
    toolCalls: mapClone(state.toolCalls),
    events: mapClone(state.events),
    outbox: mapClone(state.outbox),
    receipts: mapClone(state.receipts),
  };
}

function outboxView(entry) {
  return Object.freeze({
    eventId: entry.eventId,
    state: entry.state,
    leaseVersion: entry.leaseVersion,
    workerId: entry.workerId,
    leaseExpiresAt: entry.leaseExpiresAt,
    lastErrorCode: entry.lastErrorCode,
    event: clone(entry.event),
    createdAt: entry.createdAt,
    availableAt: entry.availableAt,
    publishedAt: entry.publishedAt,
  });
}

function validateScope(scope) {
  if (
    scope?.trustSource !== "C07_VERIFIED_TENANT_SCOPE" ||
    scope?.tenantKind !== "SYNTHETIC" ||
    !Number.isSafeInteger(scope?.lifecycleVersion) ||
    scope.lifecycleVersion < 1 ||
    typeof scope?.decisionId !== "string" ||
    typeof scope?.evidenceRef !== "string" ||
    typeof scope?.policyVersion !== "string"
  ) {
    fail("TENANT_SCOPE_VIOLATION", "C08 storage scope is invalid.");
  }
  validateSyntheticTenantId(scope.tenantId);
}

function createMemoryTransaction(state) {
  function insertUnique(map, key, value, code) {
    if (map.has(key)) fail(code, "C08 object already exists.");
    map.set(key, clone(value));
  }

  return Object.freeze({
    async findCase(caseId) {
      return clone(state.cases.get(caseId) ?? null);
    },
    async findThread(threadId) {
      return clone(state.threads.get(threadId) ?? null);
    },
    async findRun(runId) {
      return clone(state.runs.get(runId) ?? null);
    },
    async findArtifact(artifactId, artifactVersion) {
      return clone(
        state.artifacts.get(`${artifactId}\u0000${artifactVersion}`) ?? null,
      );
    },
    async findToolCall(toolCallId) {
      return clone(state.toolCalls.get(toolCallId) ?? null);
    },
    async listToolCallsByRun(runId) {
      return [...state.toolCalls.values()]
        .filter((item) => item.runId === runId)
        .map(clone);
    },
    async insertCase(value) {
      insertUnique(state.cases, value.caseId, value, "CASE_CONFLICT");
    },
    async insertThread(value) {
      insertUnique(state.threads, value.threadId, value, "THREAD_CONFLICT");
    },
    async insertRun(value) {
      insertUnique(state.runs, value.runId, value, "RUN_CONFLICT");
    },
    async insertArtifact(value) {
      insertUnique(
        state.artifacts,
        `${value.artifactId}\u0000${value.artifactVersion}`,
        value,
        "ARTIFACT_VERSION_CONFLICT",
      );
    },
    async insertToolCall(value) {
      insertUnique(
        state.toolCalls,
        value.toolCallId,
        value,
        "TOOL_CALL_CONFLICT",
      );
    },
    async updateRun(value, expectedVersion) {
      const current = state.runs.get(value.runId);
      if (!current || current.version !== expectedVersion) {
        fail("STALE_VERSION", "Run version is stale.");
      }
      state.runs.set(value.runId, clone(value));
    },
    async updateToolCall(value, expectedVersion) {
      const current = state.toolCalls.get(value.toolCallId);
      if (!current || current.version !== expectedVersion) {
        fail("STALE_VERSION", "ToolCall version is stale.");
      }
      state.toolCalls.set(value.toolCallId, clone(value));
    },
    async appendEvent(record) {
      insertUnique(
        state.events,
        record.eventId,
        record,
        "EVENT_CONFLICT",
      );
    },
    async appendOutbox(record) {
      insertUnique(
        state.outbox,
        record.eventId,
        {
          ...clone(record),
          state: "PENDING",
          leaseVersion: 0,
          workerId: null,
          leaseExpiresAt: null,
          availableAt: record.createdAt,
          publishedAt: null,
          lastErrorCode: null,
        },
        "OUTBOX_CONFLICT",
      );
    },
  });
}

export function createMemoryAiosStateStore() {
  const tenants = new Map();
  const locks = new Map();

  async function withTenantLock(tenantId, operation) {
    const previous = locks.get(tenantId) ?? Promise.resolve();
    let release;
    const current = new Promise((resolveLock) => {
      release = resolveLock;
    });
    locks.set(tenantId, current);
    await previous;
    try {
      return await operation();
    } finally {
      release();
      if (locks.get(tenantId) === current) locks.delete(tenantId);
    }
  }

  async function runCommand(scope, metadata, reducer) {
    validateScope(scope);
    exactKeys(
      metadata,
      [
        "idempotencyKey",
        "requestHash",
        "commandKind",
        "correlationId",
      ],
      "command metadata",
    );
    if (
      !IDEMPOTENCY_KEY.test(metadata.idempotencyKey ?? "") ||
      !SHA256.test(metadata.requestHash ?? "") ||
      (!COMMAND_FIELDS[metadata.commandKind] &&
        metadata.commandKind !== "RECORD_TOOL_CALL_RESULT") ||
      !CORRELATION_ID.test(metadata.correlationId ?? "") ||
      typeof reducer !== "function"
    ) {
      fail("INVALID_INPUT", "Command metadata is invalid.");
    }
    return withTenantLock(scope.tenantId, async () => {
      const current = tenants.get(scope.tenantId) ?? emptyTenantState();
      const receipt = current.receipts.get(metadata.idempotencyKey);
      if (receipt) {
        if (
          receipt.requestHash !== metadata.requestHash ||
          receipt.commandKind !== metadata.commandKind
        ) {
          fail(
            "IDEMPOTENCY_CONFLICT",
            "Idempotency key was reused for different content.",
          );
        }
        return Object.freeze({ value: clone(receipt.value), duplicate: true });
      }
      const draft = cloneTenantState(current);
      const value = await reducer(createMemoryTransaction(draft));
      const emittedEvents = [...draft.events.keys()].filter(
        (eventId) => !current.events.has(eventId),
      );
      const emittedOutbox = [...draft.outbox.keys()].filter(
        (eventId) => !current.outbox.has(eventId),
      );
      if (
        !value ||
        typeof value !== "object" ||
        Array.isArray(value) ||
        emittedEvents.length !== 1 ||
        emittedOutbox.length !== 1 ||
        emittedEvents[0] !== emittedOutbox[0]
      ) {
        fail(
          "EVIDENCE_PAIR_INVALID",
          "C08 command requires one exact Event and Outbox pair.",
        );
      }
      draft.receipts.set(metadata.idempotencyKey, {
        ...clone(metadata),
        value: clone(value),
      });
      tenants.set(scope.tenantId, draft);
      return Object.freeze({ value: clone(value), duplicate: false });
    });
  }

  async function readRun(scope, { runId }) {
    validateScope(scope);
    identifier(runId, RUN_ID, "runId");
    const state = tenants.get(scope.tenantId) ?? emptyTenantState();
    const run = state.runs.get(runId);
    if (!run) return null;
    const input = run.baseManifest.inputArtifact;
    const result = run.resultArtifact;
    return Object.freeze({
      case: clone(state.cases.get(run.caseId) ?? null),
      thread: clone(state.threads.get(run.threadId) ?? null),
      run: clone(run),
      inputArtifact: clone(
        state.artifacts.get(
          `${input.artifactId}\u0000${input.artifactVersion}`,
        ),
      ),
      resultArtifact: result
        ? clone(
            state.artifacts.get(
              `${result.artifactId}\u0000${result.artifactVersion}`,
            ),
          )
        : null,
      toolCalls: Object.freeze(
        [...state.toolCalls.values()]
          .filter((item) => item.runId === runId)
          .map((item) => Object.freeze(clone(item))),
      ),
    });
  }

  async function readTenantSnapshot(scope) {
    validateScope(scope);
    const state = tenants.get(scope.tenantId) ?? emptyTenantState();
    const countByState = (items) =>
      [...items.values()].reduce((counts, item) => {
        counts[item.state] = (counts[item.state] ?? 0) + 1;
        return counts;
      }, {});
    return Object.freeze({
      tenantId: scope.tenantId,
      tenantKind: "SYNTHETIC",
      counts: Object.freeze({
        cases: state.cases.size,
        threads: state.threads.size,
        runs: state.runs.size,
        artifacts: state.artifacts.size,
        toolCalls: state.toolCalls.size,
        events: state.events.size,
        outbox: state.outbox.size,
        receipts: state.receipts.size,
      }),
      runStates: Object.freeze(countByState(state.runs)),
      toolCallStates: Object.freeze(countByState(state.toolCalls)),
      outboxStates: Object.freeze(countByState(state.outbox)),
    });
  }

  async function claimOutbox(
    scope,
    { workerId, now, leaseExpiresAt, limit = 10 },
  ) {
    validateScope(scope);
    nonEmptyString(workerId, "workerId", 128);
    canonicalInstant(now, "now");
    canonicalInstant(leaseExpiresAt, "leaseExpiresAt");
    positiveInteger(limit, "limit");
    if (Date.parse(leaseExpiresAt) <= Date.parse(now) || limit > 100) {
      fail("INVALID_INPUT", "Outbox lease is invalid.");
    }
    return withTenantLock(scope.tenantId, async () => {
      const state = tenants.get(scope.tenantId) ?? emptyTenantState();
      const claimed = [];
      for (const entry of state.outbox.values()) {
        if (claimed.length >= limit) break;
        if (
          entry.state === "PUBLISHED" ||
          (entry.state === "PENDING" &&
            Date.parse(entry.availableAt) > Date.parse(now)) ||
          (entry.state === "LEASED" &&
            Date.parse(entry.leaseExpiresAt) > Date.parse(now))
        ) {
          continue;
        }
        entry.state = "LEASED";
        entry.workerId = workerId;
        entry.leaseVersion += 1;
        entry.leaseExpiresAt = leaseExpiresAt;
        entry.lastErrorCode = null;
        claimed.push(outboxView(entry));
      }
      tenants.set(scope.tenantId, state);
      return Object.freeze(claimed);
    });
  }

  async function completeOutbox(
    scope,
    { eventId, workerId, leaseVersion, now },
  ) {
    validateScope(scope);
    nonEmptyString(eventId, "eventId", 128);
    nonEmptyString(workerId, "workerId", 128);
    positiveInteger(leaseVersion, "leaseVersion");
    canonicalInstant(now, "now");
    return withTenantLock(scope.tenantId, async () => {
      const state = tenants.get(scope.tenantId) ?? emptyTenantState();
      const entry = state.outbox.get(eventId);
      if (
        !entry ||
        entry.state !== "LEASED" ||
        entry.workerId !== workerId ||
        entry.leaseVersion !== leaseVersion ||
        Date.parse(entry.leaseExpiresAt) < Date.parse(now)
      ) {
        fail("STALE_OUTBOX_LEASE", "Outbox lease is stale.");
      }
      entry.state = "PUBLISHED";
      entry.publishedAt = now;
      entry.workerId = null;
      entry.leaseExpiresAt = null;
      entry.lastErrorCode = null;
      state.outbox.set(eventId, entry);
      tenants.set(scope.tenantId, state);
      return outboxView(entry);
    });
  }

  async function failOutbox(
    scope,
    {
      eventId,
      workerId,
      leaseVersion,
      now,
      retryAt,
      errorCode,
    },
  ) {
    validateScope(scope);
    canonicalInstant(now, "now");
    canonicalInstant(retryAt, "retryAt");
    nonEmptyString(errorCode, "errorCode", 64);
    if (Date.parse(retryAt) <= Date.parse(now)) {
      fail("INVALID_INPUT", "Outbox retry time is invalid.");
    }
    return withTenantLock(scope.tenantId, async () => {
      const state = tenants.get(scope.tenantId) ?? emptyTenantState();
      const entry = state.outbox.get(eventId);
      if (
        !entry ||
        entry.state !== "LEASED" ||
        entry.workerId !== workerId ||
        entry.leaseVersion !== leaseVersion ||
        Date.parse(entry.leaseExpiresAt) < Date.parse(now)
      ) {
        fail("STALE_OUTBOX_LEASE", "Outbox lease is stale.");
      }
      entry.state = "PENDING";
      entry.workerId = null;
      entry.leaseExpiresAt = null;
      entry.availableAt = retryAt;
      entry.lastErrorCode = errorCode;
      state.outbox.set(eventId, entry);
      tenants.set(scope.tenantId, state);
      return outboxView(entry);
    });
  }

  return Object.freeze({
    runCommand,
    readRun,
    readTenantSnapshot,
    claimOutbox,
    completeOutbox,
    failOutbox,
  });
}

function normalizeDependency(error, fallbackCode) {
  if (error instanceof AiosStateError) return error;
  if (
    error?.name === "AiosStateStoreError" &&
    PUBLIC_STORE_ERROR_CODES.has(error.code)
  ) {
    return new AiosStateError(
      error.code,
      "C08 state storage rejected the operation.",
    );
  }
  if (
    ["TENANT_NOT_ACTIVE", "TENANT_DELETED", "TENANT_NOT_FOUND"].includes(
      error?.code,
    )
  ) {
    return new AiosStateError(
      "TENANT_NOT_ACTIVE",
      "Synthetic Tenant is not accepting C08 requests.",
    );
  }
  return new AiosStateError(fallbackCode, "C08 dependency failed closed.");
}

export function createAiosStateCore({
  tenantRegistry,
  stablePrincipalRegistry,
  authorizer,
  store,
  referenceCatalog,
  toolReceiptVerifier,
  controlAuthorize = async () => ({ allowed: false }),
  idFactory = uuidV7,
  clock = () => new Date().toISOString(),
}) {
  if (
    typeof tenantRegistry?.admitNewRequest !== "function" ||
    typeof stablePrincipalRegistry?.resolveActionIdentity !== "function" ||
    typeof authorizer?.enforce !== "function" ||
    typeof store?.runCommand !== "function" ||
    typeof store?.readRun !== "function" ||
    typeof store?.readTenantSnapshot !== "function" ||
    typeof referenceCatalog?.verify !== "function" ||
    typeof referenceCatalog?.authorizationResources !== "function" ||
    typeof toolReceiptVerifier?.resolve !== "function" ||
    typeof controlAuthorize !== "function" ||
    typeof idFactory !== "function" ||
    typeof clock !== "function"
  ) {
    fail("INVALID_CONFIGURATION", "C08 dependencies are incomplete.");
  }

  async function trustedInputs(serverContext, request, surface, resourceId) {
    const operationId = `C08_${request.command.kind}`;
    const resolveIdentity = async () => {
      let value;
      try {
        value = await stablePrincipalRegistry.resolveActionIdentity(
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
      validateIdentity(value, serverContext);
      return safeIdentity(value);
    };

    const firstIdentity = await resolveIdentity();
    let authorization;
    try {
      authorization = await authorizer.enforce(
        Object.freeze({ ...serverContext }),
        Object.freeze({
          sessionToken: request.sessionToken,
          delegationId: request.delegationId,
          resourceId,
          correlationId: request.correlationId,
        }),
        Object.freeze({
          operationId,
          surface,
          path: "aios-state-core",
          mode: surface === "READ" ? "READ" : "WRITE",
        }),
      );
    } catch (error) {
      const code =
        error?.code === "AUTHORIZATION_UNAVAILABLE"
          ? "AUTHORIZATION_UNAVAILABLE"
          : "ACCESS_DENIED";
      throw new AiosStateError(code, "C08 operation was denied.");
    }
    validateAuthorization(
      authorization,
      firstIdentity,
      serverContext,
      surface,
      resourceId,
    );

    const finalIdentity = await resolveIdentity();
    if (sha256(firstIdentity) !== sha256(finalIdentity)) {
      fail(
        "ACTION_IDENTITY_CHANGED",
        "C05 action identity changed during C08 authorization.",
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
      authorization: safeAuthorization(authorization),
      admission: Object.freeze(clone(admission)),
      scope: Object.freeze({
        trustSource: "C07_VERIFIED_TENANT_SCOPE",
        tenantId: serverContext.tenantId,
        tenantKind: "SYNTHETIC",
        lifecycleVersion: admission.lifecycleVersion,
        operationId,
        storagePath: "aios-state-core",
        correlationId: request.correlationId,
        decisionId: authorization.decisionId,
        evidenceRef: authorization.evidenceRef,
        policyVersion: authorization.policyVersion,
      }),
    });
  }

  async function reduceCommand({
    tx,
    command,
    trusted,
    correlationId,
    now,
  }) {
    const tenantId = trusted.scope.tenantId;
    let value;
    let aggregateType;
    let aggregateId;
    let aggregateVersion;
    let eventData;

    if (command.kind === "CREATE_CASE") {
      const caseId = generatedId("cas_", CASE_ID, idFactory, "caseId");
      const record = {
        caseId,
        tenantId,
        tenantKind: "SYNTHETIC",
        state: "OPEN",
        version: 1,
        goalRef: command.goalRef,
        createdAt: now,
        updatedAt: now,
      };
      await tx.insertCase(record);
      value = {
        commandKind: command.kind,
        caseId,
        state: record.state,
        version: record.version,
      };
      aggregateType = "CASE";
      aggregateId = caseId;
      aggregateVersion = 1;
      eventData = { state: record.state, goal_ref: record.goalRef };
    } else if (command.kind === "OPEN_THREAD") {
      const caseValue = await tx.findCase(command.caseId);
      if (!caseValue || caseValue.state !== "OPEN") {
        fail("CASE_NOT_OPEN", "Thread requires an open Case.");
      }
      const threadId = generatedId(
        "thd_",
        THREAD_ID,
        idFactory,
        "threadId",
      );
      const record = {
        threadId,
        caseId: caseValue.caseId,
        state: "OPEN",
        version: 1,
        purposeRef: command.purposeRef,
        createdAt: now,
        updatedAt: now,
      };
      await tx.insertThread(record);
      value = {
        commandKind: command.kind,
        caseId: record.caseId,
        threadId,
        state: record.state,
        version: record.version,
      };
      aggregateType = "THREAD";
      aggregateId = threadId;
      aggregateVersion = 1;
      eventData = {
        case_id: record.caseId,
        state: record.state,
        purpose_ref: record.purposeRef,
      };
    } else if (command.kind === "RECORD_ARTIFACT_VERSION") {
      const caseValue = await tx.findCase(command.caseId);
      const thread = await tx.findThread(command.threadId);
      if (
        !caseValue ||
        caseValue.state !== "OPEN" ||
        !thread ||
        thread.state !== "OPEN" ||
        thread.caseId !== caseValue.caseId
      ) {
        fail("INVALID_RELATION", "Artifact Case or Thread is invalid.");
      }
      let artifactId = command.artifactId;
      if (artifactId === null) {
        artifactId = generatedId(
          "art_",
          ARTIFACT_ID,
          idFactory,
          "artifactId",
        );
      } else {
        const nextExisting = await tx.findArtifact(
          artifactId,
          command.expectedArtifactVersion + 1,
        );
        if (nextExisting) {
          fail("STALE_VERSION", "Artifact version is stale.");
        }
        const previous = await tx.findArtifact(
          artifactId,
          command.expectedArtifactVersion,
        );
        if (
          !previous ||
          previous.caseId !== caseValue.caseId ||
          previous.threadId !== thread.threadId ||
          previous.kind !== command.artifactKind
        ) {
          fail(
            "ARTIFACT_VERSION_INVALID",
            "Artifact version does not continue an exact version chain.",
          );
        }
      }
      const record = {
        artifactId,
        caseId: caseValue.caseId,
        threadId: thread.threadId,
        artifactVersion: command.expectedArtifactVersion + 1,
        kind: command.artifactKind,
        contentRef: command.contentRef,
        contentSha256: command.contentSha256,
        createdAt: now,
      };
      await tx.insertArtifact(record);
      value = {
        commandKind: command.kind,
        caseId: record.caseId,
        threadId: record.threadId,
        artifactId,
        artifactVersion: record.artifactVersion,
        artifactKind: record.kind,
        contentSha256: record.contentSha256,
      };
      aggregateType = "ARTIFACT";
      aggregateId = artifactId;
      aggregateVersion = record.artifactVersion;
      eventData = {
        case_id: record.caseId,
        thread_id: record.threadId,
        artifact_kind: record.kind,
        content_ref: record.contentRef,
        content_sha256: record.contentSha256,
      };
    } else if (command.kind === "START_RUN") {
      const thread = await tx.findThread(command.threadId);
      if (!thread || thread.state !== "OPEN") {
        fail("THREAD_NOT_OPEN", "Run requires an open Thread.");
      }
      const caseValue = await tx.findCase(thread.caseId);
      const input = command.manifest.inputArtifact;
      const inputArtifact = await tx.findArtifact(
        input.artifactId,
        input.artifactVersion,
      );
      if (
        !caseValue ||
        caseValue.state !== "OPEN" ||
        !inputArtifact ||
        inputArtifact.caseId !== caseValue.caseId ||
        inputArtifact.threadId !== thread.threadId ||
        inputArtifact.kind !== "INPUT" ||
        inputArtifact.contentSha256 !== input.contentSha256
      ) {
        fail("ARTIFACT_VERSION_INVALID", "Run input Artifact is invalid.");
      }
      const runId = generatedId("run_", RUN_ID, idFactory, "runId");
      const record = {
        runId,
        caseId: caseValue.caseId,
        threadId: thread.threadId,
        state: "RUNNING",
        version: 1,
        baseManifest: Object.freeze(clone(command.manifest)),
        identity: trusted.identity,
        authorization: trusted.authorization,
        tenantLifecycleVersion: trusted.admission.lifecycleVersion,
        resultArtifact: null,
        reconstructionHash: null,
        createdAt: now,
        updatedAt: now,
      };
      await tx.insertRun(record);
      value = {
        commandKind: command.kind,
        caseId: record.caseId,
        threadId: record.threadId,
        runId,
        state: record.state,
        version: record.version,
      };
      aggregateType = "RUN";
      aggregateId = runId;
      aggregateVersion = 1;
      eventData = {
        case_id: record.caseId,
        thread_id: record.threadId,
        state: record.state,
        input_artifact_id: inputArtifact.artifactId,
        input_artifact_version: inputArtifact.artifactVersion,
        authorization_decision_id: record.authorization.decisionId,
        tenant_lifecycle_version: record.tenantLifecycleVersion,
      };
    } else if (command.kind === "PREPARE_TOOL_CALL") {
      const run = await tx.findRun(command.runId);
      if (!run || run.state !== "RUNNING") {
        fail("RUN_NOT_RUNNING", "ToolCall requires a running Run.");
      }
      assertRunActionIdentity(run, trusted.identity);
      if (run.version !== command.expectedRunVersion) {
        fail("STALE_VERSION", "Run version is stale.");
      }
      const existingToolCalls = await tx.listToolCallsByRun(run.runId);
      if (
        existingToolCalls.some(
          (toolCall) => toolCall.state === "PREPARED",
        )
      ) {
        fail(
          "TOOL_CALL_IN_FLIGHT",
          "Run already has a prepared ToolCall.",
        );
      }
      const toolCallId = generatedId(
        "tcl_",
        TOOL_CALL_ID,
        idFactory,
        "toolCallId",
      );
      const stableEffectKey = effectKey({
        tenantId,
        runId: run.runId,
        toolCallId,
        requestHash: command.requestHash,
      });
      const toolCall = {
        toolCallId,
        runId: run.runId,
        state: "PREPARED",
        version: 1,
        operationRef: command.operationRef,
        operationVersion: command.operationVersion,
        requestHash: command.requestHash,
        effectKey: stableEffectKey,
        compensationRef: command.compensationRef,
        authorization: trusted.authorization,
        receiptRef: null,
        receiptHash: null,
        outcome: null,
        createdAt: now,
        updatedAt: now,
      };
      await tx.insertToolCall(toolCall);
      const nextRun = {
        ...run,
        version: run.version + 1,
        updatedAt: now,
      };
      await tx.updateRun(nextRun, run.version);
      value = {
        commandKind: command.kind,
        runId: run.runId,
        runVersion: nextRun.version,
        toolCallId,
        toolCallVersion: 1,
        state: toolCall.state,
        effectKey: stableEffectKey,
        requestHash: toolCall.requestHash,
      };
      aggregateType = "TOOL_CALL";
      aggregateId = toolCallId;
      aggregateVersion = 1;
      eventData = {
        run_id: run.runId,
        run_version: nextRun.version,
        state: toolCall.state,
        operation_ref: toolCall.operationRef,
        operation_version: toolCall.operationVersion,
        request_hash: toolCall.requestHash,
        effect_key: toolCall.effectKey,
        compensation_ref: toolCall.compensationRef,
        authorization_decision_id:
          toolCall.authorization.decisionId,
        };
    } else if (command.kind === "RECORD_TOOL_CALL_RESULT") {
      const run = await tx.findRun(command.runId);
      const toolCall = await tx.findToolCall(command.toolCallId);
      if (
        !run ||
        run.state !== "RUNNING" ||
        !toolCall ||
        toolCall.runId !== run.runId ||
        toolCall.state !== "PREPARED"
      ) {
        fail("TOOL_CALL_INVALID", "ToolCall result is inconsistent.");
      }
      if (
        run.version !== command.expectedRunVersion ||
        toolCall.version !== command.expectedToolCallVersion
      ) {
        fail("STALE_VERSION", "Run or ToolCall version is stale.");
      }
      let verifiedReceipt;
      try {
        verifiedReceipt = await toolReceiptVerifier.resolve(
          Object.freeze({
            receiptId: command.receiptId,
            tenantId,
            runId: run.runId,
            toolCallId: toolCall.toolCallId,
            effectKey: toolCall.effectKey,
            requestHash: toolCall.requestHash,
            operationRef: toolCall.operationRef,
            operationVersion: toolCall.operationVersion,
          }),
        );
      } catch {
        fail(
          "TOOL_RECEIPT_UNVERIFIED",
          "C0 Mock Tool receipt could not be verified.",
        );
      }
      if (
        verifiedReceipt?.trustSource !==
          "VERIFIED_C0_MOCK_TOOL_RECEIPT" ||
        verifiedReceipt.receiptId !== command.receiptId ||
        verifiedReceipt.tenantId !== tenantId ||
        verifiedReceipt.runId !== run.runId ||
        verifiedReceipt.toolCallId !== toolCall.toolCallId ||
        verifiedReceipt.effectKey !== toolCall.effectKey ||
        verifiedReceipt.requestHash !== toolCall.requestHash ||
        verifiedReceipt.operationRef !== toolCall.operationRef ||
        verifiedReceipt.operationVersion !== toolCall.operationVersion ||
        !TERMINAL_TOOL_STATES.has(verifiedReceipt.outcome) ||
        typeof verifiedReceipt.receiptRef !== "string" ||
        !REFERENCE.test(verifiedReceipt.receiptRef) ||
        !SHA256.test(verifiedReceipt.receiptHash ?? "")
      ) {
        fail(
          "TOOL_RECEIPT_UNVERIFIED",
          "C0 Mock Tool receipt is inconsistent.",
        );
      }
      const nextToolCall = {
        ...toolCall,
        state: verifiedReceipt.outcome,
        version: toolCall.version + 1,
        receiptRef: verifiedReceipt.receiptRef,
        receiptHash: verifiedReceipt.receiptHash,
        outcome: verifiedReceipt.outcome,
        updatedAt: now,
      };
      const nextRun = {
        ...run,
        version: run.version + 1,
        updatedAt: now,
      };
      await tx.updateToolCall(nextToolCall, toolCall.version);
      await tx.updateRun(nextRun, run.version);
      value = {
        commandKind: command.kind,
        runId: run.runId,
        runVersion: nextRun.version,
        toolCallId: toolCall.toolCallId,
        toolCallVersion: nextToolCall.version,
        state: nextToolCall.state,
        receiptRef: nextToolCall.receiptRef,
        receiptHash: nextToolCall.receiptHash,
      };
      aggregateType = "TOOL_CALL";
      aggregateId = toolCall.toolCallId;
      aggregateVersion = nextToolCall.version;
      eventData = {
        run_id: run.runId,
        run_version: nextRun.version,
        state: nextToolCall.state,
        request_hash: nextToolCall.requestHash,
        receipt_ref: nextToolCall.receiptRef,
        receipt_hash: nextToolCall.receiptHash,
      };
    } else if (command.kind === "FINISH_RUN") {
      const run = await tx.findRun(command.runId);
      if (!run || run.state !== "RUNNING") {
        fail("RUN_NOT_RUNNING", "Only a running Run can finish.");
      }
      assertRunActionIdentity(run, trusted.identity);
      if (run.version !== command.expectedRunVersion) {
        fail("STALE_VERSION", "Run version is stale.");
      }
      const result = command.resultArtifact;
      const resultArtifact = await tx.findArtifact(
        result.artifactId,
        result.artifactVersion,
      );
      const toolCalls = await tx.listToolCallsByRun(run.runId);
      if (
        !resultArtifact ||
        resultArtifact.caseId !== run.caseId ||
        resultArtifact.threadId !== run.threadId ||
        resultArtifact.kind !== "RESULT" ||
        resultArtifact.contentSha256 !== result.contentSha256 ||
        toolCalls.some((toolCall) => !TERMINAL_TOOL_STATES.has(toolCall.state)) ||
        (command.outcome === "SUCCEEDED" &&
          (toolCalls.length < 1 ||
            toolCalls.some((toolCall) => toolCall.state !== "SUCCEEDED")))
      ) {
        fail(
          "RUN_NOT_RECONSTRUCTABLE",
          "Run is missing a frozen result or terminal Tool receipt.",
        );
      }
      const nextRun = {
        ...run,
        state: command.outcome,
        version: run.version + 1,
        resultArtifact: clone(result),
        reconstructionHash: null,
        updatedAt: now,
      };
      nextRun.reconstructionHash = sha256(
        reconstructionValue({
          run: nextRun,
          inputArtifact: await tx.findArtifact(
            run.baseManifest.inputArtifact.artifactId,
            run.baseManifest.inputArtifact.artifactVersion,
          ),
          resultArtifact,
          toolCalls,
        }),
      );
      await tx.updateRun(nextRun, run.version);
      value = {
        commandKind: command.kind,
        runId: run.runId,
        state: nextRun.state,
        version: nextRun.version,
        reconstructionHash: nextRun.reconstructionHash,
      };
      aggregateType = "RUN";
      aggregateId = run.runId;
      aggregateVersion = nextRun.version;
      eventData = {
        state: nextRun.state,
        result_artifact_id: resultArtifact.artifactId,
        result_artifact_version: resultArtifact.artifactVersion,
        result_sha256: resultArtifact.contentSha256,
        reconstruction_sha256: nextRun.reconstructionHash,
      };
    }

    const event = eventRecord({
      idFactory,
      now,
      tenantId,
      correlationId,
      commandKind: command.kind,
      aggregateType,
      aggregateId,
      aggregateVersion,
      data: eventData,
    });
    await tx.appendEvent(event);
    await tx.appendOutbox(event);
    return Object.freeze({ ...value, eventId: event.eventId });
  }

  async function execute(serverContext, request) {
    validateServerContext(serverContext);
    validateRequest(request);
    const command = Object.freeze(clone(request.command));
    verifyCommandReferences(referenceCatalog, serverContext.tenantId, command);
    const surface =
      command.kind === "PREPARE_TOOL_CALL" ? "TOOL_CALL" : "MANAGE";
    const trusted = await trustedInputs(
      serverContext,
      request,
      surface,
      authorizationResource(
        referenceCatalog,
        serverContext.tenantId,
        surface,
      ),
    );
    const now = canonicalInstant(clock(), "clock");
    const requestHash = sha256({
      tenantId: serverContext.tenantId,
      humanSubjectPrincipalId:
        trusted.identity.humanSubject.principalId,
      workloadActorPrincipalId:
        trusted.identity.workloadActor.principalId,
      delegationChain: trusted.identity.delegationChain,
      command,
    });
    let result;
    try {
      result = await store.runCommand(
        trusted.scope,
        Object.freeze({
          idempotencyKey: request.idempotencyKey,
          requestHash,
          commandKind: command.kind,
          correlationId: request.correlationId,
        }),
        async (tx) =>
          reduceCommand({
            tx,
            command,
            trusted,
            correlationId: request.correlationId,
            now,
          }),
      );
    } catch (error) {
      throw normalizeDependency(error, "STORE_UNAVAILABLE");
    }
    return Object.freeze({
      ...clone(result.value),
      duplicate: result.duplicate === true,
      verificationScope: "P1_SYNTHETIC_ONLY",
      productionVerificationStatus: "NOT_VERIFIED",
    });
  }

  async function recordToolCallResult(workerContext, request) {
    validateToolResultWorkerContext(workerContext);
    validateToolResultRequest(request);
    const command = Object.freeze(clone(request.command));
    const resourceId = authorizationResource(
      referenceCatalog,
      workerContext.tenantId,
      "MANAGE",
    );
    let control;
    try {
      control = await controlAuthorize(
        workerContext,
        "AIOS_STATE_RECORD_TOOL_RESULT",
        Object.freeze({
          tenantId: workerContext.tenantId,
          tenantKind: "SYNTHETIC",
          resourceId,
        }),
      );
    } catch {
      control = null;
    }
    if (
      control?.allowed !== true ||
      typeof control.decisionId !== "string" ||
      typeof control.evidenceRef !== "string" ||
      typeof control.policyVersion !== "string"
    ) {
      fail("ACCESS_DENIED", "C08 Tool result Worker was denied.");
    }
    let admission;
    try {
      admission = await tenantRegistry.admitNewRequest({
        tenantId: workerContext.tenantId,
        expectedTenantKind: "SYNTHETIC",
      });
    } catch (error) {
      throw normalizeDependency(error, "DEPENDENCY_UNAVAILABLE");
    }
    validateAdmission(admission, workerContext.tenantId);
    const trusted = Object.freeze({
      scope: Object.freeze({
        trustSource: "C07_VERIFIED_TENANT_SCOPE",
        tenantId: workerContext.tenantId,
        tenantKind: "SYNTHETIC",
        lifecycleVersion: admission.lifecycleVersion,
        operationId: "C08_RECORD_TOOL_CALL_RESULT",
        storagePath: "aios-state-core",
        correlationId: request.correlationId,
        decisionId: control.decisionId,
        evidenceRef: control.evidenceRef,
        policyVersion: control.policyVersion,
      }),
    });
    const now = canonicalInstant(clock(), "clock");
    const requestHash = sha256({
      tenantId: workerContext.tenantId,
      command,
    });
    let result;
    try {
      result = await store.runCommand(
        trusted.scope,
        Object.freeze({
          idempotencyKey: request.idempotencyKey,
          requestHash,
          commandKind: command.kind,
          correlationId: request.correlationId,
        }),
        async (tx) =>
          reduceCommand({
            tx,
            command,
            trusted,
            correlationId: request.correlationId,
            now,
          }),
      );
    } catch (error) {
      throw normalizeDependency(error, "STORE_UNAVAILABLE");
    }
    return Object.freeze({
      ...clone(result.value),
      duplicate: result.duplicate === true,
      verificationScope: "P1_SYNTHETIC_ONLY",
      productionVerificationStatus: "NOT_VERIFIED",
    });
  }

  async function reconstructRun(serverContext, query) {
    validateServerContext(serverContext);
    validateReconstructQuery(query);
    const trusted = await trustedInputs(
      serverContext,
      { ...query, command: { kind: "RECONSTRUCT_RUN" } },
      "READ",
      authorizationResource(
        referenceCatalog,
        serverContext.tenantId,
        "READ",
      ),
    );
    let stored;
    try {
      stored = await store.readRun(trusted.scope, { runId: query.runId });
    } catch (error) {
      throw normalizeDependency(error, "STORE_UNAVAILABLE");
    }
    if (
      !stored?.run ||
      !TERMINAL_RUN_STATES.has(stored.run.state) ||
      !stored.inputArtifact ||
      !stored.resultArtifact ||
      !Array.isArray(stored.toolCalls) ||
      (stored.run.state === "SUCCEEDED" &&
        stored.toolCalls.length < 1) ||
      stored.toolCalls.some(
        (toolCall) => !TERMINAL_TOOL_STATES.has(toolCall.state),
      ) ||
      !SHA256.test(stored.run.reconstructionHash ?? "")
    ) {
      fail("RUN_NOT_RECONSTRUCTABLE", "Run evidence is incomplete.");
    }
    const manifest = reconstructionValue(stored);
    const actualHash = sha256(manifest);
    if (actualHash !== stored.run.reconstructionHash) {
      fail("RECONSTRUCTION_MISMATCH", "Run evidence hash is inconsistent.");
    }
    return Object.freeze({
      runId: stored.run.runId,
      state: stored.run.state,
      version: stored.run.version,
      manifest,
      reconstructionHash: actualHash,
      verificationScope: "P1_SYNTHETIC_ONLY",
      productionVerificationStatus: "NOT_VERIFIED",
    });
  }

  async function inspectRun(serverContext, query) {
    validateServerContext(serverContext);
    validateReconstructQuery(query);
    const trusted = await trustedInputs(
      serverContext,
      { ...query, command: { kind: "INSPECT_RUN" } },
      "READ",
      authorizationResource(
        referenceCatalog,
        serverContext.tenantId,
        "READ",
      ),
    );
    let stored;
    try {
      stored = await store.readRun(trusted.scope, { runId: query.runId });
    } catch (error) {
      throw normalizeDependency(error, "STORE_UNAVAILABLE");
    }
    if (
      !stored?.run ||
      !stored.case ||
      stored.case.caseId !== stored.run.caseId ||
      stored.case.state !== "OPEN" ||
      !Number.isSafeInteger(stored.case.version) ||
      stored.case.version < 1 ||
      !stored.thread ||
      stored.thread.threadId !== stored.run.threadId ||
      stored.thread.caseId !== stored.run.caseId ||
      stored.thread.state !== "OPEN" ||
      !Number.isSafeInteger(stored.thread.version) ||
      stored.thread.version < 1 ||
      !RUN_STATES.has(stored.run.state) ||
      !Number.isSafeInteger(stored.run.version) ||
      stored.run.version < 1 ||
      !stored.inputArtifact ||
      stored.inputArtifact.artifactId !==
        stored.run.baseManifest?.inputArtifact?.artifactId ||
      stored.inputArtifact.artifactVersion !==
        stored.run.baseManifest?.inputArtifact?.artifactVersion ||
      stored.inputArtifact.contentSha256 !==
        stored.run.baseManifest?.inputArtifact?.contentSha256 ||
      !Array.isArray(stored.toolCalls) ||
      stored.toolCalls.some(
        (toolCall) =>
          !TOOL_STATES.has(toolCall.state) ||
          !Number.isSafeInteger(toolCall.version) ||
          toolCall.version < 1,
      )
    ) {
      fail("RUN_NOT_INSPECTABLE", "Run operational state is incomplete.");
    }

    let recoveryStatus = "IN_PROGRESS";
    if (TERMINAL_RUN_STATES.has(stored.run.state)) {
      if (
        !stored.resultArtifact ||
        (stored.run.state === "SUCCEEDED" &&
          stored.toolCalls.length < 1) ||
        stored.toolCalls.some(
          (toolCall) => !TERMINAL_TOOL_STATES.has(toolCall.state),
        ) ||
        !SHA256.test(stored.run.reconstructionHash ?? "") ||
        sha256(reconstructionValue(stored)) !==
          stored.run.reconstructionHash
      ) {
        fail("RUN_NOT_INSPECTABLE", "Terminal Run evidence is incomplete.");
      }
      recoveryStatus = "TERMINAL_VERIFIED";
    } else if (
      stored.resultArtifact !== null ||
      stored.run.resultArtifact !== null ||
      stored.run.reconstructionHash !== null
    ) {
      fail("RUN_NOT_INSPECTABLE", "Running Run contains terminal evidence.");
    }

    return Object.freeze({
      runId: stored.run.runId,
      state: stored.run.state,
      version: stored.run.version,
      recoveryStatus,
      snapshot: operationalRunValue(stored),
      verificationScope: "P1_SYNTHETIC_ONLY",
      productionVerificationStatus: "NOT_VERIFIED",
    });
  }

  async function snapshot(controlContext, query) {
    exactKeys(query, ["tenantId"], "snapshot query");
    validateSyntheticTenantId(query.tenantId);
    let control;
    try {
      control = await controlAuthorize(
        controlContext,
        "AIOS_STATE_READ",
        Object.freeze({
          tenantId: query.tenantId,
          tenantKind: "SYNTHETIC",
        }),
      );
    } catch {
      control = null;
    }
    if (
      control?.allowed !== true ||
      typeof control.decisionId !== "string" ||
      typeof control.evidenceRef !== "string" ||
      typeof control.policyVersion !== "string"
    ) {
      fail("ACCESS_DENIED", "C08 snapshot was denied.");
    }
    let admission;
    try {
      admission = await tenantRegistry.admitNewRequest({
        tenantId: query.tenantId,
        expectedTenantKind: "SYNTHETIC",
      });
    } catch (error) {
      throw normalizeDependency(error, "DEPENDENCY_UNAVAILABLE");
    }
    validateAdmission(admission, query.tenantId);
    const scope = Object.freeze({
      trustSource: "C07_VERIFIED_TENANT_SCOPE",
      tenantId: query.tenantId,
      tenantKind: "SYNTHETIC",
      lifecycleVersion: admission.lifecycleVersion,
      operationId: "C08_SNAPSHOT",
      storagePath: "aios-state-core",
      correlationId: "c08-control-snapshot",
      decisionId: control.decisionId,
      evidenceRef: control.evidenceRef,
      policyVersion: control.policyVersion,
    });
    let value;
    try {
      value = await store.readTenantSnapshot(scope);
    } catch (error) {
      throw normalizeDependency(error, "STORE_UNAVAILABLE");
    }
    return Object.freeze({
      tenantId: query.tenantId,
      tenantKind: "SYNTHETIC",
      counts: Object.freeze(clone(value.counts)),
      runStates: Object.freeze(clone(value.runStates)),
      toolCallStates: Object.freeze(clone(value.toolCallStates)),
      outboxStates: Object.freeze(clone(value.outboxStates)),
      verificationScope: "P1_SYNTHETIC_ONLY",
      productionVerificationStatus: "NOT_VERIFIED",
    });
  }

  return Object.freeze({
    execute,
    recordToolCallResult,
    inspectRun,
    reconstructRun,
    snapshot,
  });
}
