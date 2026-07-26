import { createHash } from "node:crypto";

const MANIFEST_FIELDS = Object.freeze([
  "schemaVersion",
  "name",
  "version",
  "description",
  "instructions",
  "allowedTools",
  "executionMode",
]);
const SKILL_NAME = /^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$/;
const SEMVER = /^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$/;
const TOOL_ID = /^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$/;

export class SkillRegistryError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "SkillRegistryError";
    this.code = code;
  }
}

function fail(code, message) {
  throw new SkillRegistryError(code, message);
}

function exactKeys(value, allowed, field) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    fail("INVALID_SKILL_MANIFEST", `${field} must be an object.`);
  }
  const keys = Object.keys(value);
  if (
    keys.length !== allowed.length ||
    keys.some((key) => !allowed.includes(key))
  ) {
    fail(
      "INVALID_SKILL_MANIFEST",
      `${field} must contain only the closed P1 field set.`,
    );
  }
}

function boundedString(value, field, maximum) {
  if (
    typeof value !== "string" ||
    !value.trim() ||
    value.length > maximum ||
    value.includes("\u0000")
  ) {
    fail("INVALID_SKILL_MANIFEST", `${field} is invalid.`);
  }
}

function deepFreeze(value) {
  if (value && typeof value === "object" && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const item of Object.values(value)) deepFreeze(item);
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
      fail("INVALID_SKILL_MANIFEST", "Only finite JSON numbers are supported.");
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
  fail("INVALID_SKILL_MANIFEST", "Only JSON values are supported.");
}

export function validateSkillManifest(value) {
  exactKeys(value, MANIFEST_FIELDS, "Skill Manifest");
  if (value.executionMode !== "INSTRUCTIONS_ONLY") {
    fail(
      "SCRIPT_EXECUTION_DISABLED",
      "P1 Skill executionMode must be INSTRUCTIONS_ONLY.",
    );
  }
  if (value.schemaVersion !== "1.0.0") {
    fail("INVALID_SKILL_MANIFEST", "schemaVersion is unsupported.");
  }
  boundedString(value.name, "name", 64);
  if (!SKILL_NAME.test(value.name)) {
    fail("INVALID_SKILL_MANIFEST", "name must be a lowercase kebab identifier.");
  }
  boundedString(value.version, "version", 32);
  if (!SEMVER.test(value.version)) {
    fail("INVALID_SKILL_MANIFEST", "version must be strict SemVer core syntax.");
  }
  boundedString(value.description, "description", 256);
  boundedString(value.instructions, "instructions", 16_384);
  if (
    !Array.isArray(value.allowedTools) ||
    value.allowedTools.length > 32 ||
    value.allowedTools.some(
      (tool) =>
        typeof tool !== "string" ||
        tool.length > 128 ||
        !TOOL_ID.test(tool),
    ) ||
    new Set(value.allowedTools).size !== value.allowedTools.length
  ) {
    fail(
      "INVALID_SKILL_MANIFEST",
      "allowedTools must contain unique advisory operation identifiers.",
    );
  }
  return deepFreeze(structuredClone(value));
}

export function canonicalSkillManifestSha256(value) {
  const manifest = validateSkillManifest(value);
  return `sha256:${createHash("sha256")
    .update(canonicalize(manifest))
    .digest("hex")}`;
}

const UUID_V7 =
  "[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}";
const SYNTHETIC_TENANT_ID = new RegExp(`^stn_${UUID_V7}$`);
const PRINCIPAL_ID = new RegExp(`^prn_${UUID_V7}$`);
const DELEGATION_ID = new RegExp(`^dlg_${UUID_V7}$`);
const SKILL_ID = new RegExp(`^skl_${UUID_V7}$`);
const RELEASE_ID = new RegExp(`^srl_${UUID_V7}$`);
const EVENT_ID = new RegExp(`^evt_${UUID_V7}$`);
const SHA256 = /^sha256:[a-f0-9]{64}$/;
const REFERENCE =
  /^(?:evidence|fixture|policy|profile|synthetic|test):\/\/\S+$/;
const REQUEST_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const RESOURCE_ID = /^[a-z][a-z0-9_-]{0,127}$/;
const CHANNELS = new Set(["PILOT", "STABLE"]);
const F04_CASE_IDS = Object.freeze(
  Array.from({ length: 10 }, (_, index) =>
    `F04-E${String(index + 1).padStart(3, "0")}`,
  ),
);
const F04_ZERO_TOLERANCE_CASE_IDS = new Set(F04_CASE_IDS.slice(2));
const AUTHORIZATION_BY_COMMAND = Object.freeze({
  SUBMIT_RELEASE: Object.freeze({
    operationId: "C13_SUBMIT_RELEASE",
    resourceField: "submitResourceId",
  }),
  RUN_STATIC_CHECK: Object.freeze({
    operationId: "C13_RUN_STATIC_CHECK",
    resourceField: "staticCheckResourceId",
  }),
  RUN_SYNTHETIC_EVALUATION: Object.freeze({
    operationId: "C13_RUN_SYNTHETIC_EVALUATION",
    resourceField: "evaluateResourceId",
  }),
  APPROVE_RELEASE: Object.freeze({
    operationId: "C13_APPROVE_RELEASE",
    resourceField: "approveResourceId",
  }),
  PUBLISH_RELEASE: Object.freeze({
    operationId: "C13_PUBLISH_RELEASE",
    resourceField: "publishResourceId",
  }),
  WITHDRAW_RELEASE: Object.freeze({
    operationId: "C13_WITHDRAW_RELEASE",
    resourceField: "withdrawResourceId",
  }),
  ROLLBACK_CHANNEL: Object.freeze({
    operationId: "C13_ROLLBACK_CHANNEL",
    resourceField: "rollbackResourceId",
  }),
});
const RESOLVE_AUTHORIZATION = Object.freeze({
  operationId: "C13_RESOLVE_FOR_RUN",
  resourceField: "resolveResourceId",
});
const AUTHORIZATION_OPERATION_IDS = new Set([
  ...Object.values(AUTHORIZATION_BY_COMMAND).map(
    ({ operationId }) => operationId,
  ),
  RESOLVE_AUTHORIZATION.operationId,
  "C13_READ_TENANT_SNAPSHOT",
]);
const PUBLIC_STORE_CODES = new Set([
  "ID_COLLISION",
  "IDEMPOTENCY_CONFLICT",
  "INTEGRITY_VIOLATION",
  "RELEASE_NOT_FOUND",
  "STORE_UNAVAILABLE",
  "TENANT_SCOPE_VIOLATION",
  "VERSION_CONFLICT",
]);
const COMMAND_FIELDS = Object.freeze({
  SUBMIT_RELEASE: Object.freeze([
    "kind",
    "skillId",
    "expectedLatestSequence",
    "manifest",
    "contentSha256",
    "sourceReviewRef",
    "sourceReviewSha256",
  ]),
  RUN_STATIC_CHECK: Object.freeze([
    "kind",
    "releaseId",
    "expectedReleaseVersion",
  ]),
  RUN_SYNTHETIC_EVALUATION: Object.freeze([
    "kind",
    "releaseId",
    "expectedReleaseVersion",
    "suiteId",
    "suiteSha256",
  ]),
  APPROVE_RELEASE: Object.freeze([
    "kind",
    "releaseId",
    "expectedReleaseVersion",
    "approvedContentSha256",
    "approvedEvaluationReportRef",
    "approvedEvaluationReportSha256",
    "approvedHumanBaselineDecisionRef",
    "approvedHumanBaselineDecisionSha256",
  ]),
  PUBLISH_RELEASE: Object.freeze([
    "kind",
    "releaseId",
    "expectedReleaseVersion",
    "channel",
    "expectedChannelGeneration",
    "expectedCurrentReleaseId",
  ]),
  WITHDRAW_RELEASE: Object.freeze([
    "kind",
    "releaseId",
    "expectedReleaseVersion",
    "reasonRef",
  ]),
  ROLLBACK_CHANNEL: Object.freeze([
    "kind",
    "skillId",
    "channel",
    "targetReleaseId",
    "expectedChannelGeneration",
    "expectedCurrentReleaseId",
    "reasonRef",
  ]),
});

function sha256Json(value) {
  return `sha256:${createHash("sha256")
    .update(canonicalize(value))
    .digest("hex")}`;
}

function identifier(value, expression, field) {
  if (typeof value !== "string" || !expression.test(value)) {
    fail("INVALID_INPUT", `${field} is invalid.`);
  }
}

function reference(value, field) {
  if (
    typeof value !== "string" ||
    value.length > 512 ||
    !REFERENCE.test(value)
  ) {
    fail("P3_REQUIRED", `${field} must be a P1 Synthetic reference.`);
  }
}

function positiveInteger(value, field, { allowZero = false } = {}) {
  const minimum = allowZero ? 0 : 1;
  if (!Number.isSafeInteger(value) || value < minimum) {
    fail("INVALID_INPUT", `${field} is invalid.`);
  }
}

function sha256Reference(value, field) {
  if (!SHA256.test(value ?? "")) {
    fail("INVALID_INPUT", `${field} must be a SHA-256 reference.`);
  }
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
    fail("P3_REQUIRED", "C13 accepts only Synthetic Tenant IDs before P3.");
  }
}

function validateServerContext(context) {
  const fields = [
    "synthetic",
    "routeTrustSource",
    "tenantId",
    "workloadTrustSource",
    "workloadActorPrincipalId",
  ];
  if (
    !context ||
    typeof context !== "object" ||
    Array.isArray(context) ||
    Object.keys(context).length !== fields.length ||
    Object.keys(context).some((key) => !fields.includes(key)) ||
    context.synthetic !== true ||
    context.routeTrustSource !== "VERIFIED_ROUTE_DESCRIPTOR" ||
    context.workloadTrustSource !== "VERIFIED_WORKLOAD_CONTEXT"
  ) {
    fail("UNTRUSTED_ROUTE", "C13 route or workload context is untrusted.");
  }
  validateSyntheticTenantId(context.tenantId);
  identifier(
    context.workloadActorPrincipalId,
    PRINCIPAL_ID,
    "workloadActorPrincipalId",
  );
}

function validateCommand(command) {
  if (!command || typeof command !== "object" || Array.isArray(command)) {
    fail("INVALID_INPUT", "command must be an object.");
  }
  const fields = COMMAND_FIELDS[command.kind];
  if (!fields) fail("UNKNOWN_COMMAND", "C13 command is not registered.");
  if (
    Object.keys(command).length !== fields.length ||
    Object.keys(command).some((key) => !fields.includes(key))
  ) {
    fail("INVALID_INPUT", "command has an invalid field set.");
  }
  if (command.kind === "SUBMIT_RELEASE") {
    if (command.skillId !== null) {
      identifier(command.skillId, SKILL_ID, "skillId");
    }
    positiveInteger(
      command.expectedLatestSequence,
      "expectedLatestSequence",
      { allowZero: true },
    );
    if (
      (command.skillId === null &&
        command.expectedLatestSequence !== 0) ||
      (command.skillId !== null &&
        command.expectedLatestSequence < 1)
    ) {
      fail("INVALID_INPUT", "Skill sequence does not match create/update mode.");
    }
    validateSkillManifest(command.manifest);
    sha256Reference(command.contentSha256, "contentSha256");
    reference(command.sourceReviewRef, "sourceReviewRef");
    sha256Reference(command.sourceReviewSha256, "sourceReviewSha256");
  } else if (command.kind === "ROLLBACK_CHANNEL") {
    identifier(command.skillId, SKILL_ID, "skillId");
    identifier(command.targetReleaseId, RELEASE_ID, "targetReleaseId");
    validateChannelCas(command);
    reference(command.reasonRef, "reasonRef");
  } else {
    identifier(command.releaseId, RELEASE_ID, "releaseId");
    positiveInteger(
      command.expectedReleaseVersion,
      "expectedReleaseVersion",
    );
    if (command.kind === "RUN_SYNTHETIC_EVALUATION") {
      if (command.suiteId !== "f04-frozen-evaluation-suite-v1") {
        fail("EVALUATION_SUITE_MISMATCH", "C13 requires the frozen F04 suite.");
      }
      sha256Reference(command.suiteSha256, "suiteSha256");
    } else if (command.kind === "APPROVE_RELEASE") {
      sha256Reference(
        command.approvedContentSha256,
        "approvedContentSha256",
      );
      reference(
        command.approvedEvaluationReportRef,
        "approvedEvaluationReportRef",
      );
      sha256Reference(
        command.approvedEvaluationReportSha256,
        "approvedEvaluationReportSha256",
      );
      reference(
        command.approvedHumanBaselineDecisionRef,
        "approvedHumanBaselineDecisionRef",
      );
      sha256Reference(
        command.approvedHumanBaselineDecisionSha256,
        "approvedHumanBaselineDecisionSha256",
      );
    } else if (command.kind === "PUBLISH_RELEASE") {
      validateChannelCas(command);
    } else if (command.kind === "WITHDRAW_RELEASE") {
      reference(command.reasonRef, "reasonRef");
    }
  }
}

function validateChannelCas(command) {
  if (!CHANNELS.has(command.channel)) {
    fail("INVALID_INPUT", "channel is invalid.");
  }
  positiveInteger(
    command.expectedChannelGeneration,
    "expectedChannelGeneration",
    { allowZero: true },
  );
  if (command.expectedCurrentReleaseId !== null) {
    identifier(
      command.expectedCurrentReleaseId,
      RELEASE_ID,
      "expectedCurrentReleaseId",
    );
  }
  if (
    (command.expectedChannelGeneration === 0) !==
    (command.expectedCurrentReleaseId === null)
  ) {
    fail("INVALID_INPUT", "Channel generation and current release disagree.");
  }
}

function validateRequest(request) {
  const fields = [
    "sessionToken",
    "delegationId",
    "idempotencyKey",
    "correlationId",
    "command",
  ];
  if (
    !request ||
    typeof request !== "object" ||
    Array.isArray(request) ||
    Object.keys(request).length !== fields.length ||
    Object.keys(request).some((key) => !fields.includes(key)) ||
    typeof request.sessionToken !== "string" ||
    !request.sessionToken ||
    !REQUEST_ID.test(request.idempotencyKey ?? "") ||
    !REQUEST_ID.test(request.correlationId ?? "")
  ) {
    fail("INVALID_INPUT", "C13 request metadata is invalid.");
  }
  identifier(request.delegationId, DELEGATION_ID, "delegationId");
  validateCommand(request.command);
}

function validateResolveQuery(query) {
  const fields = [
    "sessionToken",
    "delegationId",
    "correlationId",
    "skillId",
    "version",
    "contentSha256",
    "channel",
  ];
  if (
    !query ||
    typeof query !== "object" ||
    Array.isArray(query) ||
    Object.keys(query).length !== fields.length ||
    Object.keys(query).some((key) => !fields.includes(key)) ||
    typeof query.sessionToken !== "string" ||
    !query.sessionToken ||
    !REQUEST_ID.test(query.correlationId ?? "")
  ) {
    fail("INVALID_INPUT", "C13 resolution query is invalid.");
  }
  identifier(query.delegationId, DELEGATION_ID, "delegationId");
  identifier(query.skillId, SKILL_ID, "skillId");
  if (!SEMVER.test(query.version ?? "")) {
    fail("INVALID_INPUT", "version is invalid.");
  }
  sha256Reference(query.contentSha256, "contentSha256");
  if (!CHANNELS.has(query.channel)) {
    fail("INVALID_INPUT", "channel is invalid.");
  }
}

function validateScope(scope) {
  if (
    scope?.trustSource !== "C07_VERIFIED_TENANT_SCOPE" ||
    scope?.tenantKind !== "SYNTHETIC" ||
    !SYNTHETIC_TENANT_ID.test(scope?.tenantId ?? "") ||
    !Number.isSafeInteger(scope?.lifecycleVersion) ||
    scope.lifecycleVersion < 1 ||
    typeof scope?.correlationId !== "string" ||
    !scope.correlationId ||
    typeof scope?.decisionId !== "string" ||
    !scope.decisionId ||
    typeof scope?.evidenceRef !== "string" ||
    !scope.evidenceRef ||
    typeof scope?.policyVersion !== "string" ||
    !scope.policyVersion ||
    !AUTHORIZATION_OPERATION_IDS.has(scope?.operationId) ||
    scope?.storagePath !== "skill-registry"
  ) {
    fail("TENANT_SCOPE_VIOLATION", "C13 requires a C07 verified scope.");
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
    !Number.isSafeInteger(identity?.humanSubject?.securityEpoch) ||
    identity.humanSubject.securityEpoch < 1 ||
    !Number.isSafeInteger(identity?.workloadActor?.securityEpoch) ||
    identity.workloadActor.securityEpoch < 1 ||
    !Array.isArray(identity?.delegationChain) ||
    identity.delegationChain.length < 1 ||
    !DELEGATION_ID.test(
      identity.delegationChain.at(-1)?.delegationId ?? "",
    ) ||
    typeof identity?.purposeRef !== "string" ||
    !identity.purposeRef
  ) {
    fail("ACTION_IDENTITY_INVALID", "C05 action identity is inconsistent.");
  }
}

function validateAuthorization(
  decision,
  identity,
  serverContext,
  surface,
  resourceId,
  operationId,
) {
  if (
    decision?.trustSource !== "C06_BOUND_DECISION_EVIDENCE" ||
    decision?.tenantId !== serverContext.tenantId ||
    decision?.surface !== surface ||
    decision?.resourceId !== resourceId ||
    decision?.operationId !== operationId ||
    decision?.humanPrincipalId !== identity.humanSubject.principalId ||
    decision?.humanSecurityEpoch !== identity.humanSubject.securityEpoch ||
    decision?.workloadActorPrincipalId !==
      identity.workloadActor.principalId ||
    decision?.workloadActorSecurityEpoch !==
      identity.workloadActor.securityEpoch ||
    decision?.leafDelegationId !==
      identity.delegationChain.at(-1).delegationId ||
    decision?.delegationChainSha256 !==
      sha256Json(identity.delegationChain) ||
    decision?.purposeRef !== identity.purposeRef ||
    typeof decision?.decisionId !== "string" ||
    !decision.decisionId ||
    typeof decision?.evidenceRef !== "string" ||
    !decision.evidenceRef ||
    typeof decision?.policyVersion !== "string" ||
    !decision.policyVersion
  ) {
    fail(
      "AUTHORIZATION_BINDING_MISMATCH",
      "C06 decision is not bound to the C05 action identity.",
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

function normalizeDependency(error, fallback) {
  if (error instanceof SkillRegistryError) return error;
  if (
    error?.name === "SkillRegistryStoreError" &&
    PUBLIC_STORE_CODES.has(error.code)
  ) {
    return new SkillRegistryError(
      error.code,
      "C13 storage rejected the operation.",
    );
  }
  if (
    ["TENANT_NOT_ACTIVE", "TENANT_DELETED", "TENANT_NOT_FOUND"].includes(
      error?.code,
    )
  ) {
    return new SkillRegistryError(
      "TENANT_NOT_ACTIVE",
      "Synthetic Tenant is not accepting C13 requests.",
    );
  }
  return new SkillRegistryError(fallback, "C13 dependency failed closed.");
}

function emptyTenantState() {
  return {
    releases: new Map(),
    versionIndex: new Map(),
    latestSequence: new Map(),
    channels: new Map(),
    events: new Map(),
    receipts: new Map(),
  };
}

function channelKey(skillId, channel) {
  return `${skillId}\u0000${channel}`;
}

function versionKey(skillId, version) {
  return `${skillId}\u0000${version}`;
}

function memoryTransaction(state) {
  return Object.freeze({
    async findRelease(releaseId) {
      return structuredClone(state.releases.get(releaseId) ?? null);
    },
    async findReleaseByVersion(skillId, version) {
      const releaseId = state.versionIndex.get(versionKey(skillId, version));
      return structuredClone(
        releaseId ? state.releases.get(releaseId) : null,
      );
    },
    async findLatestSequence(skillId) {
      return state.latestSequence.get(skillId) ?? 0;
    },
    async insertRelease(value) {
      if (
        state.releases.has(value.releaseId) ||
        state.versionIndex.has(versionKey(value.skillId, value.version)) ||
        (state.latestSequence.get(value.skillId) ?? 0) + 1 !== value.sequence
      ) {
        fail("VERSION_CONFLICT", "Skill Release creation conflicts.");
      }
      state.releases.set(value.releaseId, structuredClone(value));
      state.versionIndex.set(
        versionKey(value.skillId, value.version),
        value.releaseId,
      );
      state.latestSequence.set(value.skillId, value.sequence);
    },
    async updateRelease(value, expectedVersion) {
      const current = state.releases.get(value.releaseId);
      if (
        !current ||
        current.stateVersion !== expectedVersion ||
        value.stateVersion !== expectedVersion + 1
      ) {
        fail("VERSION_CONFLICT", "Skill Release state version is stale.");
      }
      if (
        current.skillId !== value.skillId ||
        current.version !== value.version ||
        current.contentSha256 !== value.contentSha256 ||
        sha256Json(current.manifest) !== sha256Json(value.manifest) ||
        (current.staticReport !== null &&
          sha256Json(current.staticReport) !==
            sha256Json(value.staticReport)) ||
        (current.evaluationSuiteId !== null &&
          (current.evaluationSuiteId !== value.evaluationSuiteId ||
            current.evaluationSuiteSha256 !==
              value.evaluationSuiteSha256)) ||
        (current.evaluationReport !== null &&
          sha256Json(current.evaluationReport) !==
            sha256Json(value.evaluationReport))
      ) {
        fail("INTEGRITY_VIOLATION", "Immutable Skill content changed.");
      }
      state.releases.set(value.releaseId, structuredClone(value));
    },
    async findChannel(skillId, channel) {
      return structuredClone(
        state.channels.get(channelKey(skillId, channel)) ?? null,
      );
    },
    async putChannel(value, expectedGeneration) {
      const key = channelKey(value.skillId, value.channel);
      const current = state.channels.get(key);
      if (
        (current?.generation ?? 0) !== expectedGeneration ||
        value.generation !== expectedGeneration + 1
      ) {
        fail("VERSION_CONFLICT", "Skill channel generation is stale.");
      }
      state.channels.set(key, structuredClone(value));
    },
    async appendEvent(value) {
      if (state.events.has(value.eventId)) {
        fail("ID_COLLISION", "Skill event already exists.");
      }
      state.events.set(value.eventId, structuredClone(value));
    },
  });
}

export function createMemorySkillRegistryStore() {
  const tenants = new Map();
  const locks = new Map();

  async function withTenantLock(tenantId, operation) {
    const previous = locks.get(tenantId) ?? Promise.resolve();
    let release;
    const current = new Promise((resolve) => {
      release = resolve;
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
    if (
      !REQUEST_ID.test(metadata?.idempotencyKey ?? "") ||
      !SHA256.test(metadata?.requestHash ?? "") ||
      !COMMAND_FIELDS[metadata?.commandKind] ||
      !REQUEST_ID.test(metadata?.correlationId ?? "") ||
      typeof reducer !== "function"
    ) {
      fail("INVALID_INPUT", "C13 command metadata is invalid.");
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
        return Object.freeze({
          duplicate: true,
          value: structuredClone(receipt.value),
        });
      }
      const draft = structuredClone(current);
      const value = await reducer(memoryTransaction(draft));
      const newEvents = [...draft.events.keys()].filter(
        (eventId) => !current.events.has(eventId),
      );
      if (
        !value ||
        typeof value !== "object" ||
        Array.isArray(value) ||
        newEvents.length !== 1
      ) {
        fail(
          "INTEGRITY_VIOLATION",
          "C13 command requires exactly one append-only event.",
        );
      }
      draft.receipts.set(metadata.idempotencyKey, {
        requestHash: metadata.requestHash,
        commandKind: metadata.commandKind,
        value: structuredClone(value),
      });
      tenants.set(scope.tenantId, draft);
      return Object.freeze({
        duplicate: false,
        value: structuredClone(value),
      });
    });
  }

  async function readResolution(scope, query) {
    validateScope(scope);
    const state = tenants.get(scope.tenantId) ?? emptyTenantState();
    const releaseId = state.versionIndex.get(
      versionKey(query.skillId, query.version),
    );
    return Object.freeze({
      channel: structuredClone(
        state.channels.get(channelKey(query.skillId, query.channel)) ?? null,
      ),
      release: structuredClone(
        releaseId ? state.releases.get(releaseId) : null,
      ),
    });
  }

  async function readRelease(scope, releaseId) {
    validateScope(scope);
    const state = tenants.get(scope.tenantId) ?? emptyTenantState();
    return structuredClone(state.releases.get(releaseId) ?? null);
  }

  async function readTenantSnapshot(scope) {
    validateScope(scope);
    const state = tenants.get(scope.tenantId) ?? emptyTenantState();
    return Object.freeze({
      tenantId: scope.tenantId,
      counts: Object.freeze({
        releases: state.releases.size,
        channels: state.channels.size,
        events: state.events.size,
        receipts: state.receipts.size,
      }),
    });
  }

  return Object.freeze({
    readRelease,
    readResolution,
    readTenantSnapshot,
    runCommand,
  });
}

function releaseResult(release) {
  return {
    skillId: release.skillId,
    releaseId: release.releaseId,
    sequence: release.sequence,
    version: release.version,
    contentSha256: release.contentSha256,
    lifecycleState: release.lifecycleState,
    releaseVersion: release.stateVersion,
  };
}

export function createSkillRegistry({
  tenantRegistry,
  stablePrincipalRegistry,
  authorizer,
  store,
  catalog,
  idFactory = uuidV7,
  clock = () => new Date().toISOString(),
}) {
  if (
    typeof tenantRegistry?.admitNewRequest !== "function" ||
    typeof stablePrincipalRegistry?.resolveActionIdentity !== "function" ||
    typeof authorizer?.enforce !== "function" ||
    typeof store?.runCommand !== "function" ||
    typeof store?.readResolution !== "function" ||
    typeof catalog?.authorizationResources !== "function" ||
    typeof catalog?.verifySource !== "function" ||
    typeof catalog?.evaluate !== "function" ||
    typeof idFactory !== "function" ||
    typeof clock !== "function"
  ) {
    fail("INVALID_CONFIGURATION", "C13 dependencies are incomplete.");
  }

  async function trustedInputs(
    serverContext,
    request,
    surface,
    resourceId,
    operationId,
  ) {
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
      return deepFreeze(structuredClone(value));
    };

    const firstIdentity = await resolveIdentity();
    let decision;
    try {
      decision = await authorizer.enforce(
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
          path: "skill-registry",
          mode: surface === "READ" ? "READ" : "WRITE",
        }),
      );
    } catch (error) {
      throw normalizeDependency(
        error,
        error?.code === "AUTHORIZATION_UNAVAILABLE"
          ? "AUTHORIZATION_UNAVAILABLE"
          : "ACCESS_DENIED",
      );
    }
    validateAuthorization(
      decision,
      firstIdentity,
      serverContext,
      surface,
      resourceId,
      operationId,
    );
    const finalIdentity = await resolveIdentity();
    if (sha256Json(firstIdentity) !== sha256Json(finalIdentity)) {
      fail(
        "ACTION_IDENTITY_CHANGED",
        "C05 action identity changed during authorization.",
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
      authorization: deepFreeze(structuredClone(decision)),
      scope: Object.freeze({
        trustSource: "C07_VERIFIED_TENANT_SCOPE",
        tenantId: serverContext.tenantId,
        tenantKind: "SYNTHETIC",
        lifecycleVersion: admission.lifecycleVersion,
        operationId,
        storagePath: "skill-registry",
        correlationId: request.correlationId,
        decisionId: decision.decisionId,
        evidenceRef: decision.evidenceRef,
        policyVersion: decision.policyVersion,
      }),
    });
  }

  async function reduceCommand(tx, command, trusted, now) {
    let result;
    let aggregateId;
    let aggregateVersion;

    if (command.kind === "SUBMIT_RELEASE") {
      const manifest = validateSkillManifest(command.manifest);
      const digest = canonicalSkillManifestSha256(manifest);
      if (digest !== command.contentSha256) {
        fail("SKILL_HASH_MISMATCH", "Submitted Skill hash is not canonical.");
      }
      try {
        await catalog.verifySource({
          tenantId: trusted.scope.tenantId,
          manifest,
          contentSha256: digest,
          sourceReviewRef: command.sourceReviewRef,
          sourceReviewSha256: command.sourceReviewSha256,
        });
      } catch (error) {
        throw normalizeDependency(error, "SYNTHETIC_SOURCE_UNVERIFIED");
      }
      const skillId =
        command.skillId ??
        generatedId("skl_", SKILL_ID, idFactory, "skillId");
      const latestSequence = await tx.findLatestSequence(skillId);
      if (latestSequence !== command.expectedLatestSequence) {
        fail("VERSION_CONFLICT", "Skill sequence is stale.");
      }
      if (await tx.findReleaseByVersion(skillId, manifest.version)) {
        fail("VERSION_CONFLICT", "Skill semantic version already exists.");
      }
      const releaseId = generatedId(
        "srl_",
        RELEASE_ID,
        idFactory,
        "releaseId",
      );
      const release = {
        tenantId: trusted.scope.tenantId,
        tenantKind: "SYNTHETIC",
        skillId,
        releaseId,
        sequence: latestSequence + 1,
        name: manifest.name,
        version: manifest.version,
        manifest,
        contentSha256: digest,
        sourceReviewRef: command.sourceReviewRef,
        sourceReviewSha256: command.sourceReviewSha256,
        lifecycleState: "SUBMITTED",
        stateVersion: 1,
        staticReport: null,
        evaluationSuiteId: null,
        evaluationSuiteSha256: null,
        evaluationReport: null,
        pilotPublished: false,
        stablePublished: false,
        withdrawnAt: null,
        withdrawalReasonRef: null,
        identity: trusted.identity,
        authorization: trusted.authorization,
        tenantLifecycleVersion: trusted.scope.lifecycleVersion,
        createdAt: now,
        updatedAt: now,
      };
      await tx.insertRelease(release);
      result = releaseResult(release);
      aggregateId = releaseId;
      aggregateVersion = 1;
    } else if (command.kind === "ROLLBACK_CHANNEL") {
      const target = await tx.findRelease(command.targetReleaseId);
      if (!target || target.skillId !== command.skillId) {
        fail("RELEASE_NOT_FOUND", "Rollback target was not found.");
      }
      if (
        target.lifecycleState !== "APPROVED" ||
        target.withdrawnAt !== null ||
        (command.channel === "PILOT" && !target.pilotPublished) ||
        (command.channel === "STABLE" && !target.stablePublished)
      ) {
        fail(
          "ROLLBACK_TARGET_INVALID",
          "Rollback target was not previously published and eligible.",
        );
      }
      const current = await tx.findChannel(command.skillId, command.channel);
      assertChannelCas(current, command);
      if (current.releaseId === target.releaseId) {
        fail("VERSION_CONFLICT", "Rollback target is already current.");
      }
      const channel = {
        tenantId: trusted.scope.tenantId,
        tenantKind: "SYNTHETIC",
        skillId: command.skillId,
        channel: command.channel,
        releaseId: target.releaseId,
        generation: current.generation + 1,
        reasonRef: command.reasonRef,
        updatedAt: now,
      };
      await tx.putChannel(channel, current.generation);
      result = {
        ...releaseResult(target),
        channel: command.channel,
        channelGeneration: channel.generation,
      };
      aggregateId = `${command.skillId}:${command.channel}`;
      aggregateVersion = channel.generation;
    } else {
      const current = await tx.findRelease(command.releaseId);
      if (!current) {
        fail("RELEASE_NOT_FOUND", "Skill Release was not found.");
      }
      if (current.stateVersion !== command.expectedReleaseVersion) {
        fail("VERSION_CONFLICT", "Skill Release state version is stale.");
      }
      const release = structuredClone(current);

      if (command.kind === "RUN_STATIC_CHECK") {
        if (release.lifecycleState !== "SUBMITTED") {
          fail("INVALID_TRANSITION", "Static check requires SUBMITTED.");
        }
        release.lifecycleState = "STATIC_PASSED";
        release.staticReport = {
          status: "PASS",
          closedManifestSchema: true,
          instructionsOnly: true,
          allowedToolsAreAdvisory: true,
          scriptsEnabled: false,
        };
      } else if (command.kind === "RUN_SYNTHETIC_EVALUATION") {
        if (release.lifecycleState !== "STATIC_PASSED") {
          fail(
            "INVALID_TRANSITION",
            "Synthetic evaluation requires STATIC_PASSED.",
          );
        }
        let report;
        try {
          report = await catalog.evaluate({
            tenantId: trusted.scope.tenantId,
            name: release.name,
            version: release.version,
            contentSha256: release.contentSha256,
            suiteId: command.suiteId,
            suiteSha256: command.suiteSha256,
          });
        } catch (error) {
          throw normalizeDependency(error, "EVALUATION_UNAVAILABLE");
        }
        validateEvaluationReport(report, {
          tenantId: trusted.scope.tenantId,
          skillName: release.name,
          skillVersion: release.version,
          releaseDigest: release.contentSha256,
          suiteId: command.suiteId,
          suiteSha256: command.suiteSha256,
        });
        release.evaluationSuiteId = command.suiteId;
        release.evaluationSuiteSha256 = command.suiteSha256;
        release.evaluationReport = structuredClone(report);
        release.lifecycleState =
          report.status === "PASS" ? "EVALUATED" : "EVALUATION_FAILED";
      } else if (command.kind === "APPROVE_RELEASE") {
        if (
          release.lifecycleState !== "EVALUATED" ||
          release.evaluationReport?.status !== "PASS"
        ) {
          fail("INVALID_TRANSITION", "Approval requires a passing evaluation.");
        }
        if (release.contentSha256 !== command.approvedContentSha256) {
          fail("SKILL_HASH_MISMATCH", "Approval hash does not match content.");
        }
        if (
          release.evaluationReport.reportRef !==
            command.approvedEvaluationReportRef ||
          release.evaluationReport.reportSha256 !==
            command.approvedEvaluationReportSha256 ||
          release.evaluationReport.humanBaselineDecisionRef !==
            command.approvedHumanBaselineDecisionRef ||
          release.evaluationReport.humanBaselineDecisionSha256 !==
            command.approvedHumanBaselineDecisionSha256
        ) {
          fail(
            "EVALUATION_REPORT_MISMATCH",
            "Approval evidence does not match the evaluated release.",
          );
        }
        release.lifecycleState = "APPROVED";
      } else if (command.kind === "PUBLISH_RELEASE") {
        if (
          release.lifecycleState !== "APPROVED" ||
          release.withdrawnAt !== null
        ) {
          fail("SKILL_NOT_APPROVED", "Only an eligible approved release publishes.");
        }
        if (command.channel === "STABLE" && !release.pilotPublished) {
          fail("PILOT_REQUIRED", "Stable publication requires prior pilot.");
        }
        const currentChannel = await tx.findChannel(
          release.skillId,
          command.channel,
        );
        assertChannelCas(currentChannel, command);
        const channel = {
          tenantId: trusted.scope.tenantId,
          tenantKind: "SYNTHETIC",
          skillId: release.skillId,
          channel: command.channel,
          releaseId: release.releaseId,
          generation: command.expectedChannelGeneration + 1,
          reasonRef: null,
          updatedAt: now,
        };
        await tx.putChannel(channel, command.expectedChannelGeneration);
        if (command.channel === "PILOT") release.pilotPublished = true;
        if (command.channel === "STABLE") release.stablePublished = true;
        result = {
          ...releaseResult({
            ...release,
            stateVersion: release.stateVersion + 1,
          }),
          channel: command.channel,
          channelGeneration: channel.generation,
        };
      } else if (command.kind === "WITHDRAW_RELEASE") {
        if (
          release.lifecycleState !== "APPROVED" ||
          release.withdrawnAt !== null
        ) {
          fail("INVALID_TRANSITION", "Withdrawal requires an approved release.");
        }
        release.lifecycleState = "WITHDRAWN";
        release.withdrawnAt = now;
        release.withdrawalReasonRef = command.reasonRef;
        const clearedChannels = [];
        for (const channelName of CHANNELS) {
          const currentChannel = await tx.findChannel(
            release.skillId,
            channelName,
          );
          if (currentChannel?.releaseId === release.releaseId) {
            const channel = {
              ...currentChannel,
              releaseId: null,
              generation: currentChannel.generation + 1,
              reasonRef: command.reasonRef,
              updatedAt: now,
            };
            await tx.putChannel(channel, currentChannel.generation);
            clearedChannels.push(channelName);
          }
        }
        result = {
          ...releaseResult({
            ...release,
            stateVersion: release.stateVersion + 1,
          }),
          clearedChannels,
        };
      }
      release.stateVersion += 1;
      release.updatedAt = now;
      await tx.updateRelease(release, current.stateVersion);
      result ??= releaseResult(release);
      aggregateId = release.releaseId;
      aggregateVersion = release.stateVersion;
    }

    const eventId = generatedId("evt_", EVENT_ID, idFactory, "eventId");
    const eventData = {
      ...structuredClone(result),
      authorization: {
        operationId: trusted.authorization.operationId,
        surface: trusted.authorization.surface,
        resourceId: trusted.authorization.resourceId,
        decisionId: trusted.authorization.decisionId,
        evidenceRef: trusted.authorization.evidenceRef,
        policyVersion: trusted.authorization.policyVersion,
        humanPrincipalId:
          trusted.authorization.humanPrincipalId,
        workloadActorPrincipalId:
          trusted.authorization.workloadActorPrincipalId,
        leafDelegationId:
          trusted.authorization.leafDelegationId,
        purposeRef: trusted.authorization.purposeRef,
      },
    };
    if (command.kind === "APPROVE_RELEASE") {
      eventData.approvalEvidence = {
        contentSha256: command.approvedContentSha256,
        evaluationReportRef:
          command.approvedEvaluationReportRef,
        evaluationReportSha256:
          command.approvedEvaluationReportSha256,
        humanBaselineDecisionRef:
          command.approvedHumanBaselineDecisionRef,
        humanBaselineDecisionSha256:
          command.approvedHumanBaselineDecisionSha256,
      };
    }
    const event = {
      tenantId: trusted.scope.tenantId,
      tenantKind: "SYNTHETIC",
      eventId,
      aggregateId,
      aggregateVersion,
      commandKind: command.kind,
      event: {
        specversion: "1.0",
        id: eventId,
        source: "/skill-registry",
        type: `product.aios.skill-registry.${command.kind
          .toLowerCase()
          .replaceAll("_", "-")}.v1`,
        subject: aggregateId,
        time: now,
        datacontenttype: "application/json",
        tenantkind: "SYNTHETIC",
        synthetic: true,
        data: eventData,
      },
      createdAt: now,
    };
    await tx.appendEvent(event);
    return Object.freeze({ ...result, eventId });
  }

  async function execute(serverContext, request) {
    validateServerContext(serverContext);
    validateRequest(request);
    let resources;
    try {
      resources = catalog.authorizationResources(serverContext.tenantId);
    } catch (error) {
      throw normalizeDependency(error, "SYNTHETIC_SOURCE_UNVERIFIED");
    }
    const authorization = AUTHORIZATION_BY_COMMAND[request.command.kind];
    const resourceId = resources?.[authorization.resourceField];
    if (!RESOURCE_ID.test(resourceId ?? "")) {
      fail(
        "INVALID_CONFIGURATION",
        "C13 operation authorization resource is invalid.",
      );
    }
    const trusted = await trustedInputs(
      serverContext,
      request,
      "MANAGE",
      resourceId,
      authorization.operationId,
    );
    const metadata = {
      idempotencyKey: request.idempotencyKey,
      requestHash: sha256Json({
        tenantId: serverContext.tenantId,
        command: request.command,
      }),
      commandKind: request.command.kind,
      correlationId: request.correlationId,
    };
    let outcome;
    try {
      outcome = await store.runCommand(
        trusted.scope,
        metadata,
        (tx) =>
          reduceCommand(
            tx,
            structuredClone(request.command),
            trusted,
            clock(),
          ),
      );
    } catch (error) {
      throw normalizeDependency(error, "STORE_UNAVAILABLE");
    }
    return deepFreeze({
      ...structuredClone(outcome.value),
      duplicate: outcome.duplicate,
      scriptsEnabled: false,
      allowedToolsGrantAuthorization: false,
      verificationScope: "P1_SYNTHETIC_ONLY",
    });
  }

  async function resolveForRun(serverContext, query) {
    validateServerContext(serverContext);
    validateResolveQuery(query);
    let resources;
    try {
      resources = catalog.authorizationResources(serverContext.tenantId);
    } catch (error) {
      throw normalizeDependency(error, "SYNTHETIC_SOURCE_UNVERIFIED");
    }
    const resourceId = resources?.[RESOLVE_AUTHORIZATION.resourceField];
    if (!RESOURCE_ID.test(resourceId ?? "")) {
      fail("INVALID_CONFIGURATION", "C13 READ resource is invalid.");
    }
    const trusted = await trustedInputs(
      serverContext,
      query,
      "READ",
      resourceId,
      RESOLVE_AUTHORIZATION.operationId,
    );
    let pair;
    try {
      pair = await store.readResolution(trusted.scope, query);
    } catch (error) {
      throw normalizeDependency(error, "STORE_UNAVAILABLE");
    }
    if (
      !pair?.channel ||
      pair.channel.releaseId === null ||
      !pair.release ||
      pair.channel.releaseId !== pair.release.releaseId ||
      pair.release.lifecycleState !== "APPROVED" ||
      pair.release.withdrawnAt !== null
    ) {
      fail(
        "SKILL_NOT_AVAILABLE",
        "No approved, non-withdrawn Skill is published on this channel.",
      );
    }
    if (pair.release.contentSha256 !== query.contentSha256) {
      fail("SKILL_HASH_MISMATCH", "Requested Skill hash is not current.");
    }
    return deepFreeze({
      skillId: pair.release.skillId,
      releaseId: pair.release.releaseId,
      version: pair.release.version,
      contentSha256: pair.release.contentSha256,
      channel: pair.channel.channel,
      channelGeneration: pair.channel.generation,
      manifest: structuredClone(pair.release.manifest),
      scriptsEnabled: false,
      allowedToolsGrantAuthorization: false,
      permissionSource: "C06_RUNTIME_DECISION_ONLY",
      verificationScope: "P1_SYNTHETIC_ONLY",
      productionVerificationStatus: "NOT_VERIFIED",
    });
  }

  return Object.freeze({ execute, resolveForRun });
}

function assertChannelCas(current, command) {
  if (
    (current?.generation ?? 0) !== command.expectedChannelGeneration ||
    (current?.releaseId ?? null) !== command.expectedCurrentReleaseId
  ) {
    fail("VERSION_CONFLICT", "Skill channel CAS did not match.");
  }
}

function validateEvaluationReport(report, expected) {
  const fields = [
    "schemaVersion",
    "evidenceClass",
    "evaluationMode",
    "reportId",
    "tenantId",
    "skillName",
    "skillVersion",
    "releaseDigest",
    "suiteId",
    "suiteSha256",
    "humanBaselineDecisionRef",
    "humanBaselineDecisionSha256",
    "humanBaselineStatus",
    "reportRef",
    "reportSha256",
    "caseCount",
    "reportedCaseCount",
    "caseResults",
    "status",
    "failureCount",
    "zeroToleranceViolationCount",
    "reasonCode",
  ];
  if (
    !report ||
    typeof report !== "object" ||
    Array.isArray(report) ||
    Object.keys(report).length !== fields.length ||
    Object.keys(report).some((key) => !fields.includes(key)) ||
    report.schemaVersion !== "c13-evaluation-report.v1" ||
    !["FROZEN_SYNTHETIC", "TEST_ONLY"].includes(
      report.evidenceClass,
    ) ||
    ![
      "DETERMINISTIC_BUILTIN_F04_GATE",
      "TEST_ONLY_VALIDATED_FIXTURE",
    ].includes(report.evaluationMode) ||
    (report.evidenceClass === "FROZEN_SYNTHETIC") !==
      (report.evaluationMode ===
        "DETERMINISTIC_BUILTIN_F04_GATE") ||
    !REQUEST_ID.test(report.reportId ?? "") ||
    report.tenantId !== expected.tenantId ||
    report.skillName !== expected.skillName ||
    report.skillVersion !== expected.skillVersion ||
    report.releaseDigest !== expected.releaseDigest ||
    report.suiteId !== expected.suiteId ||
    report.suiteSha256 !== expected.suiteSha256 ||
    report.humanBaselineStatus !== "VALIDATED" ||
    !REFERENCE.test(report.humanBaselineDecisionRef ?? "") ||
    !SHA256.test(report.humanBaselineDecisionSha256 ?? "") ||
    !REFERENCE.test(report.reportRef ?? "") ||
    !SHA256.test(report.reportSha256 ?? "") ||
    report.caseCount !== F04_CASE_IDS.length ||
    !Number.isSafeInteger(report.reportedCaseCount) ||
    report.reportedCaseCount < 0 ||
    report.reportedCaseCount > report.caseCount ||
    !Array.isArray(report.caseResults) ||
    report.reportedCaseCount !== report.caseResults.length ||
    !["PASS", "FAIL", "BLOCKED"].includes(report.status) ||
    !Number.isSafeInteger(report.failureCount) ||
    report.failureCount < 0 ||
    !Number.isSafeInteger(report.zeroToleranceViolationCount) ||
    report.zeroToleranceViolationCount < 0 ||
    typeof report.reasonCode !== "string" ||
    !report.reasonCode ||
    report.reasonCode.length > 128
  ) {
    fail(
      "EVALUATION_REPORT_INVALID",
      "Synthetic evaluation report is invalid.",
    );
  }

  if (
    report.evidenceClass === "TEST_ONLY" &&
    (!report.reportRef.startsWith("test://") ||
      !report.humanBaselineDecisionRef.startsWith("test://") ||
      !report.reasonCode.startsWith("TEST_ONLY_"))
  ) {
    fail(
      "EVALUATION_REPORT_INVALID",
      "Test evaluation evidence must be explicitly TEST_ONLY.",
    );
  }

  const seen = new Set();
  for (const result of report.caseResults) {
    const caseFields = ["caseId", "outcome", "score", "evidenceRef"];
    if (
      !result ||
      typeof result !== "object" ||
      Array.isArray(result) ||
      Object.keys(result).length !== caseFields.length ||
      Object.keys(result).some((key) => !caseFields.includes(key)) ||
      !F04_CASE_IDS.includes(result.caseId) ||
      seen.has(result.caseId) ||
      !["PASS", "FAIL"].includes(result.outcome) ||
      typeof result.score !== "number" ||
      !Number.isFinite(result.score) ||
      result.score < 0 ||
      result.score > 1 ||
      !REFERENCE.test(result.evidenceRef ?? "") ||
      (report.evidenceClass === "TEST_ONLY" &&
        !result.evidenceRef.startsWith("test://"))
    ) {
      fail(
        "EVALUATION_REPORT_INVALID",
        "Synthetic evaluation case evidence is invalid.",
      );
    }
    seen.add(result.caseId);
  }

  const failures = report.caseResults.filter(
    ({ outcome, score }) => outcome !== "PASS" || score < 0.8,
  );
  const zeroToleranceFailures = failures.filter(({ caseId }) =>
    F04_ZERO_TOLERANCE_CASE_IDS.has(caseId),
  );
  if (
    report.failureCount !== failures.length ||
    report.zeroToleranceViolationCount !==
      zeroToleranceFailures.length
  ) {
    fail(
      "EVALUATION_REPORT_INVALID",
      "Synthetic evaluation failure counts are inconsistent.",
    );
  }

  if (report.reportedCaseCount === 0) {
    if (
      report.status !== "BLOCKED" ||
      report.failureCount !== 0 ||
      report.zeroToleranceViolationCount !== 0 ||
      report.reasonCode !==
        "HUMAN_BASELINE_VALIDATED_BUT_CASE_EVIDENCE_PENDING"
    ) {
      fail(
        "EVALUATION_REPORT_INVALID",
        "A zero-result blocked report must state the exact evidence gap.",
      );
    }
    return;
  }

  if (
    report.reportedCaseCount !== F04_CASE_IDS.length ||
    F04_CASE_IDS.some((caseId) => !seen.has(caseId))
  ) {
    fail(
      "EVALUATION_REPORT_INVALID",
      "A non-blocked report requires all frozen case results.",
    );
  }
  const scoreById = new Map(
    report.caseResults.map(({ caseId, score }) => [caseId, score]),
  );
  const overallScore =
    report.caseResults.reduce((sum, { score }) => sum + score, 0) /
    report.caseResults.length;
  const passesGate =
    failures.length === 0 &&
    overallScore >= 0.9 &&
    scoreById.get("F04-E001") >= 0.85 &&
    scoreById.get("F04-E002") >= 0.95;
  const expectedStatus =
    zeroToleranceFailures.length > 0
      ? "BLOCKED"
      : passesGate
        ? "PASS"
        : "FAIL";
  if (
    report.status !== expectedStatus
  ) {
    fail(
      "EVALUATION_REPORT_INVALID",
      "Synthetic evaluation decision does not match the frozen gate.",
    );
  }
}
