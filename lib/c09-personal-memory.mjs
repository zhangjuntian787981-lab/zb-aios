import { createHash } from "node:crypto";

const UUID_V7 =
  "[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}";
const SYNTHETIC_TENANT_ID = new RegExp(`^stn_${UUID_V7}$`);
const PRINCIPAL_ID = new RegExp(`^prn_${UUID_V7}$`);
const DELEGATION_ID = new RegExp(`^dlg_${UUID_V7}$`);
const MEMORY_ID = new RegExp(`^mem_${UUID_V7}$`);
const CHECKPOINT_ID = new RegExp(`^ckp_${UUID_V7}$`);
const EVENT_ID = new RegExp(`^mev_${UUID_V7}$`);
const HUMAN_CONSENT_TOKEN = new RegExp(`^hct_${UUID_V7}$`);
const SHA256 = /^sha256:[a-f0-9]{64}$/;
const REFERENCE =
  /^(?:evidence|fixture|policy|profile|synthetic|test):\/\/\S+$/;
const IDEMPOTENCY_KEY = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const CORRELATION_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const UTC_MILLISECOND_INSTANT =
  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;

const ALLOWED_CATEGORIES = new Set(["PREFERENCE", "WORK_STATE"]);
const FORBIDDEN_CATEGORIES = new Set([
  "ENTERPRISE_FACT",
  "PRICE",
  "ORDER",
  "CONTRACT",
  "CERTIFICATION",
  "KPI",
]);
const MEMORY_STATES = new Set([
  "CANDIDATE",
  "CONFIRMED",
  "EXPIRED",
  "DELETED",
]);
const PROFILE_STATES = new Set(["ACTIVE", "PAUSED"]);
const HUMAN_CONSENT_PURPOSES = new Set([
  "CONFIRM_PERSONAL_MEMORY",
  "CORRECT_PERSONAL_MEMORY",
]);
const HUMAN_CONSENT_EVIDENCE_FIELDS = Object.freeze([
  "tenantId",
  "humanPrincipalId",
  "memoryId",
  "expectedVersion",
  "contentSha256",
  "expiresAt",
  "purpose",
  "tokenSha256",
  "consumedAt",
]);

const COMMAND_FIELDS = Object.freeze({
  PROPOSE_CANDIDATE: Object.freeze([
    "candidateRef",
    "idempotencyKey",
    "correlationId",
  ]),
  CONFIRM_CANDIDATE: Object.freeze([
    "memoryId",
    "expectedVersion",
    "humanConsentToken",
    "idempotencyKey",
    "correlationId",
  ]),
  CORRECT_MEMORY: Object.freeze([
    "memoryId",
    "expectedVersion",
    "replacementCandidateRef",
    "humanConsentToken",
    "idempotencyKey",
    "correlationId",
  ]),
  CHANGE_PROFILE_STATE: Object.freeze([
    "expectedProfileVersion",
    "state",
    "idempotencyKey",
    "correlationId",
  ]),
  MATERIALIZE_EXPIRY: Object.freeze([
    "memoryId",
    "expectedVersion",
    "idempotencyKey",
    "correlationId",
  ]),
  DELETE_MEMORY: Object.freeze([
    "memoryId",
    "expectedVersion",
    "idempotencyKey",
    "correlationId",
  ]),
  SAVE_CHECKPOINT: Object.freeze([
    "checkpointId",
    "expectedVersion",
    "threadRef",
    "stateRef",
    "stateSha256",
    "memoryIds",
    "idempotencyKey",
    "correlationId",
  ]),
});

export class PersonalMemoryError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "PersonalMemoryError";
    this.code = code;
  }
}

function fail(code, message) {
  throw new PersonalMemoryError(code, message);
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

function identifier(value, pattern, field) {
  nonEmptyString(value, field, 128);
  if (!pattern.test(value)) fail("INVALID_INPUT", `${field} is invalid.`);
}

function positiveInteger(value, field, { allowZero = false } = {}) {
  const minimum = allowZero ? 0 : 1;
  if (!Number.isSafeInteger(value) || value < minimum) {
    fail("INVALID_INPUT", `${field} is invalid.`);
  }
}

function canonicalInstant(value, field) {
  if (
    typeof value !== "string" ||
    !UTC_MILLISECOND_INSTANT.test(value) ||
    new Date(value).toISOString() !== value
  ) {
    fail("INVALID_INPUT", `${field} must be a canonical UTC instant.`);
  }
  return value;
}

function reference(value, field) {
  nonEmptyString(value, field, 1024);
  if (!REFERENCE.test(value)) {
    fail("P3_REQUIRED", `${field} must be an approved P1 reference.`);
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
  if (typeof value === "number") {
    if (!Number.isFinite(value)) fail("INVALID_INPUT", "Invalid JSON number.");
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

export function personalMemorySha256(value) {
  return `sha256:${createHash("sha256")
    .update(typeof value === "string" ? value : canonicalize(value))
    .digest("hex")}`;
}

function validateHumanConsentBinding(binding) {
  exactKeys(
    binding,
    [
      "tenantId",
      "humanPrincipalId",
      "memoryId",
      "expectedVersion",
      "contentSha256",
      "expiresAt",
      "purpose",
    ],
    "human consent binding",
  );
  validateTenantId(binding.tenantId);
  identifier(
    binding.humanPrincipalId,
    PRINCIPAL_ID,
    "humanPrincipalId",
  );
  identifier(binding.memoryId, MEMORY_ID, "memoryId");
  positiveInteger(binding.expectedVersion, "expectedVersion");
  if (!SHA256.test(binding.contentSha256 ?? "")) {
    fail("INVALID_INPUT", "contentSha256 is invalid.");
  }
  canonicalInstant(binding.expiresAt, "expiresAt");
  if (!HUMAN_CONSENT_PURPOSES.has(binding.purpose)) {
    fail("INVALID_INPUT", "Human consent purpose is invalid.");
  }
  return clone(binding);
}

export function validatePersonalMemoryHumanConsentEvidence(evidence) {
  exactKeys(
    evidence,
    HUMAN_CONSENT_EVIDENCE_FIELDS,
    "human consent evidence",
  );
  const binding = validateHumanConsentBinding({
    tenantId: evidence.tenantId,
    humanPrincipalId: evidence.humanPrincipalId,
    memoryId: evidence.memoryId,
    expectedVersion: evidence.expectedVersion,
    contentSha256: evidence.contentSha256,
    expiresAt: evidence.expiresAt,
    purpose: evidence.purpose,
  });
  if (!SHA256.test(evidence.tokenSha256 ?? "")) {
    fail("INVALID_INPUT", "tokenSha256 is invalid.");
  }
  const consumedAt = canonicalInstant(
    evidence.consumedAt,
    "consumedAt",
  );
  if (Date.parse(binding.expiresAt) <= Date.parse(consumedAt)) {
    fail("INVALID_INPUT", "Human consent evidence is expired.");
  }
  return {
    ...binding,
    tokenSha256: evidence.tokenSha256,
    consumedAt,
  };
}

export function createSyntheticHumanConsentAuthority({
  tokenFactory = uuidV7,
} = {}) {
  if (typeof tokenFactory !== "function") {
    fail(
      "INVALID_CONFIGURATION",
      "Synthetic Human consent token factory is invalid.",
    );
  }
  const issued = new Map();
  const consumed = new Map();
  const issuer = Object.freeze({
    issue(binding) {
      const artifact = validateHumanConsentBinding(binding);
      const token = generatedId(
        "hct_",
        HUMAN_CONSENT_TOKEN,
        "humanConsentToken",
        tokenFactory,
      );
      if (issued.has(token) || consumed.has(token)) {
        fail("ID_COLLISION", "Human consent token already exists.");
      }
      issued.set(token, artifact);
      return token;
    },
  });
  const consentStore = Object.freeze({
    async consume({ token, expected, now, requestHash }) {
      identifier(token, HUMAN_CONSENT_TOKEN, "humanConsentToken");
      canonicalInstant(now, "clock");
      if (!SHA256.test(requestHash ?? "")) {
        fail("INVALID_INPUT", "requestHash is invalid.");
      }
      const prior = consumed.get(token);
      if (prior) {
        if (prior.requestHash !== requestHash) {
          fail(
            "HUMAN_CONSENT_ALREADY_CONSUMED",
            "Human consent artifact was already consumed.",
          );
        }
        return clone(prior.evidence);
      }
      const artifact = issued.get(token);
      if (!artifact) {
        fail(
          "HUMAN_CONSENT_INVALID",
          "Human consent artifact was not issued by a trusted Human flow.",
        );
      }
      const expectedBinding = validateHumanConsentBinding({
        ...expected,
        expiresAt: artifact.expiresAt,
      });
      if (
        personalMemorySha256(artifact) !==
          personalMemorySha256(expectedBinding)
      ) {
        fail(
          "HUMAN_CONSENT_BINDING_MISMATCH",
          "Human consent artifact does not match this action.",
        );
      }
      if (Date.parse(artifact.expiresAt) <= Date.parse(now)) {
        fail("HUMAN_CONSENT_EXPIRED", "Human consent artifact expired.");
      }
      const evidence = {
        ...artifact,
        tokenSha256: personalMemorySha256(token),
        consumedAt: now,
      };
      consumed.set(token, { requestHash, evidence });
      issued.delete(token);
      return clone(evidence);
    },
  });
  return Object.freeze({ issuer, consentStore });
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

function generatedId(prefix, pattern, field, idFactory) {
  const value = `${prefix}${idFactory()}`;
  identifier(value, pattern, field);
  return value;
}

function validateTenantId(tenantId) {
  if (!SYNTHETIC_TENANT_ID.test(tenantId ?? "")) {
    fail("P3_REQUIRED", "C09 accepts only Synthetic Tenant IDs before P3.");
  }
}

function validateCategory(category) {
  nonEmptyString(category, "category", 64);
  if (FORBIDDEN_CATEGORIES.has(category)) {
    fail(
      "FORBIDDEN_MEMORY_CATEGORY",
      `${category} cannot enter personal memory.`,
    );
  }
  if (!ALLOWED_CATEGORIES.has(category)) {
    fail("INVALID_MEMORY_CATEGORY", "Unknown personal memory category.");
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
    fail("UNTRUSTED_ROUTE", "C09 route or workload context is untrusted.");
  }
  validateTenantId(context.tenantId);
  identifier(
    context.workloadActorPrincipalId,
    PRINCIPAL_ID,
    "workloadActorPrincipalId",
  );
}

function validateRequestEnvelope(request) {
  exactKeys(
    request,
    ["sessionToken", "delegationId", "command"],
    "request",
  );
  nonEmptyString(request.sessionToken, "sessionToken", 256);
  identifier(request.delegationId, DELEGATION_ID, "delegationId");
  const fields = COMMAND_FIELDS[request.command?.kind];
  if (!fields) fail("INVALID_INPUT", "Unknown C09 command.");
  exactKeys(request.command, ["kind", ...fields], "command");
  if (!IDEMPOTENCY_KEY.test(request.command.idempotencyKey ?? "")) {
    fail("INVALID_INPUT", "idempotencyKey is invalid.");
  }
  if (!CORRELATION_ID.test(request.command.correlationId ?? "")) {
    fail("INVALID_INPUT", "correlationId is invalid.");
  }
}

function validateRecallRequest(request) {
  exactKeys(
    request,
    ["sessionToken", "delegationId", "correlationId", "limit"],
    "recall request",
  );
  nonEmptyString(request.sessionToken, "sessionToken", 256);
  identifier(request.delegationId, DELEGATION_ID, "delegationId");
  if (!CORRELATION_ID.test(request.correlationId ?? "")) {
    fail("INVALID_INPUT", "correlationId is invalid.");
  }
  positiveInteger(request.limit, "limit");
  if (request.limit > 50) fail("INVALID_INPUT", "limit exceeds 50.");
}

function validateIdentity(identity, context, delegationId) {
  if (
    identity?.tenantId !== context.tenantId ||
    identity?.tenantKind !== "SYNTHETIC" ||
    identity?.trustSource !==
      "VERIFIED_SESSION_IDENTITY_LINK_AND_WORKLOAD_CONTEXT" ||
    identity?.humanSubject?.principalType !== "HUMAN" ||
    identity?.workloadActor?.principalId !==
      context.workloadActorPrincipalId ||
    !Array.isArray(identity?.delegationChain) ||
    identity.delegationChain.length === 0
  ) {
    fail("IDENTITY_BINDING_INVALID", "C05 identity binding is invalid.");
  }
  identifier(
    identity.humanSubject.principalId,
    PRINCIPAL_ID,
    "humanSubject.principalId",
  );
  identifier(
    identity.workloadActor.principalId,
    PRINCIPAL_ID,
    "workloadActor.principalId",
  );
  nonEmptyString(identity.sessionId, "identity.sessionId", 256);
  positiveInteger(
    identity.humanSubject.lifecycleVersion,
    "humanSubject.lifecycleVersion",
  );
  positiveInteger(
    identity.humanSubject.securityEpoch,
    "humanSubject.securityEpoch",
  );
  positiveInteger(
    identity.workloadActor.lifecycleVersion,
    "workloadActor.lifecycleVersion",
  );
  positiveInteger(
    identity.workloadActor.securityEpoch,
    "workloadActor.securityEpoch",
  );
  const leaf = identity.delegationChain.at(-1);
  if (
    leaf?.delegationId !== delegationId ||
    leaf?.delegatorPrincipalId !== identity.humanSubject.principalId ||
    leaf?.delegatePrincipalId !== identity.workloadActor.principalId
  ) {
    fail("IDENTITY_BINDING_INVALID", "Delegation binding is invalid.");
  }
  positiveInteger(leaf.lifecycleVersion, "delegation.lifecycleVersion");
  return clone(identity);
}

function validateAuthorization(
  decision,
  { tenantId, principalId, operation, identity },
) {
  const leaf = identity.delegationChain.at(-1);
  if (
    decision?.allowed !== true ||
    decision?.tenantId !== tenantId ||
    decision?.humanPrincipalId !== principalId ||
    decision?.workloadActorPrincipalId !==
      identity.workloadActor.principalId ||
    decision?.delegationId !== leaf.delegationId ||
    decision?.operation !== operation
  ) {
    fail("FORBIDDEN", "C06 denied the personal-memory operation.");
  }
  nonEmptyString(decision.decisionId, "decisionId", 128);
  reference(decision.evidenceRef, "evidenceRef");
  nonEmptyString(decision.policyVersion, "policyVersion", 128);
  return {
    decisionId: decision.decisionId,
    evidenceRef: decision.evidenceRef,
    policyVersion: decision.policyVersion,
    humanPrincipalId: principalId,
    workloadActorPrincipalId: identity.workloadActor.principalId,
    delegationId: leaf.delegationId,
  };
}

function sameActionIdentity(left, right) {
  const leftLeaf = left.delegationChain.at(-1);
  const rightLeaf = right.delegationChain.at(-1);
  return (
    left.sessionId === right.sessionId &&
    left.humanSubject.principalId === right.humanSubject.principalId &&
    left.humanSubject.lifecycleVersion ===
      right.humanSubject.lifecycleVersion &&
    left.humanSubject.securityEpoch === right.humanSubject.securityEpoch &&
    left.workloadActor.principalId === right.workloadActor.principalId &&
    left.workloadActor.lifecycleVersion ===
      right.workloadActor.lifecycleVersion &&
    left.workloadActor.securityEpoch === right.workloadActor.securityEpoch &&
    leftLeaf.delegationId === rightLeaf.delegationId &&
    leftLeaf.lifecycleVersion === rightLeaf.lifecycleVersion
  );
}

function validateScope(scope, tenantId, correlationId) {
  if (
    scope?.trustSource !== "C07_VERIFIED_TENANT_SCOPE" ||
    scope.tenantId !== tenantId ||
    scope.tenantKind !== "SYNTHETIC" ||
    scope.correlationId !== correlationId
  ) {
    fail("TENANT_SCOPE_VIOLATION", "C07 Tenant scope is invalid.");
  }
  positiveInteger(scope.lifecycleVersion, "scope.lifecycleVersion");
  nonEmptyString(scope.decisionId, "scope.decisionId", 128);
  reference(scope.evidenceRef, "scope.evidenceRef");
  nonEmptyString(scope.policyVersion, "scope.policyVersion", 128);
  return clone(scope);
}

function catalogCandidate(entry) {
  exactKeys(
    entry,
    [
      "candidateRef",
      "category",
      "content",
      "contentSha256",
      "expiresAt",
    ],
    "catalog candidate",
  );
  reference(entry.candidateRef, "candidateRef");
  validateCategory(entry.category);
  nonEmptyString(entry.content, "content", 2048);
  if (
    !SHA256.test(entry.contentSha256 ?? "") ||
    personalMemorySha256(entry.content) !== entry.contentSha256
  ) {
    fail("INVALID_CATALOG", "Candidate content hash is invalid.");
  }
  canonicalInstant(entry.expiresAt, "expiresAt");
  return Object.freeze(clone(entry));
}

export function createSyntheticPersonalMemoryCatalog(document) {
  exactKeys(
    document,
    ["schemaVersion", "status", "tenants"],
    "catalog",
  );
  if (
    document.schemaVersion !==
      "c09-synthetic-personal-memory-catalog.v1" ||
    document.status !== "SYNTHETIC_ONLY" ||
    !Array.isArray(document.tenants) ||
    document.tenants.length !== 3
  ) {
    fail("INVALID_CATALOG", "C09 requires three frozen Synthetic Tenants.");
  }
  const tenants = new Map();
  for (const entry of document.tenants) {
    exactKeys(
      entry,
      ["tenantId", "fixtureId", "candidates"],
      "catalog tenant",
    );
    validateTenantId(entry.tenantId);
    nonEmptyString(entry.fixtureId, "fixtureId", 128);
    if (
      tenants.has(entry.tenantId) ||
      !Array.isArray(entry.candidates) ||
      entry.candidates.length < 2
    ) {
      fail("INVALID_CATALOG", "Synthetic Tenant catalog is invalid.");
    }
    const candidates = new Map();
    for (const raw of entry.candidates) {
      const candidate = catalogCandidate(raw);
      if (candidates.has(candidate.candidateRef)) {
        fail("INVALID_CATALOG", "Duplicate candidateRef.");
      }
      candidates.set(candidate.candidateRef, candidate);
    }
    tenants.set(entry.tenantId, Object.freeze({
      fixtureId: entry.fixtureId,
      candidates,
    }));
  }
  return Object.freeze({
    resolve(tenantId, candidateRef) {
      validateTenantId(tenantId);
      reference(candidateRef, "candidateRef");
      const candidate = tenants.get(tenantId)?.candidates.get(candidateRef);
      if (!candidate) {
        fail(
          "SYNTHETIC_FIXTURE_MISMATCH",
          "Candidate is not frozen for this Synthetic Tenant.",
        );
      }
      return clone(candidate);
    },
    tenantIds() {
      return [...tenants.keys()];
    },
  });
}

function emptyState() {
  return {
    profiles: new Map(),
    memories: new Map(),
    checkpoints: new Map(),
    events: [],
    receipts: new Map(),
  };
}

function composite(...parts) {
  return parts.join("\u001f");
}

function memoryKey(tenantId, memoryId) {
  return composite(tenantId, memoryId);
}

function profileKey(tenantId, principalId) {
  return composite(tenantId, principalId);
}

function checkpointKey(tenantId, checkpointId) {
  return composite(tenantId, checkpointId);
}

function receiptKey(tenantId, principalId, idempotencyKey) {
  return composite(tenantId, principalId, idempotencyKey);
}

function profileFor(state, envelope) {
  const key = profileKey(envelope.tenantId, envelope.principalId);
  let profile = state.profiles.get(key);
  if (!profile) {
    profile = {
      tenantId: envelope.tenantId,
      tenantKind: "SYNTHETIC",
      principalId: envelope.principalId,
      state: "ACTIVE",
      version: 1,
      createdAt: envelope.now,
      updatedAt: envelope.now,
    };
    state.profiles.set(key, profile);
  }
  return profile;
}

function requireActiveProfile(profile) {
  if (profile.state !== "ACTIVE") {
    fail("PROFILE_PAUSED", "Personal profile is paused.");
  }
}

function requireOwnedMemory(state, envelope) {
  const memory = state.memories.get(
    memoryKey(envelope.tenantId, envelope.memoryId),
  );
  if (!memory || memory.principalId !== envelope.principalId) {
    fail("MEMORY_NOT_FOUND", "Memory was not found for this owner.");
  }
  if (memory.version !== envelope.expectedVersion) {
    fail("STALE_VERSION", "Memory version is stale.");
  }
  return memory;
}

function eventFor(envelope, {
  eventId = envelope.eventId,
  memoryId = envelope.memoryId,
  eventType,
  fromState,
  toState,
  contentSha256,
}) {
  return {
    tenantId: envelope.tenantId,
    tenantKind: "SYNTHETIC",
    eventId,
    memoryId,
    principalId: envelope.principalId,
    eventType,
    fromState,
    toState,
    contentSha256,
    actorPrincipalId: envelope.actorPrincipalId,
    authorizationEvidence: clone(envelope.authorizationEvidence),
    humanConsentEvidence: clone(envelope.humanConsentEvidence ?? null),
    correlationId: envelope.correlationId,
    createdAt: envelope.now,
  };
}

function requireHumanConsent(envelope, contentSha256, purpose) {
  const evidence = envelope.humanConsentEvidence;
  if (
    !evidence ||
    evidence.tenantId !== envelope.tenantId ||
    evidence.humanPrincipalId !== envelope.principalId ||
    evidence.memoryId !== envelope.memoryId ||
    evidence.expectedVersion !== envelope.expectedVersion ||
    evidence.contentSha256 !== contentSha256 ||
    evidence.purpose !== purpose ||
    evidence.consumedAt !== envelope.now ||
    Date.parse(evidence.expiresAt) <= Date.parse(envelope.now)
  ) {
    fail(
      "HUMAN_CONSENT_BINDING_MISMATCH",
      "Stored action does not match consumed Human consent.",
    );
  }
}

function scrubMemory(memory, state, reason, envelope) {
  const previousState = memory.state;
  const previousHash = memory.contentSha256;
  memory.state = state;
  memory.content = null;
  memory.version += 1;
  memory.updatedAt = envelope.now;
  memory.terminalReason = reason;
  for (const checkpoint of envelope.state.checkpoints.values()) {
    if (
      checkpoint.tenantId === envelope.tenantId &&
      checkpoint.principalId === envelope.principalId &&
      checkpoint.memoryIds.includes(memory.memoryId)
    ) {
      checkpoint.memoryIds = checkpoint.memoryIds.filter(
        (memoryId) => memoryId !== memory.memoryId,
      );
      checkpoint.version += 1;
      checkpoint.updatedAt = envelope.now;
    }
  }
  envelope.state.events.push(
    eventFor(envelope, {
      eventType: state === "DELETED"
        ? "MEMORY_DELETED"
        : "MEMORY_EXPIRED",
      fromState: previousState,
      toState: state,
      contentSha256: previousHash,
    }),
  );
  return memory;
}

function applyToState(state, envelope) {
  envelope.state = state;
  const receiptId = receiptKey(
    envelope.tenantId,
    envelope.principalId,
    envelope.idempotencyKey,
  );
  const existing = state.receipts.get(receiptId);
  if (existing) {
    if (existing.requestHash !== envelope.requestHash) {
      fail("IDEMPOTENCY_CONFLICT", "Idempotency key was reused.");
    }
    return clone(existing.result);
  }

  const profile = profileFor(state, envelope);
  let result;
  if (envelope.operation === "PROPOSE_CANDIDATE") {
    requireActiveProfile(profile);
    const memory = {
      tenantId: envelope.tenantId,
      tenantKind: "SYNTHETIC",
      memoryId: envelope.memoryId,
      principalId: envelope.principalId,
      state: "CANDIDATE",
      category: envelope.candidate.category,
      content: envelope.candidate.content,
      contentSha256: envelope.candidate.contentSha256,
      sourceRef: envelope.candidate.candidateRef,
      expiresAt: envelope.candidate.expiresAt,
      version: 1,
      terminalReason: null,
      createdAt: envelope.now,
      updatedAt: envelope.now,
    };
    if (state.memories.has(memoryKey(envelope.tenantId, memory.memoryId))) {
      fail("ID_COLLISION", "Generated memory ID already exists.");
    }
    state.memories.set(memoryKey(envelope.tenantId, memory.memoryId), memory);
    state.events.push(
      eventFor(envelope, {
        eventType: "MEMORY_CANDIDATE_PROPOSED",
        fromState: null,
        toState: "CANDIDATE",
        contentSha256: memory.contentSha256,
      }),
    );
    result = {
      memoryId: memory.memoryId,
      state: memory.state,
      version: memory.version,
    };
  } else if (envelope.operation === "CONFIRM_CANDIDATE") {
    requireActiveProfile(profile);
    const memory = requireOwnedMemory(state, envelope);
    if (memory.state !== "CANDIDATE") {
      fail("INVALID_STATE", "Only a Candidate can be confirmed.");
    }
    requireHumanConsent(
      envelope,
      memory.contentSha256,
      "CONFIRM_PERSONAL_MEMORY",
    );
    memory.state = "CONFIRMED";
    memory.version += 1;
    memory.updatedAt = envelope.now;
    state.events.push(
      eventFor(envelope, {
        eventType: "MEMORY_CONFIRMED",
        fromState: "CANDIDATE",
        toState: "CONFIRMED",
        contentSha256: memory.contentSha256,
      }),
    );
    result = {
      memoryId: memory.memoryId,
      state: memory.state,
      version: memory.version,
    };
  } else if (envelope.operation === "CORRECT_MEMORY") {
    requireActiveProfile(profile);
    const memory = requireOwnedMemory(state, envelope);
    if (memory.state !== "CONFIRMED") {
      fail("INVALID_STATE", "Only a Confirmed memory can be corrected.");
    }
    requireHumanConsent(
      envelope,
      envelope.replacementCandidate.contentSha256,
      "CORRECT_PERSONAL_MEMORY",
    );
    scrubMemory(memory, "DELETED", "CORRECTED", envelope);
    const replacement = {
      tenantId: envelope.tenantId,
      tenantKind: "SYNTHETIC",
      memoryId: envelope.replacementMemoryId,
      principalId: envelope.principalId,
      state: "CONFIRMED",
      category: envelope.replacementCandidate.category,
      content: envelope.replacementCandidate.content,
      contentSha256: envelope.replacementCandidate.contentSha256,
      sourceRef: envelope.replacementCandidate.candidateRef,
      expiresAt: envelope.replacementCandidate.expiresAt,
      version: 1,
      terminalReason: null,
      createdAt: envelope.now,
      updatedAt: envelope.now,
    };
    if (
      state.memories.has(
        memoryKey(envelope.tenantId, replacement.memoryId),
      )
    ) {
      fail("ID_COLLISION", "Generated replacement memory ID already exists.");
    }
    state.memories.set(
      memoryKey(envelope.tenantId, replacement.memoryId),
      replacement,
    );
    state.events.push(
      eventFor(envelope, {
        eventId: envelope.replacementEventId,
        memoryId: replacement.memoryId,
        eventType: "MEMORY_CONFIRMED",
        fromState: null,
        toState: "CONFIRMED",
        contentSha256: replacement.contentSha256,
      }),
    );
    result = {
      deletedMemoryId: memory.memoryId,
      deletedVersion: memory.version,
      memoryId: replacement.memoryId,
      state: replacement.state,
      version: replacement.version,
    };
  } else if (envelope.operation === "CHANGE_PROFILE_STATE") {
    if (profile.version !== envelope.expectedProfileVersion) {
      fail("STALE_VERSION", "Profile version is stale.");
    }
    if (!PROFILE_STATES.has(envelope.profileState)) {
      fail("INVALID_INPUT", "Unknown profile state.");
    }
    if (profile.state === envelope.profileState) {
      fail("INVALID_STATE", "Profile is already in this state.");
    }
    profile.state = envelope.profileState;
    profile.version += 1;
    profile.updatedAt = envelope.now;
    result = {
      principalId: profile.principalId,
      state: profile.state,
      version: profile.version,
    };
  } else if (envelope.operation === "MATERIALIZE_EXPIRY") {
    const memory = requireOwnedMemory(state, envelope);
    if (
      !["CANDIDATE", "CONFIRMED"].includes(memory.state) ||
      Date.parse(memory.expiresAt) > Date.parse(envelope.now)
    ) {
      fail("INVALID_STATE", "Memory is not due for expiration.");
    }
    scrubMemory(memory, "EXPIRED", "RETENTION_EXPIRED", envelope);
    result = {
      memoryId: memory.memoryId,
      state: memory.state,
      version: memory.version,
    };
  } else if (envelope.operation === "DELETE_MEMORY") {
    const memory = requireOwnedMemory(state, envelope);
    if (!["CANDIDATE", "CONFIRMED", "EXPIRED"].includes(memory.state)) {
      fail("INVALID_STATE", "Memory cannot be deleted again.");
    }
    scrubMemory(memory, "DELETED", "OWNER_REQUEST", envelope);
    result = {
      memoryId: memory.memoryId,
      state: memory.state,
      version: memory.version,
    };
  } else if (envelope.operation === "SAVE_CHECKPOINT") {
    requireActiveProfile(profile);
    const key = checkpointKey(envelope.tenantId, envelope.checkpointId);
    const existingCheckpoint = state.checkpoints.get(key);
    if (existingCheckpoint) {
      if (
        existingCheckpoint.principalId !== envelope.principalId ||
        existingCheckpoint.version !== envelope.expectedVersion
      ) {
        fail("STALE_VERSION", "Checkpoint version is stale.");
      }
    } else if (envelope.expectedVersion !== 0) {
      fail("STALE_VERSION", "New Checkpoint must expect version zero.");
    }
    const memoryIds = [];
    for (const memoryId of envelope.memoryIds) {
      const memory = state.memories.get(
        memoryKey(envelope.tenantId, memoryId),
      );
      if (
        !memory ||
        memory.principalId !== envelope.principalId ||
        memory.state !== "CONFIRMED" ||
        Date.parse(memory.expiresAt) <= Date.parse(envelope.now)
      ) {
        fail("INVALID_CHECKPOINT_REFERENCE", "Checkpoint memory is invalid.");
      }
      memoryIds.push(memoryId);
    }
    const checkpoint = {
      tenantId: envelope.tenantId,
      tenantKind: "SYNTHETIC",
      checkpointId: envelope.checkpointId,
      principalId: envelope.principalId,
      threadRef: envelope.threadRef,
      stateRef: envelope.stateRef,
      stateSha256: envelope.stateSha256,
      memoryIds,
      version: (existingCheckpoint?.version ?? 0) + 1,
      createdAt: existingCheckpoint?.createdAt ?? envelope.now,
      updatedAt: envelope.now,
    };
    state.checkpoints.set(key, checkpoint);
    result = {
      checkpointId: checkpoint.checkpointId,
      version: checkpoint.version,
      memoryIds: clone(checkpoint.memoryIds),
    };
  } else {
    fail("INVALID_INPUT", "Unsupported C09 operation.");
  }

  state.receipts.set(receiptId, {
    tenantId: envelope.tenantId,
    principalId: envelope.principalId,
    idempotencyKey: envelope.idempotencyKey,
    requestHash: envelope.requestHash,
    operation: envelope.operation,
    result: clone(result),
    createdAt: envelope.now,
  });
  return clone(result);
}

function serializeState(state, { asOf = null } = {}) {
  const profileStates = new Map(
    [...state.profiles.values()].map((profile) => [
      profileKey(profile.tenantId, profile.principalId),
      profile.state,
    ]),
  );
  const memories = [...state.memories.values()].map((memory) => {
    const unavailableAtExport =
      asOf &&
      !["EXPIRED", "DELETED"].includes(memory.state) &&
      (
        profileStates.get(
          profileKey(memory.tenantId, memory.principalId),
        ) === "PAUSED" ||
        Date.parse(memory.expiresAt) <= Date.parse(asOf)
    );
    if (unavailableAtExport) {
      const paused =
        profileStates.get(
          profileKey(memory.tenantId, memory.principalId),
        ) === "PAUSED";
      return {
        ...clone(memory),
        state: paused ? "DELETED" : "EXPIRED",
        content: null,
        version: memory.version + 1,
        terminalReason: paused
          ? "PROFILE_PAUSED_AT_EXPORT"
          : "RETENTION_EXPIRED_AT_EXPORT",
        updatedAt: asOf,
      };
    }
    if (["EXPIRED", "DELETED"].includes(memory.state)) {
      return { ...clone(memory), content: null };
    }
    return clone(memory);
  });
  const availableMemoryIds = new Set(
    memories
      .filter(
        (memory) =>
          memory.state === "CONFIRMED" &&
          profileStates.get(
            profileKey(memory.tenantId, memory.principalId),
          ) === "ACTIVE" &&
          Date.parse(memory.expiresAt) > Date.parse(asOf),
      )
      .map((memory) => memoryKey(memory.tenantId, memory.memoryId)),
  );
  const checkpoints = [...state.checkpoints.values()].map((checkpoint) => {
    const memoryIds = asOf
      ? checkpoint.memoryIds.filter((memoryId) =>
          availableMemoryIds.has(
            memoryKey(checkpoint.tenantId, memoryId),
          )
        )
      : clone(checkpoint.memoryIds);
    return {
      ...clone(checkpoint),
      memoryIds,
      version:
        memoryIds.length === checkpoint.memoryIds.length
          ? checkpoint.version
          : checkpoint.version + 1,
      updatedAt:
        memoryIds.length === checkpoint.memoryIds.length
          ? checkpoint.updatedAt
          : asOf,
    };
  });
  return {
    profiles: [...state.profiles.values()].map(clone),
    memories,
    checkpoints,
    events: state.events.map(clone),
    receipts: [...state.receipts.values()].map(clone),
  };
}

function hydrateState(snapshot) {
  if (!snapshot) return emptyState();
  exactKeys(
    snapshot,
    ["profiles", "memories", "checkpoints", "events", "receipts"],
    "recovery snapshot",
  );
  const state = emptyState();
  for (const profile of snapshot.profiles) {
    state.profiles.set(
      profileKey(profile.tenantId, profile.principalId),
      clone(profile),
    );
  }
  for (const memory of snapshot.memories) {
    if (
      ["EXPIRED", "DELETED"].includes(memory.state) &&
      memory.content !== null
    ) {
      fail("RECOVERY_SNAPSHOT_INVALID", "Terminal memory retained content.");
    }
    state.memories.set(
      memoryKey(memory.tenantId, memory.memoryId),
      clone(memory),
    );
  }
  for (const checkpoint of snapshot.checkpoints) {
    state.checkpoints.set(
      checkpointKey(checkpoint.tenantId, checkpoint.checkpointId),
      clone(checkpoint),
    );
  }
  state.events = snapshot.events.map(clone);
  for (const receipt of snapshot.receipts) {
    state.receipts.set(
      receiptKey(
        receipt.tenantId,
        receipt.principalId,
        receipt.idempotencyKey,
      ),
      clone(receipt),
    );
  }
  return state;
}

export function createMemoryPersonalMemoryStore({ snapshot = null } = {}) {
  let state = hydrateState(snapshot);
  let queue = Promise.resolve();

  async function locked(operation) {
    const pending = queue.then(operation, operation);
    queue = pending.catch(() => {});
    return pending;
  }

  function assertScope(scope, tenantId) {
    if (
      scope?.trustSource !== "C07_VERIFIED_TENANT_SCOPE" ||
      scope.tenantId !== tenantId ||
      scope.tenantKind !== "SYNTHETIC"
    ) {
      fail("TENANT_SCOPE_VIOLATION", "Store Tenant scope is invalid.");
    }
  }

  return Object.freeze({
    async apply(scope, envelope) {
      assertScope(scope, envelope.tenantId);
      return locked(async () => {
        const draft = hydrateState(serializeState(state));
        const result = applyToState(draft, clone(envelope));
        state = draft;
        return result;
      });
    },
    async readCommandReceipt(scope, {
      tenantId,
      principalId,
      idempotencyKey,
      requestHash,
    }) {
      assertScope(scope, tenantId);
      const receipt = state.receipts.get(
        receiptKey(tenantId, principalId, idempotencyKey),
      );
      if (!receipt) return null;
      if (receipt.requestHash !== requestHash) {
        fail("IDEMPOTENCY_CONFLICT", "Idempotency key was reused.");
      }
      return clone(receipt.result);
    },
    async listRecallMetadata(scope, {
      tenantId,
      principalId,
      now,
      limit,
    }) {
      assertScope(scope, tenantId);
      const profile = state.profiles.get(
        profileKey(tenantId, principalId),
      );
      if (profile?.state === "PAUSED") return [];
      return [...state.memories.values()]
        .filter(
          (memory) =>
            memory.tenantId === tenantId &&
            memory.principalId === principalId &&
            memory.state === "CONFIRMED" &&
            Date.parse(memory.expiresAt) > Date.parse(now),
        )
        .sort((left, right) =>
          left.createdAt.localeCompare(right.createdAt)
        )
        .slice(0, limit)
        .map((memory) => ({
          memoryId: memory.memoryId,
          category: memory.category,
          contentSha256: memory.contentSha256,
          version: memory.version,
          expiresAt: memory.expiresAt,
        }));
    },
    async readRecallContent(scope, {
      tenantId,
      principalId,
      memoryId,
      expectedVersion,
      now,
    }) {
      assertScope(scope, tenantId);
      const profile = state.profiles.get(
        profileKey(tenantId, principalId),
      );
      if (profile?.state === "PAUSED") return null;
      const memory = state.memories.get(memoryKey(tenantId, memoryId));
      if (
        !memory ||
        memory.principalId !== principalId ||
        memory.state !== "CONFIRMED" ||
        memory.version !== expectedVersion ||
        Date.parse(memory.expiresAt) <= Date.parse(now)
      ) {
        return null;
      }
      return clone(memory);
    },
    async readProfile(scope, { tenantId, principalId }) {
      assertScope(scope, tenantId);
      return clone(state.profiles.get(profileKey(tenantId, principalId)) ?? {
        tenantId,
        tenantKind: "SYNTHETIC",
        principalId,
        state: "ACTIVE",
        version: 1,
      });
    },
    async readConsentTarget(scope, {
      tenantId,
      principalId,
      memoryId,
    }) {
      assertScope(scope, tenantId);
      const memory = state.memories.get(memoryKey(tenantId, memoryId));
      if (!memory || memory.principalId !== principalId) return null;
      return {
        memoryId: memory.memoryId,
        state: memory.state,
        contentSha256: memory.contentSha256,
        version: memory.version,
      };
    },
    async readCheckpoint(scope, {
      tenantId,
      principalId,
      checkpointId,
      asOf,
    }) {
      assertScope(scope, tenantId);
      const profile = state.profiles.get(
        profileKey(tenantId, principalId),
      );
      if (profile?.state === "PAUSED") return null;
      const checkpoint = state.checkpoints.get(
        checkpointKey(tenantId, checkpointId),
      );
      if (!checkpoint || checkpoint.principalId !== principalId) return null;
      return {
        ...clone(checkpoint),
        memoryIds: checkpoint.memoryIds.filter((memoryId) => {
          const memory = state.memories.get(memoryKey(tenantId, memoryId));
          return (
            memory?.principalId === principalId &&
            memory.state === "CONFIRMED" &&
            Date.parse(memory.expiresAt) > Date.parse(asOf)
          );
        }),
      };
    },
    async inspectForTest() {
      return serializeState(state);
    },
    async exportRecoverySnapshot({ asOf } = {}) {
      canonicalInstant(asOf, "asOf");
      return serializeState(state, { asOf });
    },
  });
}

function commandOperation(kind) {
  return `C09_${kind}`;
}

function validateCommand(command, catalog, tenantId, idFactory) {
  const base = {
    operation: command.kind,
    idempotencyKey: command.idempotencyKey,
    correlationId: command.correlationId,
  };
  if (command.kind === "PROPOSE_CANDIDATE") {
    return {
      ...base,
      candidate: catalog.resolve(tenantId, command.candidateRef),
      memoryId: generatedId("mem_", MEMORY_ID, "memoryId", idFactory),
      eventId: generatedId("mev_", EVENT_ID, "eventId", idFactory),
    };
  }
  if (
    [
      "CONFIRM_CANDIDATE",
      "MATERIALIZE_EXPIRY",
      "DELETE_MEMORY",
    ].includes(
      command.kind,
    )
  ) {
    identifier(command.memoryId, MEMORY_ID, "memoryId");
    positiveInteger(command.expectedVersion, "expectedVersion");
    if (command.kind === "CONFIRM_CANDIDATE") {
      identifier(
        command.humanConsentToken,
        HUMAN_CONSENT_TOKEN,
        "humanConsentToken",
      );
    }
    return {
      ...base,
      memoryId: command.memoryId,
      expectedVersion: command.expectedVersion,
      humanConsentToken: command.humanConsentToken,
      eventId: generatedId("mev_", EVENT_ID, "eventId", idFactory),
    };
  }
  if (command.kind === "CORRECT_MEMORY") {
    identifier(command.memoryId, MEMORY_ID, "memoryId");
    positiveInteger(command.expectedVersion, "expectedVersion");
    identifier(
      command.humanConsentToken,
      HUMAN_CONSENT_TOKEN,
      "humanConsentToken",
    );
    return {
      ...base,
      memoryId: command.memoryId,
      expectedVersion: command.expectedVersion,
      humanConsentToken: command.humanConsentToken,
      eventId: generatedId("mev_", EVENT_ID, "eventId", idFactory),
      replacementMemoryId: generatedId(
        "mem_",
        MEMORY_ID,
        "replacementMemoryId",
        idFactory,
      ),
      replacementEventId: generatedId(
        "mev_",
        EVENT_ID,
        "replacementEventId",
        idFactory,
      ),
      replacementCandidate: catalog.resolve(
        tenantId,
        command.replacementCandidateRef,
      ),
    };
  }
  if (command.kind === "CHANGE_PROFILE_STATE") {
    positiveInteger(
      command.expectedProfileVersion,
      "expectedProfileVersion",
    );
    if (!PROFILE_STATES.has(command.state)) {
      fail("INVALID_INPUT", "Unknown profile state.");
    }
    return {
      ...base,
      expectedProfileVersion: command.expectedProfileVersion,
      profileState: command.state,
    };
  }
  if (command.kind === "SAVE_CHECKPOINT") {
    if (command.checkpointId === null) {
      if (command.expectedVersion !== 0) {
        fail("INVALID_INPUT", "New Checkpoint must expect version zero.");
      }
    } else {
      identifier(command.checkpointId, CHECKPOINT_ID, "checkpointId");
    }
    positiveInteger(command.expectedVersion, "expectedVersion", {
      allowZero: true,
    });
    reference(command.threadRef, "threadRef");
    reference(command.stateRef, "stateRef");
    if (!SHA256.test(command.stateSha256 ?? "")) {
      fail("INVALID_INPUT", "stateSha256 is invalid.");
    }
    if (
      !Array.isArray(command.memoryIds) ||
      command.memoryIds.length > 32 ||
      new Set(command.memoryIds).size !== command.memoryIds.length
    ) {
      fail("INVALID_INPUT", "memoryIds is invalid.");
    }
    command.memoryIds.forEach((memoryId) =>
      identifier(memoryId, MEMORY_ID, "memoryId")
    );
    return {
      ...base,
      checkpointId: command.checkpointId ??
        generatedId("ckp_", CHECKPOINT_ID, "checkpointId", idFactory),
      expectedVersion: command.expectedVersion,
      threadRef: command.threadRef,
      stateRef: command.stateRef,
      stateSha256: command.stateSha256,
      memoryIds: clone(command.memoryIds),
    };
  }
  fail("INVALID_INPUT", "Unsupported C09 command.");
}

export function createPersonalMemoryService({
  tenantRegistry,
  stablePrincipalRegistry,
  authorizer,
  tenantScopeFactory,
  catalog,
  humanConsentStore,
  store = createMemoryPersonalMemoryStore(),
  clock = () => new Date().toISOString(),
  idFactory = uuidV7,
}) {
  if (
    typeof tenantRegistry?.admitNewRequest !== "function" ||
    typeof stablePrincipalRegistry?.resolveActionIdentity !== "function" ||
    typeof authorizer?.enforce !== "function" ||
    typeof tenantScopeFactory !== "function" ||
    typeof catalog?.resolve !== "function" ||
    typeof humanConsentStore?.consume !== "function" ||
    typeof store?.apply !== "function" ||
    typeof store?.readCommandReceipt !== "function" ||
    typeof store?.readConsentTarget !== "function"
  ) {
    fail("INVALID_CONFIGURATION", "C09 dependencies are incomplete.");
  }

  async function resolve(context, request, operation, correlationId, resource) {
    validateServerContext(context);
    const identity = validateIdentity(
      await stablePrincipalRegistry.resolveActionIdentity(
        {
          synthetic: true,
          workloadTrustSource: context.workloadTrustSource,
          workloadActorPrincipalId: context.workloadActorPrincipalId,
        },
        {
          sessionToken: request.sessionToken,
          expectedTenantId: context.tenantId,
          delegationId: request.delegationId,
        },
      ),
      context,
      request.delegationId,
    );
    const principalId = identity.humanSubject.principalId;
    const authorization = validateAuthorization(
      await authorizer.enforce({
        operation,
        tenantId: context.tenantId,
        identity: clone(identity),
        resource: clone(resource ?? {
          resourceType: "personal_memory_profile",
          resourceId: principalId,
        }),
      }),
      {
        tenantId: context.tenantId,
        principalId,
        operation,
        identity,
      },
    );
    const finalIdentity = validateIdentity(
      await stablePrincipalRegistry.resolveActionIdentity(
        {
          synthetic: true,
          workloadTrustSource: context.workloadTrustSource,
          workloadActorPrincipalId: context.workloadActorPrincipalId,
        },
        {
          sessionToken: request.sessionToken,
          expectedTenantId: context.tenantId,
          delegationId: request.delegationId,
        },
      ),
      context,
      request.delegationId,
    );
    if (!sameActionIdentity(identity, finalIdentity)) {
      fail(
        "IDENTITY_CHANGED",
        "C05 identity changed after C06 authorization.",
      );
    }
    const tenant = await tenantRegistry.admitNewRequest({
      tenantId: context.tenantId,
      expectedTenantKind: "SYNTHETIC",
    });
    if (
      tenant?.tenantId !== context.tenantId ||
      tenant?.tenantKind !== "SYNTHETIC"
    ) {
      fail("TENANT_SCOPE_VIOLATION", "C03 Tenant admission is invalid.");
    }
    const tenantScope = validateScope(
      await tenantScopeFactory({
        tenant: clone(tenant),
        identity: clone(finalIdentity),
        authorization: clone(authorization),
        correlationId,
      }),
      context.tenantId,
      correlationId,
    );
    const scope = {
      ...tenantScope,
      principalLifecycleVersion:
        finalIdentity.humanSubject.lifecycleVersion,
      principalSecurityEpoch: finalIdentity.humanSubject.securityEpoch,
    };
    return {
      identity: finalIdentity,
      principalId,
      authorization,
      scope,
    };
  }

  return Object.freeze({
    async execute(context, request) {
      validateRequestEnvelope(request);
      const operation = commandOperation(request.command.kind);
      const trusted = await resolve(
        context,
        request,
        operation,
        request.command.correlationId,
      );
      const validated = validateCommand(
        request.command,
        catalog,
        context.tenantId,
        idFactory,
      );
      const now = canonicalInstant(clock(), "clock");
      const requestHash = personalMemorySha256({
        tenantId: context.tenantId,
        principalId: trusted.principalId,
        command: request.command,
      });
      const replay = await store.readCommandReceipt(trusted.scope, {
        tenantId: context.tenantId,
        principalId: trusted.principalId,
        idempotencyKey: validated.idempotencyKey,
        requestHash,
      });
      if (replay !== null) return replay;
      let humanConsentEvidence = null;
      if (
        ["CONFIRM_CANDIDATE", "CORRECT_MEMORY"].includes(
          validated.operation,
        )
      ) {
        const target = await store.readConsentTarget(trusted.scope, {
          tenantId: context.tenantId,
          principalId: trusted.principalId,
          memoryId: validated.memoryId,
        });
        if (!target) {
          fail(
            "MEMORY_NOT_FOUND",
            "Memory was not found for this owner.",
          );
        }
        if (target.version !== validated.expectedVersion) {
          fail("STALE_VERSION", "Memory version is stale.");
        }
        const expectedState =
          validated.operation === "CONFIRM_CANDIDATE"
            ? "CANDIDATE"
            : "CONFIRMED";
        if (target.state !== expectedState) {
          fail(
            "INVALID_STATE",
            validated.operation === "CONFIRM_CANDIDATE"
              ? "Only a Candidate can be confirmed."
              : "Only Confirmed memory can be corrected.",
          );
        }
        const purpose =
          validated.operation === "CONFIRM_CANDIDATE"
            ? "CONFIRM_PERSONAL_MEMORY"
            : "CORRECT_PERSONAL_MEMORY";
        const contentSha256 =
          validated.operation === "CONFIRM_CANDIDATE"
            ? target.contentSha256
            : validated.replacementCandidate.contentSha256;
        humanConsentEvidence = validatePersonalMemoryHumanConsentEvidence(
          await humanConsentStore.consume({
            token: validated.humanConsentToken,
            expected: {
              tenantId: context.tenantId,
              humanPrincipalId: trusted.principalId,
              memoryId: validated.memoryId,
              expectedVersion: validated.expectedVersion,
              contentSha256,
              purpose,
            },
            now,
            requestHash,
          }),
        );
        if (
          humanConsentEvidence.tokenSha256 !==
            personalMemorySha256(validated.humanConsentToken) ||
          humanConsentEvidence.consumedAt !== now
        ) {
          fail(
            "HUMAN_CONSENT_BINDING_MISMATCH",
            "Consumed Human consent evidence does not match this action.",
          );
        }
      }
      const storeCommand = { ...validated };
      delete storeCommand.humanConsentToken;
      return store.apply(trusted.scope, {
        ...storeCommand,
        tenantId: context.tenantId,
        tenantKind: "SYNTHETIC",
        principalId: trusted.principalId,
        actorPrincipalId: identityActor(trusted.identity),
        authorizationEvidence: trusted.authorization,
        humanConsentEvidence,
        requestHash,
        now,
      });
    },

    async recall(context, request) {
      validateRecallRequest(request);
      const trusted = await resolve(
        context,
        request,
        "C09_RECALL",
        request.correlationId,
      );
      const now = canonicalInstant(clock(), "clock");
      const profile = await store.readProfile(trusted.scope, {
        tenantId: context.tenantId,
        principalId: trusted.principalId,
      });
      if (profile.state !== "ACTIVE") {
        return { principalId: trusted.principalId, memories: [] };
      }
      const metadata = await store.listRecallMetadata(trusted.scope, {
        tenantId: context.tenantId,
        principalId: trusted.principalId,
        now,
        limit: request.limit,
      });
      const memories = [];
      for (const item of metadata) {
        let itemDecision;
        try {
          itemDecision = validateAuthorization(
            await authorizer.enforce({
              operation: "C09_RECALL_ITEM",
              tenantId: context.tenantId,
              identity: clone(trusted.identity),
              resource: {
                resourceType: "personal_memory",
                resourceId: item.memoryId,
                category: item.category,
                version: item.version,
              },
            }),
            {
              tenantId: context.tenantId,
              principalId: trusted.principalId,
              operation: "C09_RECALL_ITEM",
              identity: trusted.identity,
            },
          );
        } catch (error) {
          if (
            error instanceof PersonalMemoryError &&
            error.code === "FORBIDDEN"
          ) {
            continue;
          }
          throw error;
        }
        const memory = await store.readRecallContent(trusted.scope, {
          tenantId: context.tenantId,
          principalId: trusted.principalId,
          memoryId: item.memoryId,
          expectedVersion: item.version,
          now,
        });
        if (memory) {
          memories.push({
            memoryId: memory.memoryId,
            category: memory.category,
            content: memory.content,
            contentSha256: memory.contentSha256,
            version: memory.version,
            expiresAt: memory.expiresAt,
            authorizationEvidence: itemDecision,
          });
        }
      }
      return { principalId: trusted.principalId, memories };
    },

    async readCheckpoint(context, request) {
      exactKeys(
        request,
        [
          "sessionToken",
          "delegationId",
          "checkpointId",
          "correlationId",
        ],
        "checkpoint request",
      );
      identifier(request.checkpointId, CHECKPOINT_ID, "checkpointId");
      if (!CORRELATION_ID.test(request.correlationId ?? "")) {
        fail("INVALID_INPUT", "correlationId is invalid.");
      }
      const trusted = await resolve(
        context,
        request,
        "C09_READ_CHECKPOINT",
        request.correlationId,
        {
          resourceType: "personal_memory_checkpoint",
          resourceId: request.checkpointId,
        },
      );
      const now = canonicalInstant(clock(), "clock");
      const profile = await store.readProfile(trusted.scope, {
        tenantId: context.tenantId,
        principalId: trusted.principalId,
      });
      if (profile.state !== "ACTIVE") {
        fail("PROFILE_PAUSED", "Personal profile is paused.");
      }
      return store.readCheckpoint(trusted.scope, {
        tenantId: context.tenantId,
        principalId: trusted.principalId,
        checkpointId: request.checkpointId,
        asOf: now,
      });
    },
  });
}

function identityActor(identity) {
  return identity.workloadActor.principalId;
}

export const C09_PERSONAL_MEMORY_CATEGORIES = Object.freeze({
  allowed: Object.freeze([...ALLOWED_CATEGORIES]),
  forbidden: Object.freeze([...FORBIDDEN_CATEGORIES]),
});

export const C09_PERSONAL_MEMORY_STATES = Object.freeze([
  ...MEMORY_STATES,
]);
